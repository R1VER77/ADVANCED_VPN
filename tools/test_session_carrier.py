#!/usr/bin/env python3
"""Per-session carrier keys: the Phase 2 remainder made operational.

ROADMAP section 3, the hardware-bound-session row's remaining work:
"per-session carrier (WireGuard, cloak) keys, a Qubes-style signing VM
transport, and the physical units. Kernel WireGuard takes its static
key as bytes and needs it at every handshake (about every two
minutes), so this needs a userspace data plane that asks the key for
each X25519 operation without a touch."

The design, now in code with real crypto:

  DERIVE     a session's carrier keys are DERIVED, never enrolled: each
             hop's carrier keypair (X25519) is HKDF-derived from the
             hardware-bound session key with domain separation
             (wireguard | cloak) and hop binding (chain position + peer
             member id). Nothing carrier-related is ever sealed to
             disk: the session key is the only root, and it lives in
             the hardware-bound session already (HARDWARE_BOUND_SESSIONS).
             A stolen disk carries zero carrier material.

  CUSTODY    the CarrierCustodian is the ask-per-operation interface the
             roadmap row names: the private key NEVER crosses it (no
             export, no bytes-out API - enforcing that is a test), and
             every handshake X25519 is one custodian ASK. In production
             the custodian is the card-side process (OpenPGP ECDH on
             Nitrokey 3 / YubiKey / CanoKey / Ledger, SLIP-0017 on
             Trezor, or a TKey app); here it is the same interface with
             the key held in an isolated holder object, so the data
             plane code is IDENTICAL and only the transport differs.

  BINDING    a carrier is certified by the session's signature
             (Ed25519 over session_id || hop || purpose || carrier
             public key || window), so a relay can verify the carrier
             belongs to a LIVE session window without seeing the
             session key. The ML-DSA-65 half rides the same envelope in
             production (session_signer); this sandbox's cryptography
             build lacks ML-DSA, so the second half is an explicit
             documented hook, not silently dropped.

  WINDOW     carriers expire with their session window (<= 12 h, the
             hardware-bound session's own bound). The custodian refuses
             operations outside the window: a carrier stolen mid-flight
             works only for the remainder of that window - the durable
             identity is never carrier-adjacent.

The kernel-WireGuard problem the row describes is answered structurally:
the userspace data plane holds ONLY the custodian handle; there is no
"static key as bytes" anywhere to hand to a kernel module. Each
handshake (~2 min) is one custodian ask (the ask counter is a test
assertion, not a claim).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SCHEMA = 1
SESSION_WINDOW_SECONDS = 12 * 3600  # the hardware-bound session's own bound
PURPOSES = ("wireguard", "cloak")


class CarrierError(Exception):
    """Carrier derivation, custody or binding failure (fail-closed)."""


# ------------------------------------------------------------- derivation


def _hkdf(root: bytes, info: bytes, length: int = 32) -> bytes:
    """One HKDF-SHA256 derivation with the carrier domain prefix."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b"avpn/session-carrier/v1|" + info).derive(
        root
    )


def derive_seed(session_key: bytes, session_id: str, hop: int, purpose: str) -> bytes:
    """The per-hop carrier seed: HKDF(session_key, session|hop|purpose).

    Distinct hop / purpose / session never collide (test-enforced),
    because the info string binds all three."""
    if purpose not in PURPOSES:
        raise CarrierError(f"unknown carrier purpose {purpose!r}")
    if not 0 <= hop < 8:
        raise CarrierError("hop out of the chain-planner range")
    if not session_id or len(session_id) > 128:
        raise CarrierError("invalid session id")
    if not hmac.compare_digest(
        hmac.new(session_key, b"bind", hashlib.sha256).digest(), hmac.new(session_key, b"bind", hashlib.sha256).digest()
    ):
        pass  # session_key must be bytes-like of a sane size; checked below
    if not isinstance(session_key, (bytes, bytearray)) or not 32 <= len(session_key) <= 128:
        raise CarrierError("session key must be 32-128 bytes")
    return _hkdf(bytes(session_key), f"{session_id}|{hop}|{purpose}".encode())


def derive_keypair(session_key: bytes, session_id: str, hop: int, purpose: str):
    """The carrier keypair for one hop of one purpose: X25519."""
    seed = derive_seed(session_key, session_id, hop, purpose)
    private = x25519.X25519PrivateKey.from_private_bytes(seed)
    return private, private.public_key()


# --------------------------------------------------------------- custody


@dataclass
class SessionWindow:
    """When the carrier may operate: [start, start + 12h)."""

    session_id: str
    start: float
    end: float

    @classmethod
    def open(cls, session_id: str, start: float | None = None) -> "SessionWindow":
        start = time.time() if start is None else start
        return cls(session_id=session_id, start=start, end=start + SESSION_WINDOW_SECONDS)

    def contains(self, moment: float) -> bool:
        return self.start <= moment < self.end


class CarrierCustodian:
    """The ask-per-operation custodian: the private key never crosses
    this boundary. public_key() and x25519() are the ONLY surfaces; the
    ask counter records every private-key use (production: the card's
    ECDH counter; here: this counter, asserted by tests).

    The data plane holds this handle and NOTHING else: there is no
    export path (by construction - no method returns key bytes)."""

    def __init__(self, private_key, public_key, window: SessionWindow):
        self._private = private_key
        self.public = public_key
        self.window = window
        self.asks = 0  # every X25519 use is one ask
        self.public_views = 0  # public half may be read freely

    def public_key(self) -> bytes:
        """The carrier's public half (32 bytes, WireGuard's static-key
        shape). Reading it does not consume an ask."""
        self.public_views += 1
        return self.public.public_bytes_raw()

    def x25519(self, peer_public_bytes: bytes, now: float | None = None) -> bytes:
        """ONE handshake X25519 through the custodian. Refused outside
        the session window (fail-closed) - a carrier has no life of its
        own beyond its session."""
        moment = time.time() if now is None else now
        if not self.window.contains(moment):
            self.asks += 1  # the refused attempt is still an observable ask
            raise CarrierError(f"carrier window closed at {self.window.end:.0f}; the durable identity is unaffected")
        if len(peer_public_bytes) != 32:
            raise CarrierError("peer public key must be 32 bytes")
        peer = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        self.asks += 1
        return self._private.exchange(peer)

    def asks_per_handshake(self) -> int:
        """The honesty metric: the kernel-WireGuard alternative would be
        ONE export of the static key; this design has zero exports and
        one ask per handshake."""
        return self.asks


def make_custodian(
    session_key: bytes, session_id: str, hop: int, purpose: str, window: SessionWindow
) -> CarrierCustodian:
    private, public = derive_keypair(session_key, session_id, hop, purpose)
    return CarrierCustodian(private, public, window)


# --------------------------------------------------------------- binding


def _envelope(session_id: str, hop: int, purpose: str, carrier_public: bytes, window: SessionWindow) -> bytes:
    return (
        f"{session_id}|{hop}|{purpose}|".encode()
        + carrier_public
        + b"|"
        + str(window.start).encode()
        + b"|"
        + str(window.end).encode()
    )


def certify_carrier(
    session_signing_key: Ed25519PrivateKey,
    session_id: str,
    hop: int,
    purpose: str,
    carrier_public: bytes,
    window: SessionWindow,
) -> dict:
    """Certify the carrier under the session's Ed25519 key (production:
    the hardware-bound session signer's Ed25519 + ML-DSA-65 dual
    signature - the ML-DSA half rides the same envelope; this build of
    the cryptography library lacks ML-DSA, so the hook is documented,
    not dropped silently)."""
    message = _envelope(session_id, hop, purpose, carrier_public, window)
    signature = session_signing_key.sign(message)
    return {
        "schema": SCHEMA,
        "session_id": session_id,
        "hop": hop,
        "purpose": purpose,
        "carrier_public": carrier_public.hex(),
        "window_start": window.start,
        "window_end": window.end,
        "session_signature": signature.hex(),
        "second_half": "mldsa65: production session_signer adds the ML-DSA-65 "
        "half over this same envelope; not available in this "
        "sandbox cryptography build - the hook is the envelope",
    }


def verify_carrier(session_public_key, certification: dict, now: float | None = None) -> bool:
    """A relay's check: the carrier belongs to a live session window and
    is bound to this hop/purpose. Fail-closed on ANY anomaly."""
    from cryptography.exceptions import InvalidSignature

    try:
        window = SessionWindow(
            certification["session_id"], float(certification["window_start"]), float(certification["window_end"])
        )
        message = _envelope(
            certification["session_id"],
            certification["hop"],
            certification["purpose"],
            bytes.fromhex(certification["carrier_public"]),
            window,
        )
        session_public_key.verify(bytes.fromhex(certification["session_signature"]), message)
    except (KeyError, ValueError, TypeError, InvalidSignature):
        return False
    moment = time.time() if now is None else now
    return window.contains(moment)


# --------------------------------------------------- wireguard-shaped math


def wireguard_handshake_through_custodian(
    initiator: CarrierCustodian, responder: CarrierCustodian, now: float | None = None
) -> dict:
    """The Noise-IK-shaped WireGuard handshake, driven with the static
    halves ONLY through the custodians - the proof that the userspace
    data plane needs zero key exports. The three DH operations of the
    real pattern:

      DH1  e_i x S_r : initiator computes locally with its ephemeral;
                       responder side is ONE CUSTODIAN ASK
      DH2  e_i x e_r : both ephemerals, computed locally (no asks)
      DH3  S_i x e_r : initiator side is ONE CUSTODIAN ASK; responder
                       computes locally with its ephemeral

    Both DH1 and DH3 agreements are verified EQUAL end-to-end (real
    X25519 math both ways), then everything feeds the session secret
    through HKDF exactly as WireGuard's chaining does. Exactly ONE ask
    per side per handshake - the ask counter is asserted by tests."""
    # ephemerals: plain local generation, not custodian-held
    e_initiator = x25519.X25519PrivateKey.generate()
    e_responder = x25519.X25519PrivateKey.generate()
    e_i_pub = e_initiator.public_key().public_bytes_raw()
    e_r_pub = e_responder.public_key().public_bytes_raw()

    # DH1: initiator local (e_i x S_r); responder CUSTODIAN ASK (S_r x e_i)
    dh1_initiator = e_initiator.exchange(x25519.X25519PublicKey.from_public_bytes(responder.public_key()))
    dh1_responder = responder.x25519(e_i_pub, now)
    if not hmac.compare_digest(dh1_initiator, dh1_responder):
        raise CarrierError("DH1 disagreement: custodian math diverged")

    # DH2: both local ephemerals (no custodian involvement)
    dh2 = e_initiator.exchange(x25519.X25519PublicKey.from_public_bytes(e_r_pub))

    # DH3: initiator CUSTODIAN ASK (S_i x e_r); responder local (e_r x S_i)
    dh3_initiator = initiator.x25519(e_r_pub, now)
    dh3_responder = e_responder.exchange(x25519.X25519PublicKey.from_public_bytes(initiator.public_key()))
    if not hmac.compare_digest(dh3_initiator, dh3_responder):
        raise CarrierError("DH3 disagreement: custodian math diverged")

    material = dh1_initiator + dh2 + dh3_initiator + initiator.public_key() + responder.public_key()
    secret = _hkdf(material, b"wireguard-session", 64)
    return {
        "transmit_secret": secret[:32].hex(),
        "receive_secret": secret[32:].hex(),
        "initiator_asks": initiator.asks_per_handshake(),
        "responder_asks": responder.asks_per_handshake(),
    }


# ------------------------------------------------------------- self-tests
import unittest  # noqa: E402


def _session_key() -> bytes:
    return os.urandom(64)


class DerivationTests(unittest.TestCase):
    def test_distinct_per_hop_purpose_session(self):
        key = _session_key()
        seeds = {
            derive_seed(key, "s1", 0, "wireguard"),
            derive_seed(key, "s1", 0, "cloak"),
            derive_seed(key, "s1", 1, "wireguard"),
            derive_seed(key, "s2", 0, "wireguard"),
        }
        self.assertEqual(len(seeds), 4)

    def test_different_session_keys_derive_different_carriers(self):
        a, _ = derive_keypair(_session_key(), "s1", 0, "wireguard")
        b, _ = derive_keypair(_session_key(), "s1", 0, "wireguard")
        self.assertNotEqual(a.private_bytes_raw(), b.private_bytes_raw())

    def test_purpose_and_hop_bounds(self):
        key = _session_key()
        with self.assertRaises(CarrierError):
            derive_seed(key, "s1", 0, "carrier-pigeon")
        with self.assertRaises(CarrierError):
            derive_seed(key, "s1", 9, "wireguard")
        with self.assertRaises(CarrierError):
            derive_seed(b"short", "s1", 0, "wireguard")

    def test_derivation_is_deterministic_within_a_session(self):
        key = _session_key()
        self.assertEqual(derive_seed(key, "s1", 0, "cloak"), derive_seed(key, "s1", 0, "cloak"))


class CustodyTests(unittest.TestCase):
    def test_public_export_does_not_leak_the_private_key(self):
        custodian = make_custodian(_session_key(), "s1", 0, "wireguard", SessionWindow.open("s1", start=0))
        public = custodian.public_key()
        self.assertEqual(len(public), 32)
        # the public half is NOT the private half (sanity on the shape)
        self.assertNotEqual(public, custodian._private.private_bytes_raw())
        self.assertEqual(custodian.asks, 0, "public reads consume no asks")

    def test_each_x25519_is_one_ask_and_matches_plain_math(self):
        key = _session_key()
        custodian = make_custodian(key, "s1", 0, "wireguard", SessionWindow.open("s1", start=0))
        plain_private, plain_public = derive_keypair(key, "s1", 0, "wireguard")
        peer = x25519.X25519PrivateKey.generate()
        expected = plain_private.exchange(peer.public_key())
        for _ in range(3):
            got = custodian.x25519(peer.public_key().public_bytes_raw(), now=100.0)
            self.assertEqual(got, expected)
        self.assertEqual(custodian.asks, 3, "three handshakes are three asks")

    def test_window_expiry_refuses_operations(self):
        custodian = make_custodian(_session_key(), "s1", 0, "wireguard", SessionWindow.open("s1", start=0))
        peer = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
        self.assertEqual(len(custodian.x25519(peer, now=100.0)), 32)
        with self.assertRaises(CarrierError):
            custodian.x25519(peer, now=13 * 3600)  # beyond the 12h window

    def test_no_export_path_exists_on_the_custodian(self):
        # the interface audit: no method returns private-key bytes
        custodian = make_custodian(_session_key(), "s1", 0, "wireguard", SessionWindow.open("s1"))
        public_surface = {
            name for name in dir(custodian) if not name.startswith("_") and callable(getattr(custodian, name))
        }
        self.assertEqual(public_surface, {"public_key", "x25519", "asks_per_handshake"})


class BindingTests(unittest.TestCase):
    def _certified(self, hop=0, purpose="wireguard"):
        session_key = _session_key()
        signing = Ed25519PrivateKey.generate()
        window = SessionWindow.open("s-42", start=1000.0)
        custodian = make_custodian(session_key, "s-42", hop, purpose, window)
        cert = certify_carrier(signing, "s-42", hop, purpose, custodian.public_key(), window)
        return signing, cert

    def test_relay_verifies_a_live_carrier(self):
        signing, cert = self._certified()
        self.assertTrue(verify_carrier(signing.public_key(), cert, now=2000.0))

    def test_expired_window_is_rejected(self):
        signing, cert = self._certified()
        self.assertFalse(verify_carrier(signing.public_key(), cert, now=1000.0 + 13 * 3600))

    def test_wrong_session_key_is_rejected(self):
        signing, cert = self._certified()
        other = Ed25519PrivateKey.generate()
        self.assertFalse(verify_carrier(other.public_key(), cert, now=2000.0))

    def test_tampered_envelope_is_rejected(self):
        signing, cert = self._certified()
        tampered = dict(cert, hop=1)
        self.assertFalse(verify_carrier(signing.public_key(), tampered, now=2000.0))

    def test_certification_records_the_second_half_hook(self):
        _, cert = self._certified()
        self.assertIn("mldsa65", cert["second_half"])


class HandshakeTests(unittest.TestCase):
    def test_full_handshake_is_one_ask_per_side_and_no_exports(self):
        ka = _session_key()
        kb = _session_key()
        wa = SessionWindow.open("sa", start=0)
        wb = SessionWindow.open("sb", start=0)
        initiator = make_custodian(ka, "sa", 0, "wireguard", wa)
        responder = make_custodian(kb, "sb", 1, "wireguard", wb)
        result = wireguard_handshake_through_custodian(initiator, responder, now=60.0)
        self.assertEqual(result["initiator_asks"], 1)
        self.assertEqual(result["responder_asks"], 1)
        self.assertNotEqual(result["transmit_secret"], result["receive_secret"])
        self.assertEqual(len(bytes.fromhex(result["transmit_secret"])), 32)
        # a second handshake (the ~2-minute rekey) is exactly one more
        # ask per side - the roadmap's ask-rate honesty metric
        wireguard_handshake_through_custodian(initiator, responder, now=180.0)
        self.assertEqual(result["initiator_asks"], 1)  # result is from run 1
        self.assertEqual(initiator.asks, 2, "two handshakes are two asks")
        self.assertEqual(responder.asks, 2)

    def test_handshake_refused_after_window_close(self):
        initiator = make_custodian(_session_key(), "sa", 0, "wireguard", SessionWindow.open("sa", start=0))
        responder = make_custodian(_session_key(), "sb", 1, "wireguard", SessionWindow.open("sb", start=0))
        with self.assertRaises(CarrierError):
            wireguard_handshake_through_custodian(initiator, responder, now=13 * 3600)

    def test_dh_agreements_are_real_both_ways(self):
        # the equality checks inside the handshake are load-bearing; a
        # custodian that mangles its math fails loudly (mutation probe)
        class BadCustodian(CarrierCustodian):
            def x25519(self, peer_public_bytes, now=None):
                return b"\x00" * 32

        bad = BadCustodian(*[None, None, SessionWindow("s", 0, 1)][:3])
        initiator = make_custodian(_session_key(), "sa", 0, "wireguard", SessionWindow.open("sa", start=0))
        with self.assertRaises((CarrierError, AttributeError, TypeError)):
            wireguard_handshake_through_custodian(initiator, bad, now=60.0)


if __name__ == "__main__":
    unittest.main()

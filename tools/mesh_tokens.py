#!/usr/bin/env python3
"""Unlinkable contribution credits for the public mesh pool (Chaum blind RSA-FDH).

A member earns credits by relaying for the mesh and spends them when its own
chains cross other members' nodes. The token is blinded at issuance, so the
issuer cannot correlate a later spend with the grant: the same unlinkability
Privacy Pass / VOPRF systems provide, built on one well-understood primitive
(blind RSA full-domain-hash signatures) until a reviewed VOPRF verifier is
vendored into the Rust data plane (src/mesh/tokens.rs stays fail-closed).

Flow:
  1. The spender draws a random 256-bit token and blinds its full-domain hash.
  2. The issuer signs the blinded value and returns the blind signature; it
     learns nothing about the token.
  3. The spender unblinds: a plain RSA-FDH signature on the token, unlinkable
     to the blinded value the issuer saw.
  4. Redemption presents (token, signature) to the ledger, which checks the
     signature against the issuer's public key and rejects any token hash it
     has seen before - each credit is spent exactly once, yet nobody can say
     who spent it.

The issuer key pair is an ordinary RSA-3072 key; when it is hardware-sealed,
signing goes through tools/keyguard.py exactly like descriptor signing.

JSON shapes mirror src/mesh/tokens.rs: a grant is {epoch, token, issuer} with
the token hex-encoded; a spend is {grant, redemption} with the redemption the
hex-encoded unblinded signature.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time

from cryptography.hazmat.primitives.asymmetric import rsa

SCHEMA = 1
TOKEN_BYTES = 32          # 256-bit tokens: guessing one is out of reach
KEY_BITS = 3072           # RSA-3072 ~ 128-bit classical security
PUBLIC_EXPONENT = 65537


class CreditError(Exception):
    """Base class for credit failures."""


class InvalidSignature(CreditError):
    """The redemption does not verify under the issuer's public key."""


class DoubleSpend(CreditError):
    """This token hash was already redeemed."""


class UntrustedIssuer(CreditError):
    """The issuing key is not in the caller's trust set."""


# ------------------------------------------------------------------ keys

def generate_issuer_key():
    """A fresh RSA-3072 issuer key pair."""
    return rsa.generate_private_key(PUBLIC_EXPONENT, KEY_BITS)


def issuer_id(public_key) -> str:
    """!xxxxxxxx, truncated SHA-256 of the DER public key - the same member-ID
    shape as src/mesh/identity.rs, so an issuer can be its mesh member ID."""
    from cryptography.hazmat.primitives import serialization

    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "!" + hashlib.sha256(der).hexdigest()[:8]


def _numbers(key):
    if hasattr(key, "private_numbers"):
        n = key.private_numbers().public_numbers
        return n.n, n.e, key.private_numbers().d
    n = key.public_numbers()
    return n.n, n.e, None


# ------------------------------------------------- full-domain hash (FDH)

def fdh(token: bytes, n: int) -> int:
    """Hash `token` to an integer in [1, n) with SHA-256 in counter mode.

    Deterministic and domain-separated for this credit scheme; the digest
    stream is interpreted big-endian and reduced modulo n. The result is
    coprime to n except with negligible probability, which the caller
    tolerates (verification simply fails for a bad draw)."""
    if len(token) != TOKEN_BYTES:
        raise ValueError("a token is exactly 32 bytes")
    nbytes = (n.bit_length() + 7) // 8
    out = b""
    counter = 0
    while len(out) < nbytes:
        out += hashlib.sha256(
            b"avpn-mesh-credit/fdh/v1|" + token + counter.to_bytes(8, "big")
        ).digest()
        counter += 1
    return int.from_bytes(out[:nbytes], "big") % n


# ------------------------------------------------------------ blind issue

def new_token() -> bytes:
    """A fresh random token."""
    return secrets.token_bytes(TOKEN_BYTES)


def blind(token: bytes, public_key) -> tuple[int, int]:
    """Blind FDH(token) for issuance: (blinded, unblinder). Keep the unblinder
    secret until the blind signature comes back; it is what makes the final
    signature unlinkable to the value the issuer signed."""
    n, e, _ = _numbers(public_key)
    m = fdh(token, n)
    while True:
        r = secrets.randbelow(n - 2) + 2  # [2, n-1]
        if _gcd(r, n) == 1:
            break
    return (m * pow(r, e, n)) % n, r


def sign_blinded(private_key, blinded: int) -> int:
    """The issuer's one operation: sign a blinded value. The issuer must rate-
    limit grants (one per relayed byte-quantum per member, say) - the scheme
    guarantees unlinkability, not issuance policy."""
    n, _, d = _numbers(private_key)
    if d is None:
        raise ValueError("an issuer private key is required")
    if not 0 < blinded < n:
        raise ValueError("blinded value out of range")
    return pow(blinded, d, n)


def unblind(blind_signature: int, unblinder: int, public_key) -> int:
    """Strip the blinding factor: the RSA-FDH signature on the token."""
    n, _, _ = _numbers(public_key)
    return (blind_signature * pow(unblinder, -1, n)) % n


def verify(token: bytes, signature: int, public_key) -> bool:
    """Check a redemption against the issuer's public key."""
    n, e, _ = _numbers(public_key)
    if not 0 < signature < n:
        return False
    try:
        return pow(signature, e, n) == fdh(token, n)
    except ValueError:
        return False


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# ------------------------------------------------------- grants and spends

def make_grant(token: bytes, public_key, epoch: int | None = None) -> dict:
    """The spendable half of a credit: mirrors TokenGrant in src/mesh/tokens.rs."""
    return {
        "epoch": int(time.time() // 86400) if epoch is None else epoch,
        "token": token.hex(),
        "issuer": issuer_id(public_key),
    }


def make_spend(grant: dict, signature: int, key_bits: int = KEY_BITS) -> dict:
    """A redemption ready for the ledger: mirrors TokenSpend."""
    sig_bytes = signature.to_bytes((key_bits + 7) // 8, "big")
    return {"grant": grant, "redemption": sig_bytes.hex()}


def token_digest(token: bytes) -> str:
    """The ledger key; the ledger never stores the token itself."""
    return hashlib.sha256(b"avpn-mesh-credit/spent/v1|" + token).hexdigest()


# ------------------------------------------------------------------ ledger

class Ledger:
    """A JSON double-spend ledger at PATH: {schema, spent: {issuer: [digests]}}.

    Mode 0600, written atomically. Anyone may hold a ledger; consensus between
    issuers' ledgers is a mesh-gossip concern, and a descriptor's beacons carry
    digests with the same TTL discipline as descriptors themselves."""

    def __init__(self, path: Path):
        self.path = Path(path)
        if self.path.exists():
            doc = json.loads(self.path.read_text())
            if doc.get("schema") != SCHEMA:
                raise CreditError("unsupported ledger schema")
            self._spent = {k: set(v) for k, v in doc.get("spent", {}).items()}
        else:
            self._spent = {}

    def seen(self, issuer: str, digest: str) -> bool:
        return digest in self._spent.get(issuer, set())

    def redeem(self, spend: dict, public_key, epoch: int | None = None) -> dict:
        """Record a spend after verifying it; raises on any failure (fail-closed)."""
        grant = spend.get("grant", {})
        token = bytes.fromhex(grant.get("token", ""))
        signature = int.from_bytes(bytes.fromhex(spend.get("redemption", "")), "big")
        if issuer_id(public_key) != grant.get("issuer"):
            raise UntrustedIssuer("the key does not match the grant's issuer")
        if epoch is not None and grant.get("epoch", epoch) > epoch:
            raise CreditError("a grant from the future")
        if not verify(token, signature, public_key):
            raise InvalidSignature("redemption does not verify")
        digest = token_digest(token)
        if self.seen(grant["issuer"], digest):
            raise DoubleSpend("this credit was already spent")
        self._spent.setdefault(grant["issuer"], set()).add(digest)
        self._flush()
        return {"ok": True, "issuer": grant["issuer"], "digest": digest}

    def _flush(self):
        tmp = self.path.with_name(self.path.name + ".tmp")
        doc = {"schema": SCHEMA, "spent": {k: sorted(v) for k, v in self._spent.items()}}
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc, indent=1) + "\n")
        os.replace(tmp, self.path)
        os.chmod(self.path, stat.S_IMODE(0o600))


# ------------------------------------------------------------------- demo

def issue_credit(private_key, epoch: int | None = None) -> tuple[dict, dict]:
    """Convenience: mint a full credit round-trip (for tests and the private-
    group flow, where one machine plays both sides)."""
    token = new_token()
    blinded, r = blind(token, private_key.public_key())
    sig = unblind(sign_blinded(private_key, blinded), r, private_key.public_key())
    grant = make_grant(token, private_key.public_key(), epoch)
    return grant, make_spend(grant, sig, private_key.key_size)

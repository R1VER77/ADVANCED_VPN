"""Oblivious control-plane requests: the RFC 9458 (Oblivious HTTP) design, post-quantum.

The mesh's control plane (descriptor fetch and publication through beacons) otherwise
tells every beacon which member's address asks for what. Oblivious requests split that
knowledge between two operators that do not collude:

- the **relay** sees the member's address and only ciphertext, both ways, and never
  names the member to the gateway (no forwarded-for header, nothing but the body);
- the **gateway** (in front of a beacon) sees the request, but only the relay's address.

Encapsulation follows RFC 9458's request shape (a header naming the key and the HPKE
suite, then the HPKE encapsulation and ciphertext), with the hybrid post-quantum KEM
ML-KEM-768 + X25519 (cryptography's HPKE, `KEM.MLKEM768_X25519`), HKDF-SHA256 and
AES-256-GCM. It is not wire-compatible with RFC 9458: the pinned library exposes
single-shot HPKE without the exporter that RFC 9458 derives the response key from, so
the client puts a fresh reply key inside its encrypted request and the gateway seals
the response to it. Requests carry a timestamp and a nonce; the gateway refuses stale
or replayed ones.
"""

import base64
import json
import os
import struct
import time

from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

# RFC 9180 / draft-ietf-hpke-pq identifiers, for the header only.
KEM_ID, KDF_ID, AEAD_ID = 0x647A, 0x0001, 0x0002
SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
REQUEST_INFO = b"advanced-vpn/ohttp/v1 request"
RESPONSE_INFO = b"advanced-vpn/ohttp/v1 response"
MLKEM_PUBLIC = 1184
PUBLIC = MLKEM_PUBLIC + 32
FRESH_SECONDS = 60
MAX_BODY = 1 << 20


class Refused(ValueError):
    """An oblivious request or response that is not authentic, fresh and well-formed."""


def keypair():
    """A new hybrid key pair: (private key, public bytes = ML-KEM-768 || X25519)."""
    m, x = mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    return hpke.MLKEM768X25519PrivateKey(m, x), public_bytes(m, x)


def public_bytes(m, x):
    """Serialize a hybrid public key: the ML-KEM-768 key, then the X25519 key."""
    raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    return m.public_key().public_bytes(*raw) + x.public_key().public_bytes(*raw)


def private_bytes(m, x):
    """Serialize a hybrid private key (seed form), for a gateway's private key file."""
    return m.private_bytes_raw() + x.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def load_private(raw):
    """The hybrid private key from `private_bytes`."""
    if len(raw) != 64 + 32:
        raise ValueError("bad gateway key")
    m = mlkem.MLKEM768PrivateKey.from_seed_bytes(raw[:64])
    x = x25519.X25519PrivateKey.from_private_bytes(raw[64:])
    return hpke.MLKEM768X25519PrivateKey(m, x), public_bytes(m, x)


def load_public(raw):
    """A hybrid public key from its bytes."""
    if len(raw) != PUBLIC:
        raise Refused("bad public key")
    return hpke.MLKEM768X25519PublicKey(
        mlkem.MLKEM768PublicKey.from_public_bytes(raw[:MLKEM_PUBLIC]),
        x25519.X25519PublicKey.from_public_bytes(raw[MLKEM_PUBLIC:]),
    )


def header(key_id):
    """RFC 9458 request header: key id, KEM, KDF, AEAD."""
    return struct.pack(">BHHH", key_id, KEM_ID, KDF_ID, AEAD_ID)


def encapsulate(gateway_public, key_id, method, path, body=b""):
    """Client: seal one request to the gateway. Returns (wire bytes, reply private key)."""
    if len(body) > MAX_BODY:
        raise ValueError("request too large")
    reply_private, reply_public = keypair()
    inner = json.dumps(
        dict(
            t=int(time.time()),
            nonce=os.urandom(16).hex(),
            method=method,
            path=path,
            body=base64.b64encode(body).decode(),
            reply=base64.b64encode(reply_public).decode(),
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    h = header(key_id)
    return h + SUITE.encrypt(inner, load_public(gateway_public), REQUEST_INFO + h), reply_private


class Gateway:
    """Gateway side: open requests sealed to this key, refusing stale or replayed ones."""

    def __init__(self, private, key_id, started=None):
        self.private, self.key_id = private, key_id
        self.seen = {}
        # The replay cache lives in memory. So that a restart cannot reopen the freshness
        # window to replays, nothing sent before this gateway started is accepted (to the
        # second: requests carry whole-second times); a client caught by a restart retries.
        self.started = int(time.time() if started is None else started)

    def open(self, wire, now=None):
        """(method, path, body, reply public key) of one request; raises Refused."""
        now = time.time() if now is None else now
        h = header(self.key_id)
        if len(wire) < len(h) or wire[: len(h)] != h:
            raise Refused("unknown key or suite")
        try:
            inner = json.loads(SUITE.decrypt(wire[len(h) :], self.private, REQUEST_INFO + h))
        except Exception as e:  # the library raises its own error types on a failed open
            raise Refused("not authentic") from e
        try:
            t, nonce = int(inner["t"]), str(inner["nonce"])
            method, path = str(inner["method"]), str(inner["path"])
            body = base64.b64decode(inner["body"], validate=True)
            reply = base64.b64decode(inner["reply"], validate=True)
        except (KeyError, TypeError, ValueError) as e:
            raise Refused("malformed request") from e
        if abs(now - t) > FRESH_SECONDS:
            raise Refused("stale request")
        if t < self.started:
            raise Refused("sent before this gateway started")
        self.seen = {n: s for n, s in self.seen.items() if now - s <= 2 * FRESH_SECONDS}
        if nonce in self.seen or len(nonce) != 32:
            raise Refused("replayed request")
        self.seen[nonce] = now
        load_public(reply)
        return method, path, body, reply

    @staticmethod
    def seal(reply, status, body):
        """Seal a response to the client's reply key."""
        inner = json.dumps(dict(status=status, body=base64.b64encode(body).decode())).encode()
        return SUITE.encrypt(inner, load_public(reply), RESPONSE_INFO)


def decapsulate(wire, reply_private):
    """Client: (status, body) of a sealed response; raises Refused."""
    try:
        inner = json.loads(SUITE.decrypt(wire, reply_private, RESPONSE_INFO))
        return int(inner["status"]), base64.b64decode(inner["body"], validate=True)
    except Exception as e:
        raise Refused("not authentic") from e

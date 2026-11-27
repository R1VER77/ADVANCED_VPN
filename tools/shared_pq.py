"""Multi-family post-quantum cryptography for shared-access admission and credits.

Combines independent hardness assumptions so breaking any single primitive does
not undo protection:
- Key exchange combiner: X25519 + X448 + ML-KEM-1024 with dual-hash
  HKDF-SHA-512 XOR HKDF-SHA3-512 (zero steady-state data-plane overhead).
- Multi-family signatures: FIPS 204 ML-DSA-87 (Module-LWE lattice) + SafeCurves
  Ed25519 + FIPS 205 SLH-DSA-SHA2-128f (stateless hash-based, zero algebraic or
  lattice assumptions) via OpenSSL 3.5 libcrypto when available, failing closed
  whenever a pinned SLH-DSA key is configured.
- RFC 9576 split-authority PQ Epoch Stamper: pairs RFC 9578 blind-RSA credits
  with multi-family PQ stamps so even a quantum break of RSA-2048 (or lattices)
  cannot forge access credits.
"""

from __future__ import annotations

import base64
from contextlib import closing
import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared_admission import AdmissionError, Cohort, EPOCH_SECONDS, TOKEN_INPUT_BYTES, verify_token


SLHDSA_ALG = b"SLH-DSA-SHA2-128f"
SLHDSA_PUBLIC_BYTES = 32
SLHDSA_SIGNATURE_BYTES = 17088
PQ_STAMP_DOMAIN = b"cpvpn/shared-pq-stamp/v1\0"
PQ_TICKET_DOMAIN = b"cpvpn/shared-pq-ticket/v1\0"

_LIBCRYPTO = None
_SLHDSA_READY: bool | None = None


def _load_libcrypto():
    """Load OpenSSL 3.5 libcrypto with FIPS 205 SLH-DSA support, or return None."""
    global _LIBCRYPTO, _SLHDSA_READY
    if _SLHDSA_READY is not None:
        return _LIBCRYPTO if _SLHDSA_READY else None
    try:
        lib = ctypes.CDLL("libcrypto.so.3")
        lib.EVP_PKEY_Q_keygen.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.EVP_PKEY_Q_keygen.restype = ctypes.c_void_p
        lib.EVP_PKEY_new_raw_public_key_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.EVP_PKEY_new_raw_public_key_ex.restype = ctypes.c_void_p
        lib.EVP_PKEY_get_raw_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        lib.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
        lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
        lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        lib.EVP_DigestSignInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.EVP_DigestSignInit_ex.restype = ctypes.c_int
        lib.EVP_DigestSign.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.EVP_DigestSign.restype = ctypes.c_int
        lib.EVP_DigestVerifyInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        lib.EVP_DigestVerifyInit_ex.restype = ctypes.c_int
        lib.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        lib.EVP_DigestVerify.restype = ctypes.c_int
        probe = lib.EVP_PKEY_Q_keygen(None, None, SLHDSA_ALG)
        if not probe:
            _SLHDSA_READY = False
            return None
        lib.EVP_PKEY_free(probe)
        _LIBCRYPTO = lib
        _SLHDSA_READY = True
        return lib
    except (OSError, AttributeError):
        _SLHDSA_READY = False
        return None


def slhdsa_available() -> bool:
    """Return True when OpenSSL 3.5 FIPS 205 SLH-DSA-SHA2-128f is usable."""
    return _load_libcrypto() is not None


class SlhDsaKeypair:
    """Ephemeral or service FIPS 205 SLH-DSA-SHA2-128f keypair backed by OpenSSL 3.5."""

    def __init__(self):
        lib = _load_libcrypto()
        if lib is None:
            raise AdmissionError("OpenSSL 3.5 SLH-DSA-SHA2-128f is unavailable")
        self._lib = lib
        self._pkey = lib.EVP_PKEY_Q_keygen(None, None, SLHDSA_ALG)
        if not self._pkey:
            raise AdmissionError("SLH-DSA key generation failed")
        plen = ctypes.c_size_t(SLHDSA_PUBLIC_BYTES)
        buf = ctypes.create_string_buffer(SLHDSA_PUBLIC_BYTES)
        if (
            lib.EVP_PKEY_get_raw_public_key(self._pkey, buf, ctypes.byref(plen)) != 1
            or plen.value != SLHDSA_PUBLIC_BYTES
        ):
            self.wipe()
            raise AdmissionError("SLH-DSA public key export failed")
        self.public_bytes = bytes(buf.raw)

    def sign(self, message: bytes) -> bytes:
        """Sign `message` with stateless hash-based SLH-DSA-SHA2-128f."""
        if not self._pkey:
            raise AdmissionError("SLH-DSA private key has been wiped")
        ctx = self._lib.EVP_MD_CTX_new()
        if not ctx:
            raise AdmissionError("OpenSSL MD_CTX allocation failed")
        try:
            if self._lib.EVP_DigestSignInit_ex(ctx, None, None, None, None, self._pkey, None) != 1:
                raise AdmissionError("SLH-DSA sign init failed")
            slen = ctypes.c_size_t(0)
            if self._lib.EVP_DigestSign(ctx, None, ctypes.byref(slen), message, len(message)) != 1:
                raise AdmissionError("SLH-DSA signature size query failed")
            if slen.value != SLHDSA_SIGNATURE_BYTES:
                raise AdmissionError("unexpected SLH-DSA signature buffer size")
            sig = ctypes.create_string_buffer(SLHDSA_SIGNATURE_BYTES)
            try:
                if self._lib.EVP_DigestSign(ctx, sig, ctypes.byref(slen), message, len(message)) != 1:
                    raise AdmissionError("SLH-DSA signing failed")
                if slen.value != SLHDSA_SIGNATURE_BYTES:
                    raise AdmissionError("unexpected SLH-DSA signature length")
                return bytes(sig.raw[: slen.value])
            finally:
                ctypes.memset(sig, 0, SLHDSA_SIGNATURE_BYTES)
        finally:
            self._lib.EVP_MD_CTX_free(ctx)

    def wipe(self):
        """Release the underlying OpenSSL EVP_PKEY handle."""
        if getattr(self, "_pkey", None):
            self._lib.EVP_PKEY_free(self._pkey)
            self._pkey = None

    def __del__(self):
        self.wipe()


def slhdsa_verify(public_bytes: bytes, signature: bytes, message: bytes):
    """Verify a FIPS 205 SLH-DSA-SHA2-128f signature; fail closed if unavailable or invalid."""
    if len(public_bytes) != SLHDSA_PUBLIC_BYTES or len(signature) != SLHDSA_SIGNATURE_BYTES:
        raise AdmissionError("invalid SLH-DSA public key or signature size")
    lib = _load_libcrypto()
    if lib is None:
        raise AdmissionError("SLH-DSA verification required but OpenSSL 3.5 is unavailable")
    pkey = lib.EVP_PKEY_new_raw_public_key_ex(None, SLHDSA_ALG, None, public_bytes, len(public_bytes))
    if not pkey:
        raise AdmissionError("invalid SLH-DSA public key")
    ctx = lib.EVP_MD_CTX_new()
    if not ctx:
        lib.EVP_PKEY_free(pkey)
        raise AdmissionError("OpenSSL MD_CTX allocation failed")
    try:
        if lib.EVP_DigestVerifyInit_ex(ctx, None, None, None, None, pkey, None) != 1:
            raise AdmissionError("SLH-DSA verify init failed")
        if lib.EVP_DigestVerify(ctx, signature, len(signature), message, len(message)) != 1:
            raise AdmissionError("invalid SLH-DSA signature")
    finally:
        lib.EVP_MD_CTX_free(ctx)
        lib.EVP_PKEY_free(pkey)


def dual_hkdf_expand(ikm: bytes | bytearray, salt_context: bytes, info: bytes, length: int = 32) -> bytes:
    """Dual-hash PRF combiner: HKDF-SHA-512 XOR HKDF-SHA3-512 (secure if either SHA-2 or SHA-3 holds)."""
    if not ikm or not any(ikm) or length <= 0:
        raise AdmissionError("invalid KDF inputs")
    ikm_bytes = bytes(ikm)
    salt_sha2 = hashlib.sha512(b"cpvpn/dual-kdf/sha2/v1\0" + salt_context).digest()
    salt_sha3 = hashlib.sha3_512(b"cpvpn/dual-kdf/sha3/v1\0" + salt_context).digest()
    out_sha2 = HKDF(algorithm=hashes.SHA512(), length=length, salt=salt_sha2, info=info).derive(ikm_bytes)
    out_sha3 = HKDF(algorithm=hashes.SHA3_512(), length=length, salt=salt_sha3, info=info).derive(ikm_bytes)
    combined = bytes(a ^ b for a, b in zip(out_sha2, out_sha3, strict=True))
    if not any(combined):
        raise AdmissionError("degenerate KDF output")
    return combined


@dataclass(frozen=True)
class HybridPqPublic:
    """Pinned multi-family public identity: ML-DSA-87 + Ed25519 + optional SLH-DSA-SHA2-128f."""

    mldsa87_raw: bytes
    ed25519_raw: bytes
    slhdsa_raw: bytes | None = None

    def __post_init__(self):
        if len(self.mldsa87_raw) != 2592 or len(self.ed25519_raw) != 32:
            raise AdmissionError("invalid hybrid PQ public key sizes")
        if self.slhdsa_raw is not None and len(self.slhdsa_raw) != SLHDSA_PUBLIC_BYTES:
            raise AdmissionError("invalid SLH-DSA public key size")

    def to_dict(self) -> dict[str, str]:
        """Serialize pinned multi-family public keys as base64 strings."""
        out = {
            "mldsa87": base64.b64encode(self.mldsa87_raw).decode("ascii"),
            "ed25519": base64.b64encode(self.ed25519_raw).decode("ascii"),
        }
        if self.slhdsa_raw is not None:
            out["slhdsa_sha2_128f"] = base64.b64encode(self.slhdsa_raw).decode("ascii")
        return out

    @classmethod
    def from_dict(cls, data: dict) -> HybridPqPublic:
        """Deserialize pinned multi-family public keys strictly."""
        if not isinstance(data, dict):
            raise AdmissionError("invalid hybrid PQ public key object")
        try:
            mldsa87_raw = base64.b64decode(data["mldsa87"], validate=True)
            ed25519_raw = base64.b64decode(data["ed25519"], validate=True)
            slhdsa_raw = (
                base64.b64decode(data["slhdsa_sha2_128f"], validate=True) if "slhdsa_sha2_128f" in data else None
            )
        except (KeyError, TypeError, ValueError):
            raise AdmissionError("malformed hybrid PQ public key encoding") from None
        return cls(mldsa87_raw=mldsa87_raw, ed25519_raw=ed25519_raw, slhdsa_raw=slhdsa_raw)

    def verify(self, domain: bytes, message: bytes, signatures: dict):
        """Verify EVERY pinned signature family; fail closed on any missing or invalid leg."""
        if not isinstance(signatures, dict):
            raise AdmissionError("missing multi-family PQ signatures")
        digest = domain + hashlib.sha512(message).digest() + hashlib.sha3_512(message).digest()
        try:
            mldsa_sig = base64.b64decode(signatures["mldsa87"], validate=True)
            ed_sig = base64.b64decode(signatures["ed25519"], validate=True)
            mldsa.MLDSA87PublicKey.from_public_bytes(self.mldsa87_raw).verify(mldsa_sig, digest)
            ed25519.Ed25519PublicKey.from_public_bytes(self.ed25519_raw).verify(ed_sig, digest)
        except (KeyError, TypeError, ValueError, InvalidSignature):
            raise AdmissionError("invalid ML-DSA-87 or Ed25519 signature") from None
        if self.slhdsa_raw is not None:
            if "slhdsa_sha2_128f" not in signatures:
                raise AdmissionError("missing required SLH-DSA-SHA2-128f signature")
            try:
                slh_sig = base64.b64decode(signatures["slhdsa_sha2_128f"], validate=True)
            except (TypeError, ValueError):
                raise AdmissionError("malformed SLH-DSA-SHA2-128f signature") from None
            slhdsa_verify(self.slhdsa_raw, slh_sig, digest)


class HybridPqIdentity:
    """Multi-family signer combining ML-DSA-87 (lattice) + Ed25519 (SafeCurves) + SLH-DSA (hash-based)."""

    def __init__(self, *, include_slhdsa: bool | None = None):
        use_slhdsa = slhdsa_available() if include_slhdsa is None else include_slhdsa
        self._mldsa87 = mldsa.MLDSA87PrivateKey.generate()
        self._ed25519 = ed25519.Ed25519PrivateKey.generate()
        self._slhdsa = SlhDsaKeypair() if use_slhdsa else None
        self.public = HybridPqPublic(
            mldsa87_raw=self._mldsa87.public_key().public_bytes_raw(),
            ed25519_raw=self._ed25519.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            slhdsa_raw=self._slhdsa.public_bytes if self._slhdsa is not None else None,
        )

    def sign(self, domain: bytes, message: bytes) -> dict[str, str]:
        """Sign `domain || SHA-512(message) || SHA3-512(message)` under every active family."""
        if self._mldsa87 is None or self._ed25519 is None:
            raise AdmissionError("hybrid PQ private identity has been wiped")
        digest = domain + hashlib.sha512(message).digest() + hashlib.sha3_512(message).digest()
        sigs = {
            "mldsa87": base64.b64encode(self._mldsa87.sign(digest)).decode("ascii"),
            "ed25519": base64.b64encode(self._ed25519.sign(digest)).decode("ascii"),
        }
        if self._slhdsa is not None:
            sigs["slhdsa_sha2_128f"] = base64.b64encode(self._slhdsa.sign(digest)).decode("ascii")
        return sigs

    def wipe(self):
        """Destroy all private key handles immediately (forward privacy on retirement/shutdown)."""
        self._mldsa87 = None
        self._ed25519 = None
        if self._slhdsa is not None:
            self._slhdsa.wipe()
            self._slhdsa = None


def pq_stamp_message(cohort: Cohort, token: bytes) -> bytes:
    """Canonical message signed by the independent PQ Epoch Stamper for one RFC 9578 credit."""
    if len(token) < TOKEN_INPUT_BYTES:
        raise AdmissionError("invalid token length for PQ stamp")
    return (
        PQ_STAMP_DOMAIN
        + hashlib.sha3_256(cohort.challenge).digest()
        + hashlib.sha3_256(token[:TOKEN_INPUT_BYTES]).digest()
    )


def issue_checkout_ticket(attester: HybridPqIdentity, epoch: int) -> dict:
    """Mint one single-use PQ-authenticated exchange ticket bound to `epoch` (anti-CRQC forgery)."""
    ticket_id = os.urandom(32)
    body = epoch.to_bytes(4, "big") + ticket_id
    return {
        "epoch": epoch,
        "ticket_id": ticket_id.hex(),
        "signatures": attester.sign(PQ_TICKET_DOMAIN, body),
    }


class PqEpochStamper:
    """RFC 9576 split-authority PQ stamper adding ML-DSA-87 + SLH-DSA + Ed25519 unforgeability.

    Operated independently of checkout and relays (reached over a separate Tor circuit or
    mix-lane): never observes payment txids or order IDs, verifies both the unblinded
    RFC 9578 token and the checkout attester's multi-family PQ ticket, atomically consumes
    both one-time exchange digests, and stamps the credit with its own multi-family PQ key.
    """

    def __init__(self, ledger_path: Path, attester_public: HybridPqPublic, *, include_slhdsa: bool | None = None):
        self.ledger_path = ledger_path
        self.attester_public = attester_public
        self.identity = HybridPqIdentity(include_slhdsa=include_slhdsa)
        self.public = self.identity.public

    def initialize(self):
        """Provision a private atomic exchange ledger without overwriting an existing file."""
        fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(self._connect()) as db, db:
            db.execute("CREATE TABLE stamped_tokens (digest BLOB PRIMARY KEY, expires INTEGER NOT NULL) WITHOUT ROWID")
            db.execute(
                "CREATE TABLE spent_tickets (ticket_id BLOB PRIMARY KEY, expires INTEGER NOT NULL) WITHOUT ROWID"
            )

    def _connect(self):
        return sqlite3.connect(self.ledger_path.absolute().as_uri() + "?mode=rw", uri=True, timeout=5)

    def stamp(self, cohort: Cohort, token: bytes, ticket: dict, *, now: int) -> dict[str, str]:
        """Verify RFC 9578 token + PQ checkout ticket, consume both once, and return PQ stamp."""
        if cohort.epoch not in (now // EPOCH_SECONDS, now // EPOCH_SECONDS + 1):
            raise AdmissionError("stamper refuses inactive or stale cohort epoch")
        if not isinstance(ticket, dict) or ticket.get("epoch") != cohort.epoch:
            raise AdmissionError("PQ checkout ticket epoch mismatch")
        try:
            ticket_id = bytes.fromhex(ticket["ticket_id"])
        except (KeyError, TypeError, ValueError):
            raise AdmissionError("invalid PQ checkout ticket") from None
        if len(ticket_id) != 32 or not any(ticket_id):
            raise AdmissionError("invalid PQ checkout ticket identifier")
        self.attester_public.verify(
            PQ_TICKET_DOMAIN, cohort.epoch.to_bytes(4, "big") + ticket_id, ticket.get("signatures")
        )
        token_digest = verify_token(token, cohort.challenge, cohort.issuer_spki)
        try:
            with closing(self._connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                t1 = db.execute("INSERT OR IGNORE INTO stamped_tokens VALUES (?, ?)", (token_digest, cohort.expires))
                t2 = db.execute("INSERT OR IGNORE INTO spent_tickets VALUES (?, ?)", (ticket_id, cohort.expires))
                if t1.rowcount != 1 or t2.rowcount != 1:
                    raise AdmissionError("credit or PQ checkout ticket already stamped")
        except sqlite3.Error:
            raise AdmissionError("PQ stamper ledger unavailable") from None
        return self.identity.sign(PQ_STAMP_DOMAIN, pq_stamp_message(cohort, token))

    def retire_epoch(self, now: int):
        """Destroy the epoch stamper private keys and prune expired exchange digests."""
        self.identity.wipe()
        cutoff = now // EPOCH_SECONDS * EPOCH_SECONDS
        with closing(self._connect()) as db, db:
            db.execute("PRAGMA secure_delete = ON")
            db.execute("DELETE FROM stamped_tokens WHERE expires <= ?", (cutoff,))
            db.execute("DELETE FROM spent_tickets WHERE expires <= ?", (cutoff,))

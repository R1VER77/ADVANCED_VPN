"""Shared-access pilot admission primitives. No production routing or implicit opt-in."""

from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import os
import re
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, padding, rsa


EPOCH_SECONDS = 86400
SESSION_SECONDS = 3600
TOKEN_TYPE = b"\x00\x02"
TOKEN_INPUT_BYTES = 98
TOKEN_SIGNATURE_BYTES = 256
# The canonical RSA-2048 SPKI encoding in RFC 9578 section 6.5. This pilot
# pins SHA-384, MGF1(SHA-384), a 48-byte salt, and exponent 65537.
SPKI_PREFIX = bytes.fromhex(
    "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202"
    "a11a301806092a864886f70d010108300b0609608648016503040202a203020130"
    "0382010f00"
)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
ROLES = ("entry", "exit")
DNS_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class AdmissionError(ValueError):
    """A generic admission failure that carries no client metadata."""


def token_public_key(spki: bytes) -> rsa.RSAPublicKey:
    """Load the exact issuer key encoding supported by the pilot."""
    if len(spki) != 342 or not spki.startswith(SPKI_PREFIX):
        raise AdmissionError("unsupported issuer key encoding")
    try:
        key = serialization.load_der_public_key(spki[len(SPKI_PREFIX) :])
    except ValueError:
        raise AdmissionError("invalid issuer key") from None
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537:
        raise AdmissionError("unsupported issuer key")
    return key


def verify_token(token: bytes, challenge: bytes, spki: bytes) -> bytes:
    """Verify an RFC 9578 type 2 token and return its opaque replay digest."""
    if len(token) != TOKEN_INPUT_BYTES + TOKEN_SIGNATURE_BYTES or token[:2] != TOKEN_TYPE:
        raise AdmissionError("invalid token format")
    if token[34:66] != hashlib.sha256(challenge).digest() or token[66:98] != hashlib.sha256(spki).digest():
        raise AdmissionError("token does not match the admission policy")
    try:
        token_public_key(spki).verify(token[TOKEN_INPUT_BYTES:], token[:TOKEN_INPUT_BYTES], PSS, hashes.SHA384())
    except InvalidSignature:
        raise AdmissionError("invalid token signature") from None
    # Hash the signed input, independent of the PSS signature or its encoding.
    return hashlib.sha256(b"cpvpn/shared-replay/v1\0" + token[:TOKEN_INPUT_BYTES]).digest()


@dataclass(frozen=True)
class Cohort:
    """One trusted pool, relay role, issuer key and UTC redemption epoch."""

    issuer_name: str
    pool_name: str
    role: str
    epoch: int
    issuer_spki: bytes = field(repr=False)

    def __post_init__(self):
        if self.role not in ROLES or type(self.epoch) is not int or not 0 <= self.epoch < 2**31:
            raise AdmissionError("invalid admission cohort")
        for name in (self.issuer_name, self.pool_name):
            if len(name) > 240 or not DNS_NAME.fullmatch(name):
                raise AdmissionError("invalid issuer or pool name")
        token_public_key(self.issuer_spki)

    @property
    def challenge(self) -> bytes:
        """RFC 9577 challenge shared by the entire role and epoch, with no client fields."""
        issuer = self.issuer_name.encode("ascii")
        origin = f"{self.role}.{self.pool_name}".encode("ascii")
        context = hashlib.sha256(b"cpvpn/shared-epoch/v1\0" + self.epoch.to_bytes(4, "big")).digest()
        return (
            TOKEN_TYPE
            + len(issuer).to_bytes(2, "big")
            + issuer
            + b"\x20"
            + context
            + len(origin).to_bytes(2, "big")
            + origin
        )

    @property
    def expires(self) -> int:
        """Last instant at which the corresponding epoch is active, exclusive."""
        return (self.epoch + 1) * EPOCH_SECONDS


class ReplayLedger:
    """Atomic replay protection for one role in a private service state directory.

    Every instance for a pool role must use the same authoritative ledger. An
    unavailable database is a refusal. Retirement permanently advances the
    earliest allowed expiry before deleting old digests.
    """

    def __init__(self, path: Path, role: str):
        if role not in ROLES:
            raise AdmissionError("invalid ledger role")
        self.path = path
        self.role = role

    def initialize(self):
        """Provision the role ledger explicitly. Refuse to overwrite an existing ledger."""
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(self._connect()) as db, db:
            db.execute(f"PRAGMA application_id = {self._application_id()}")
            db.execute("CREATE TABLE spent (digest BLOB PRIMARY KEY, expires INTEGER NOT NULL) WITHOUT ROWID")
            db.execute("CREATE TABLE retirement (cutoff INTEGER NOT NULL)")
            db.execute("INSERT INTO retirement VALUES (0)")

    def _connect(self):
        return sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True, timeout=5)

    def _application_id(self):
        return 0x43504131 + ROLES.index(self.role)

    def _begin(self, db):
        db.execute("BEGIN IMMEDIATE")
        if db.execute("PRAGMA application_id").fetchone() != (self._application_id(),):
            raise AdmissionError("replay ledger has the wrong role")
        row = db.execute("SELECT cutoff FROM retirement").fetchone()
        if row is None:
            raise AdmissionError("replay ledger unavailable")
        return row[0]

    def consume(self, digest: bytes, expires: int):
        """Record exactly one redemption, including across processes and restarts."""
        try:
            with closing(self._connect()) as db, db:
                if expires <= self._begin(db):
                    raise AdmissionError("token epoch permanently retired")
                seen = db.execute("INSERT OR IGNORE INTO spent VALUES (?, ?)", (digest, expires))
                if seen.rowcount != 1:
                    raise AdmissionError("token already redeemed")
        except sqlite3.Error:
            raise AdmissionError("replay ledger unavailable") from None

    def retire_expired(self, now: int):
        """Permanently retire past UTC epochs and remove their spent digests."""
        expiry = now // EPOCH_SECONDS * EPOCH_SECONDS
        try:
            with closing(self._connect()) as db, db:
                db.execute("PRAGMA secure_delete = ON")
                cutoff = self._begin(db)
                if expiry > cutoff:
                    db.execute("UPDATE retirement SET cutoff = ?", (expiry,))
                    db.execute("DELETE FROM spent WHERE expires <= ?", (expiry,))
        except sqlite3.Error:
            raise AdmissionError("replay ledger unavailable") from None


def binding_message(
    cohort: Cohort, token: bytes, hop_key_id: bytes, channel_binding: bytes, carrier_key: bytes
) -> bytes:
    """Bind a fresh client key to this hop, live channel and WireGuard peer key."""
    if any(len(value) != 32 or not any(value) for value in (hop_key_id, channel_binding, carrier_key)):
        raise AdmissionError("invalid session binding")
    return (
        b"cpvpn/shared-admission/v1\0"
        + hashlib.sha256(cohort.challenge).digest()
        + hashlib.sha256(token).digest()
        + hop_key_id
        + channel_binding
        + carrier_key
    )


def admit(
    cohort: Cohort,
    ledger: ReplayLedger,
    token: bytes,
    now: int,
    *,
    hop_key_id: bytes,
    channel_binding: bytes,
    carrier_key: bytes,
    session_key: mldsa.MLDSA65PublicKey,
    proof: bytes,
) -> int:
    """Verify a spend and session proof before returning a short-lived peer expiry.

    The caller supplies the pinned hop ID, locally derived TLS exporter and wall
    clock. A token is consumed before the caller can install any peer state.
    """
    if ledger.role != cohort.role or now // EPOCH_SECONDS != cohort.epoch:
        raise AdmissionError("token epoch or role is inactive")
    if not isinstance(session_key, mldsa.MLDSA65PublicKey):
        raise AdmissionError("session key must be ML-DSA-65")
    digest = verify_token(token, cohort.challenge, cohort.issuer_spki)
    try:
        session_key.verify(proof, binding_message(cohort, token, hop_key_id, channel_binding, carrier_key))
    except InvalidSignature:
        raise AdmissionError("invalid session proof") from None
    ledger.consume(digest, cohort.expires)
    return min(cohort.expires, now + SESSION_SECONDS)

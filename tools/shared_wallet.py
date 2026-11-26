"""Nitrokey-sealed fixed-size credit batches for the shared-access pilot."""

import fcntl
import hashlib
import json
import os
from pathlib import Path

import keyguard
from shared_admission import AdmissionError, Cohort, EPOCH_SECONDS, ROLES, verify_token


PAIRS_PER_BATCH = 4
WALLET_ROLE = "shared-pilot-credits-v1"


class CreditWallet:
    """Store locally verified credits and reserve an entry/exit pair at most once."""

    def __init__(self, path: Path, vault: Path, entry: Cohort, exit: Cohort):
        if (entry.role, exit.role) != ROLES or (entry.issuer_name, entry.pool_name, entry.epoch, entry.issuer_spki) != (
            exit.issuer_name,
            exit.pool_name,
            exit.epoch,
            exit.issuer_spki,
        ):
            raise AdmissionError("wallet cohorts do not belong to the same issuance batch")
        self.path = path
        self.vault = vault
        self.cohorts = (entry, exit)
        self.binding = hashlib.sha256(entry.challenge + exit.challenge + entry.issuer_spki).digest()

    def _write(self, pairs, secret, meta):
        body = json.dumps([[token.hex() for token in pair] for pair in pairs]).encode()
        document = keyguard.seal_bytes(secret, meta, WALLET_ROLE, self.binding, body)
        keyguard.atomic(self.path, json.dumps(document).encode())

    def import_batch(self, pairs):
        """Seal one verified batch. Importing again cannot resurrect spent credits."""
        if len(pairs) != PAIRS_PER_BATCH or any(len(pair) != len(ROLES) for pair in pairs):
            raise AdmissionError("invalid credit batch size")
        digests = {
            verify_token(token, cohort.challenge, cohort.issuer_spki)
            for pair in pairs
            for token, cohort in zip(pair, self.cohorts, strict=True)
        }
        if len(digests) != PAIRS_PER_BATCH * len(ROLES):
            raise AdmissionError("duplicate credit in batch")
        with self._lock():
            if os.path.lexists(self.path):
                raise AdmissionError("this credit wallet has already been imported")
            secret, meta = keyguard.hardware_secret(self.vault)
            self._write(pairs, secret, meta)

    def take_pair(self, now: int) -> tuple[bytes, bytes]:
        """Unlock locally and remove one pair before returning it to the caller."""
        if now // EPOCH_SECONDS != self.cohorts[0].epoch:
            raise AdmissionError("credit batch is outside its redemption epoch")
        with self._lock():
            document = json.loads(keyguard.read_private(self.path))
            secret, meta = keyguard.hardware_secret(self.vault)
            rows = json.loads(keyguard.open_bytes(secret, meta, WALLET_ROLE, self.binding, document))
            if not rows:
                raise AdmissionError("credit wallet is empty")
            pairs = [tuple(bytes.fromhex(value) for value in pair) for pair in rows]
            self._write(pairs[1:], secret, meta)
            return pairs[0]

    def _lock(self):
        path = self.path.with_name(self.path.name + ".lock")
        fd = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        lock = os.fdopen(fd, "rb")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
        except OSError:
            lock.close()
            raise
        return lock

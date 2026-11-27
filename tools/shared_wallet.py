"""Nitrokey-sealed fixed-size credit batches for the shared-access pilot."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets

import keyguard
from shared_admission import AdmissionError, Cohort, EPOCH_SECONDS, ROLES, verify_token
from shared_pq import PQ_STAMP_DOMAIN, pq_stamp_message


PAIRS_PER_BATCH = 4
WALLET_ROLE = "shared-pilot-credits-v1"
# Constant-size sealed envelopes so encrypted wallet length on disk never leaks remaining credit count.
WALLET_PADDED_BYTES = 8192
WALLET_STAMPED_PADDED_BYTES = 327680
WALLET_MAX_SEALED_BYTES = 524288


class CreditWallet:
    """Store locally verified credits (with optional multi-family PQ stamps) and reserve each pair at most once."""

    def __init__(self, path: Path, vault: Path, entry: Cohort, exit: Cohort):
        if (entry.role, exit.role) != ROLES or (
            entry.issuer_name,
            entry.pool_name,
            entry.epoch,
            entry.issuer_spki,
            entry.pq_stamper_public,
        ) != (
            exit.issuer_name,
            exit.pool_name,
            exit.epoch,
            exit.issuer_spki,
            exit.pq_stamper_public,
        ):
            raise AdmissionError("wallet cohorts do not belong to the same issuance batch")
        self.path = path
        self.vault = vault
        self.cohorts = (entry, exit)
        stamper_bind = (
            json.dumps(entry.pq_stamper_public.to_dict(), sort_keys=True).encode()
            if entry.pq_stamper_public is not None
            else b""
        )
        self.binding = hashlib.sha256(entry.challenge + exit.challenge + entry.issuer_spki + stamper_bind).digest()

    def _write(self, pairs, secret, meta, pq_stamps=None):
        if pq_stamps is None:
            raw = json.dumps([[token.hex() for token in pair] for pair in pairs], separators=(",", ":")).encode()
            target_size = WALLET_PADDED_BYTES
        else:
            raw = json.dumps(
                {
                    "pairs": [[token.hex() for token in pair] for pair in pairs],
                    "pq_stamps": [list(stamps) for stamps in pq_stamps],
                },
                separators=(",", ":"),
            ).encode()
            target_size = WALLET_STAMPED_PADDED_BYTES
        if len(raw) > target_size:
            raise AdmissionError("credit wallet payload exceeds fixed padded envelope")
        body = bytearray(raw) + bytearray(b" " * (target_size - len(raw)))
        try:
            document = keyguard.seal_bytes(secret, meta, WALLET_ROLE, self.binding, bytes(body))
            keyguard.atomic(self.path, json.dumps(document).encode())
        finally:
            body[:] = bytes(len(body))

    def import_batch(self, pairs, pq_stamps=None):
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
        stamper_pub = self.cohorts[0].pq_stamper_public
        if stamper_pub is not None and pq_stamps is None:
            raise AdmissionError("pool requires multi-family PQ stamps on imported credits")
        if pq_stamps is not None:
            if stamper_pub is None:
                raise AdmissionError("PQ stamps provided but pool pins no pq_stamper_public key")
            if len(pq_stamps) != PAIRS_PER_BATCH or any(len(row) != len(ROLES) for row in pq_stamps):
                raise AdmissionError("invalid PQ stamp batch size")
            for pair, stamp_pair in zip(pairs, pq_stamps, strict=True):
                for token, stamp, cohort in zip(pair, stamp_pair, self.cohorts, strict=True):
                    if not isinstance(stamp, dict):
                        raise AdmissionError("malformed PQ stamp in batch")
                    try:
                        stamper_pub.verify(PQ_STAMP_DOMAIN, pq_stamp_message(cohort, token), stamp)
                    except ValueError as err:
                        raise AdmissionError(f"invalid multi-family PQ stamp: {err}") from None
        with self._lock():
            if os.path.lexists(self.path):
                raise AdmissionError("this credit wallet has already been imported")
            secret, meta = keyguard.hardware_secret(self.vault)
            order = list(range(len(pairs)))
            secrets.SystemRandom().shuffle(order)
            shuffled_pairs = [pairs[i] for i in order]
            shuffled_stamps = [pq_stamps[i] for i in order] if pq_stamps is not None else None
            self._write(shuffled_pairs, secret, meta, pq_stamps=shuffled_stamps)

    def take_stamped_pair(self, now: int) -> tuple[tuple[bytes, bytes], tuple[dict, dict] | None]:
        """Unlock locally and remove one randomly selected pair (and its PQ stamps if present)."""
        if now // EPOCH_SECONDS != self.cohorts[0].epoch:
            raise AdmissionError("credit batch is outside its redemption epoch")
        with self._lock():
            document = json.loads(keyguard.read_private(self.path, limit=WALLET_MAX_SEALED_BYTES))
            secret, meta = keyguard.hardware_secret(self.vault)
            opened = bytearray(keyguard.open_bytes(secret, meta, WALLET_ROLE, self.binding, document))
            try:
                decoded = json.loads(opened.decode())
            finally:
                opened[:] = bytes(len(opened))
            if isinstance(decoded, dict):
                rows = decoded.get("pairs", [])
                stamp_rows = decoded.get("pq_stamps")
            else:
                rows = decoded
                stamp_rows = None
            if not rows:
                raise AdmissionError("credit wallet is empty")
            pairs = [tuple(bytes.fromhex(value) for value in pair) for pair in rows]
            idx = secrets.randbelow(len(pairs))
            chosen = pairs.pop(idx)
            chosen_stamps = None
            if stamp_rows is not None:
                if len(stamp_rows) != len(pairs) + 1:
                    raise AdmissionError("corrupt stamped credit wallet")
                chosen_stamps = tuple(stamp_rows.pop(idx))
            self._write(pairs, secret, meta, pq_stamps=stamp_rows)
            return chosen, chosen_stamps

    def take_pair(self, now: int) -> tuple[bytes, bytes]:
        """Unlock locally and remove one randomly selected pair before returning it."""
        pair, _ = self.take_stamped_pair(now)
        return pair

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

"""Post-quantum STARK credit migration bridge (docs/ZK_MEMBERSHIP_DESIGN.md, v1.0 track).

Matches research/zk-membership/methods/guest/src/main.rs byte-for-byte:
- Leaf commitment:  SHA-256("cpvpn/member/v2" || H^N(s0))
- Forward step:     H(x) = SHA-256("cpvpn/fp-step/v1" || x)
- Merkle node:      SHA-256("cpvpn/node/v1" || left || right)
- Nullifier:        SHA-256("cpvpn/nullifier/v2" || x_k || epoch_u64_be || scope_32)
- Action binding:   SHA-256("cpvpn/zk-action/v1\0" || request_bytes)

Provides canonical Merkle tree construction, forward-private journal verification,
atomic SQLite nullifier replay protection with secure deletion on epoch retirement,
and fail-closed pluggable RISC Zero STARK receipt verification (plus optional hybrid
multi-family PQ stamp verification during the transition window).
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3

import zkid


NODE_DOMAIN = b"cpvpn/node/v1"
ACTION_DOMAIN = b"cpvpn/zk-action/v1\0"
EMPTY_LEAF = hashlib.sha256(b"cpvpn/empty-leaf/v1").digest()


class ZkCreditError(ValueError):
    """Refusal of a STARK membership credit or nullifier."""


def merkle_node(left: bytes, right: bytes) -> bytes:
    """Internal SHA-256 Merkle node matching `research/zk-membership/methods/guest/src/main.rs`."""
    if len(left) != 32 or len(right) != 32:
        raise ZkCreditError("Merkle node inputs must be 32 bytes")
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def action_hash(request_bytes: bytes) -> bytes:
    """Bind a STARK proof to the exact admission or relay request it authorizes."""
    if not isinstance(request_bytes, bytes) or not request_bytes:
        raise ZkCreditError("request bytes must be non-empty")
    return hashlib.sha256(ACTION_DOMAIN + request_bytes).digest()


def fold_merkle_path(leaf: bytes, path: list[tuple[bytes, bool]]) -> bytes:
    """Fold `(sibling, sibling_is_right)` from leaf to root, identical to the RISC Zero guest."""
    node = leaf
    for sibling, sibling_is_right in path:
        node = merkle_node(node, sibling) if sibling_is_right else merkle_node(sibling, node)
    return node


class MemberTree:
    """Deterministic binary SHA-256 Merkle tree of registered forward-private commitments."""

    def __init__(self, leaves: list[bytes]):
        if not leaves or any(not isinstance(item, bytes) or len(item) != 32 for item in leaves):
            raise ZkCreditError("member tree requires one or more 32-byte commitments")
        size = 1
        while size < len(leaves):
            size <<= 1
        self._leaves = list(leaves) + [EMPTY_LEAF] * (size - len(leaves))
        self._levels: list[list[bytes]] = [self._leaves]
        current = self._leaves
        while len(current) > 1:
            nxt = [merkle_node(current[i], current[i + 1]) for i in range(0, len(current), 2)]
            self._levels.append(nxt)
            current = nxt

    @property
    def root(self) -> bytes:
        """Return the 32-byte Merkle root committed in the directory."""
        return self._levels[-1][0]

    def proof_path(self, index: int) -> list[tuple[bytes, bool]]:
        """Return `(sibling, sibling_is_right)` path for leaf `index`."""
        if not 0 <= index < len(self._leaves):
            raise ZkCreditError("leaf index out of range")
        path: list[tuple[bytes, bool]] = []
        idx = index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                path.append((level[idx + 1], True))
            else:
                path.append((level[idx - 1], False))
            idx >>= 1
        return path


@dataclass(frozen=True)
class StarkJournal:
    """Canonical 7-field public output matching `env::commit(...)` in the RISC Zero guest."""

    root: bytes
    lifetime: int
    start: int
    epoch: int
    scope: bytes
    nullifier: bytes
    action: bytes

    def __post_init__(self):
        for field_name, val in (
            ("root", self.root),
            ("scope", self.scope),
            ("nullifier", self.nullifier),
            ("action", self.action),
        ):
            if not isinstance(val, bytes) or len(val) != 32:
                raise ZkCreditError(f"invalid {field_name} length")
        if self.lifetime < 1 or self.start < 0 or not (self.start <= self.epoch <= self.start + self.lifetime):
            raise ZkCreditError("journal epoch outside tree lifetime")

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for receipt binding and optional hybrid PQ stamping."""
        return (
            b"cpvpn/zk-journal/v2\0"
            + self.root
            + self.lifetime.to_bytes(8, "big")
            + self.start.to_bytes(8, "big")
            + self.epoch.to_bytes(8, "big")
            + self.scope
            + self.nullifier
            + self.action
        )


def reference_guest_evaluate(
    *,
    x_epoch: bytes,
    path: list[tuple[bytes, bool]],
    lifetime: int,
    start: int,
    epoch: int,
    scope: bytes,
    request_bytes: bytes,
) -> StarkJournal:
    """Reference witness evaluation matching `guest/src/main.rs` (for tests & witness preflight)."""
    leaf = zkid.leaf_from(x_epoch, epoch, start, lifetime)
    root = fold_merkle_path(leaf, path)
    nf = zkid.nullifier(x_epoch, epoch, scope)
    return StarkJournal(
        root=root,
        lifetime=lifetime,
        start=start,
        epoch=epoch,
        scope=scope,
        nullifier=nf,
        action=action_hash(request_bytes),
    )


class NullifierLedger:
    """Atomic SQLite nullifier replay protection with secure deletion on epoch retirement."""

    def __init__(self, path: Path):
        self.path = path

    def initialize(self):
        """Create a private nullifier ledger without overwriting an existing file."""
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(self._connect()) as db, db:
            db.execute(
                "CREATE TABLE nullifiers (epoch INTEGER NOT NULL, scope BLOB NOT NULL, "
                "nullifier BLOB NOT NULL, PRIMARY KEY (epoch, scope, nullifier)) WITHOUT ROWID"
            )
            db.execute("CREATE TABLE retirement (min_epoch INTEGER NOT NULL)")
            db.execute("INSERT INTO retirement VALUES (0)")

    def _connect(self):
        return sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True, timeout=5)

    def consume(self, epoch: int, scope: bytes, nullifier: bytes):
        """Record one nullifier atomically; reject replays or retired epochs."""
        try:
            with closing(self._connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                min_epoch = db.execute("SELECT min_epoch FROM retirement").fetchone()[0]
                if epoch < min_epoch:
                    raise ZkCreditError("credit epoch permanently retired")
                cur = db.execute("INSERT OR IGNORE INTO nullifiers VALUES (?, ?, ?)", (epoch, scope, nullifier))
                if cur.rowcount != 1:
                    raise ZkCreditError("nullifier already spent in this epoch and scope")
        except sqlite3.Error:
            raise ZkCreditError("nullifier ledger unavailable") from None

    def retire_before(self, min_epoch: int):
        """Advance the permanent epoch floor and securely wipe retired nullifiers."""
        try:
            with closing(self._connect()) as db, db:
                db.execute("PRAGMA secure_delete = ON")
                db.execute("BEGIN IMMEDIATE")
                current = db.execute("SELECT min_epoch FROM retirement").fetchone()[0]
                if min_epoch > current:
                    db.execute("UPDATE retirement SET min_epoch = ?", (min_epoch,))
                    db.execute("DELETE FROM nullifiers WHERE epoch < ?", (min_epoch,))
        except sqlite3.Error:
            raise ZkCreditError("nullifier ledger unavailable") from None


class StarkCreditVerifier:
    """Fail-closed verifier for forward-private STARK membership credits (v1.0 migration)."""

    def __init__(
        self,
        *,
        image_id: bytes,
        trusted_root: bytes,
        tree_start: int,
        tree_lifetime: int,
        allowed_scopes: set[bytes],
        ledger: NullifierLedger,
        verify_receipt: Callable[[bytes, bytes, StarkJournal], bool],
        hybrid_pq_public=None,
    ):
        if len(image_id) != 32 or len(trusted_root) != 32 or not allowed_scopes:
            raise ZkCreditError("invalid STARK verifier configuration")
        self.image_id = image_id
        self.trusted_root = trusted_root
        self.tree_start = tree_start
        self.tree_lifetime = tree_lifetime
        self.allowed_scopes = frozenset(allowed_scopes)
        self.ledger = ledger
        self.verify_receipt = verify_receipt
        self.hybrid_pq_public = hybrid_pq_public

    def redeem(
        self,
        *,
        receipt: bytes,
        journal: StarkJournal,
        request_bytes: bytes,
        current_epoch: int,
        pq_stamp: dict | None = None,
    ) -> bytes:
        """Verify STARK receipt, root, scope, action binding, optional hybrid PQ stamp, and consume nullifier."""
        if not isinstance(receipt, bytes) or not receipt:
            raise ZkCreditError("missing STARK receipt")
        if journal.root != self.trusted_root:
            raise ZkCreditError("STARK root does not match trusted epoch tree")
        if (journal.start, journal.lifetime) != (self.tree_start, self.tree_lifetime):
            raise ZkCreditError("STARK tree parameters mismatch")
        if journal.epoch != current_epoch:
            raise ZkCreditError("STARK credit is outside the active epoch")
        if journal.scope not in self.allowed_scopes:
            raise ZkCreditError("unrecognized rationed scope (scope multiplication refused)")
        if journal.action != action_hash(request_bytes):
            raise ZkCreditError("STARK proof is bound to a different request")
        if not self.verify_receipt(self.image_id, receipt, journal):
            raise ZkCreditError("invalid STARK receipt for pinned guest image ID")
        if self.hybrid_pq_public is not None:
            self.hybrid_pq_public.verify(b"cpvpn/zk-hybrid-stamp/v1\0", journal.canonical_bytes(), pq_stamp)
        self.ledger.consume(journal.epoch, journal.scope, journal.nullifier)
        return journal.nullifier

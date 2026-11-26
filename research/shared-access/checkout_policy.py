"""Offline checkout policy for independently verified shielded testnet notes."""

from contextlib import closing
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
import os
from pathlib import Path
import sqlite3


REQUIRED_CONFIRMATIONS = 10
REQUEST_BYTES = 259  # RFC 9578 type 2 request
RESPONSE_BYTES = 256
BATCH_SIZE = 8


class CheckoutError(ValueError):
    """The order could not authorize minting."""


@dataclass(frozen=True)
class Order:
    """A prepaid quote issued over the private checkout channel."""

    id: bytes
    receiver: bytes = field(repr=False)
    price: int
    expires_at: int

    def __post_init__(self):
        if len(self.id) != 16 or len(self.receiver) != 43 or self.price <= 0 or self.expires_at <= 0:
            raise CheckoutError("invalid order")


@dataclass(frozen=True)
class Note:
    """A verified note returned by a trusted watcher adapter.

    The adapter must authenticate the source and validate its chain and the
    decrypted note before constructing this value. This module does no RPC.
    """

    network: str
    pool: str
    txid: bytes
    block_hash: bytes
    height: int
    tip_height: int
    receiver: bytes = field(repr=False)
    amount: int

    def payment(self):
        """Return the fields that two independent watchers must agree on."""
        return (self.network, self.pool, self.txid, self.block_hash, self.height, self.receiver, self.amount)


@dataclass(frozen=True)
class Watcher:
    """Operator identity and proof-validating lookup configured locally."""

    operator: str
    lookup: Callable[[bytes, bytes], Note | None] = field(repr=False)


def confirmed(order, txid, watchers):
    """Require both independent watchers to attest to the same confirmed note."""
    watchers = tuple(watchers)
    if len(watchers) != 2:
        raise CheckoutError("two independent watchers are required")
    first, second = watchers
    if not first.operator or not second.operator or first.operator == second.operator or first.lookup == second.lookup:
        raise CheckoutError("two independent watchers are required")
    if len(txid) != 32:
        raise CheckoutError("invalid transaction identifier")
    try:
        notes = [watcher.lookup(txid, order.receiver) for watcher in watchers]
    except (OSError, ValueError):
        raise CheckoutError("payment confirmation unavailable") from None
    for note in notes:
        if (
            not isinstance(note, Note)
            or (note.network, note.pool) != ("testnet", "orchard")
            or note.txid != txid
            or len(note.block_hash) != 32
            or note.height <= 0
            or note.tip_height - note.height + 1 < REQUIRED_CONFIRMATIONS
            or note.receiver != order.receiver
            or note.amount < order.price
        ):
            raise CheckoutError("shielded testnet payment not confirmed")
    if notes[0].payment() != notes[1].payment():
        raise CheckoutError("watchers disagree about the confirmed payment")


class CheckoutLedger:
    """Atomically persist issuance and return the same responses for an exact retry.

    The mint callback is a local blind-sign operation with no external side
    effects. Nothing returns to a buyer until the database commit succeeds.
    """

    def __init__(self, path: Path, issuer_key_id: bytes):
        if len(issuer_key_id) != 32:
            raise CheckoutError("invalid pinned issuer key identifier")
        self.path = path
        self.request_prefix = b"\x00\x02" + issuer_key_id[-1:]

    def _open(self):
        return sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True, timeout=5)

    def initialize(self):
        """Provision a private ledger without replacing an existing file."""
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(self._open()) as db, db:
            db.execute("CREATE TABLE paid (txid BLOB PRIMARY KEY) WITHOUT ROWID")
            db.execute(
                "CREATE TABLE issued (order_id BLOB PRIMARY KEY, request_digest BLOB NOT NULL, "
                "response BLOB NOT NULL, expires INTEGER NOT NULL) WITHOUT ROWID"
            )

    def issue(self, order, txid, requests, watchers, mint, *, now):
        """Release a fixed-size batch of blind responses for one confirmed payment."""
        requests = tuple(requests)
        if now >= order.expires_at:
            raise CheckoutError("order expired")
        if (
            len(requests) != BATCH_SIZE
            or any(
                not isinstance(r, bytes) or len(r) != REQUEST_BYTES or not r.startswith(self.request_prefix)
                for r in requests
            )
            or len(set(requests)) != BATCH_SIZE
            or len(txid) != 32
        ):
            raise CheckoutError("invalid sponsored-policy credit batch")
        digest = sha256(b"cpvpn/checkout-issue/v1\0" + txid + b"".join(requests)).digest()
        # Read external sources before acquiring the write lock. A disagreement
        # on a retry also stops issuance while a possible reorg is investigated.
        confirmed(order, txid, watchers)
        try:
            with closing(self._open()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                previous = db.execute(
                    "SELECT request_digest, response FROM issued WHERE order_id = ?", (order.id,)
                ).fetchone()
                if previous is not None:
                    if previous[0] != digest:
                        raise CheckoutError("order already used for a different batch")
                    return self._responses(previous[1])
                if db.execute("SELECT 1 FROM paid WHERE txid = ?", (txid,)).fetchone() is not None:
                    raise CheckoutError("transaction already used")
                responses = tuple(mint(requests))
                if len(responses) != BATCH_SIZE or any(
                    not isinstance(response, bytes) or len(response) != RESPONSE_BYTES for response in responses
                ):
                    raise CheckoutError("mint returned an invalid batch")
                db.execute("INSERT INTO paid VALUES (?)", (txid,))
                db.execute(
                    "INSERT INTO issued VALUES (?, ?, ?, ?)", (order.id, digest, b"".join(responses), order.expires_at)
                )
                return responses
        except sqlite3.Error:
            raise CheckoutError("checkout ledger unavailable") from None

    def prune(self, now):
        """Delete expired retry data while retaining the paid transaction denylist."""
        try:
            with closing(self._open()) as db, db:
                db.execute("PRAGMA secure_delete = ON")
                db.execute("DELETE FROM issued WHERE expires <= ?", (now,))
        except sqlite3.Error:
            raise CheckoutError("checkout ledger unavailable") from None

    @staticmethod
    def _responses(data):
        if len(data) != BATCH_SIZE * RESPONSE_BYTES:
            raise CheckoutError("checkout ledger contains an invalid response")
        return tuple(data[start : start + RESPONSE_BYTES] for start in range(0, len(data), RESPONSE_BYTES))

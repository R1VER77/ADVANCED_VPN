"""Synthetic chain observations for the private checkout policy."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from checkout_policy import BATCH_SIZE, CheckoutError, CheckoutLedger, Note, Order, Watcher


class CheckoutTests(unittest.TestCase):
    """Exercise the eligibility and atomic issuance rules without live funds."""

    def setUp(self):
        """Prepare one paid order and a private temporary ledger."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.ledger = CheckoutLedger(Path(directory.name) / "checkout.sqlite", b"i" * 32)
        self.ledger.initialize()
        self.order = Order(b"a" * 16, b"r" * 43, 500, 3600)
        self.note = Note("testnet", "orchard", b"t" * 32, b"b" * 32, 100, 109, self.order.receiver, 500)
        self.requests = [b"\x00\x02i" + bytes([index]) * 256 for index in range(BATCH_SIZE)]
        self.responses = tuple(bytes([index + 1]) * 256 for index in range(BATCH_SIZE))
        self.mint = Mock(return_value=self.responses)

    def issue(self, *, note=None, second=None, requests=None, order=None, now=10):
        """Run issuance with independent test watcher callbacks."""
        if note is None:
            note = self.note
        watchers = (Watcher("first", lambda *_: note), Watcher("second", lambda *_: note if second is None else second))
        return self.ledger.issue(
            order or self.order,
            self.note.txid,
            self.requests if requests is None else requests,
            watchers,
            self.mint,
            now=now,
        )

    def test_disagreement_reorg_and_unconfirmed_notes_cannot_mint(self):
        """Verify that no invalid or inconsistent evidence authorizes a batch."""
        with self.assertRaisesRegex(CheckoutError, "disagree"):
            self.issue(second=replace(self.note, block_hash=b"c" * 32))
        for note in (
            replace(self.note, tip_height=108),
            replace(self.note, amount=499),
            replace(self.note, pool="transparent"),
            replace(self.note, receiver=b"x" * 43),
            replace(self.note, network="mainnet"),
        ):
            with self.assertRaisesRegex(CheckoutError, "not confirmed"):
                self.issue(second=note)
        self.mint.assert_not_called()
        self.assertEqual(self.issue(), self.responses)
        with self.assertRaisesRegex(CheckoutError, "disagree"):
            self.issue(second=replace(self.note, block_hash=b"c" * 32))
        self.mint.assert_called_once()

    def test_retry_is_atomic_and_rejects_payment_reuse(self):
        """Race identical requests and check the paid set after retry data expires."""
        with ThreadPoolExecutor(max_workers=6) as pool:
            self.assertEqual(list(pool.map(lambda _: self.issue(), range(10))), [self.responses] * 10)
        self.mint.assert_called_once()
        with self.assertRaisesRegex(CheckoutError, "different batch"):
            self.issue(requests=list(reversed(self.requests)))
        other = replace(self.order, id=b"x" * 16, expires_at=7200)
        with self.assertRaisesRegex(CheckoutError, "already used"):
            self.issue(order=other)
        self.ledger.prune(now=self.order.expires_at)
        with self.assertRaisesRegex(CheckoutError, "already used"):
            self.issue(order=other, now=self.order.expires_at)

    def test_mint_failure_can_retry_without_spending_the_payment(self):
        """An invalid mint response must leave the order eligible for retry."""
        self.mint.side_effect = [(), self.responses]
        with self.assertRaisesRegex(CheckoutError, "invalid batch"):
            self.issue()
        self.assertEqual(self.issue(), self.responses)

    def test_same_source_wrong_epoch_key_and_expired_order_refused(self):
        """Enforce independent sources, the pinned key and the order window."""
        watchers = (Watcher("same", lambda *_: self.note), Watcher("same", lambda *_: self.note))
        with self.assertRaisesRegex(CheckoutError, "independent"):
            self.ledger.issue(self.order, self.note.txid, self.requests, watchers, self.mint, now=10)
        with self.assertRaisesRegex(CheckoutError, "credit batch"):
            self.issue(requests=[b"\x00\x02x" + item[3:] for item in self.requests])
        with self.assertRaisesRegex(CheckoutError, "expired"):
            self.issue(now=self.order.expires_at)
        self.mint.assert_not_called()

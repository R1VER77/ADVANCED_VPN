#!/usr/bin/env python3
"""Tests for the blind-voucher engine (tools/voucher.py): the full
buy-unblind-redeem flow with real RSA-FDH blind signatures, the
webhook's HMAC authentication and replay protection, tier/epoch
validity, double-spend refusal, scratch-card batches whose printer view
leaks no codes, and the cost-honesty table."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mesh_tokens as mt  # noqa: E402
import voucher as v  # noqa: E402


def settled_webhook(payment_id: str, cents: int) -> bytes:
    return json.dumps(
        {
            "type": "InvoiceSettled",
            "payment_id": payment_id,
            "amount": f"{cents / 100:.2f}",
            "currency": "USD",
        }
    ).encode()


class EndToEndTests(unittest.TestCase):
    def test_buy_unblind_redeem(self):
        mint = v.Mint()
        buyer = v.Buyer()
        v.set_mint_key_for_tests(mint.key.public_key())
        blinded, unblinder = buyer.blinded()
        issued = mint.issue(blinded, "fast")
        voucher = buyer.finish(
            int(issued["blind_signature"], 16),
            unblinder,
            issued["epoch"],
            issued["tier"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            ledger = mt.Ledger(Path(tmp) / "ledger.json")
            result = v.redeem_voucher(voucher, mint.key.public_key(), ledger)
        self.assertTrue(result["ok"])
        self.assertEqual(result["tier"], "fast")
        self.assertEqual(result["rate_class"], "fast")

    def test_payment_to_tier_mapping(self):
        self.assertEqual(v.tier_for_price(500), "standard")
        self.assertEqual(v.tier_for_price(1000), "fast")
        self.assertEqual(v.tier_for_price(2500), "line")
        with self.assertRaises(v.TierError):
            v.tier_for_price(7)


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.mint = v.Mint()

    def _sig(self, body: bytes) -> str:
        import hashlib
        import hmac

        return hmac.new(self.mint.webhook_secret, body, hashlib.sha256).hexdigest()

    def test_settled_webhook_accepted(self):
        body = settled_webhook("pay-1", 1000)
        notice = self.mint.verify_webhook(body, self._sig(body))
        self.assertEqual(notice["type"], "InvoiceSettled")

    def test_wrong_hmac_rejected(self):
        body = settled_webhook("pay-1", 1000)
        with self.assertRaises(v.WebhookAuthError):
            self.mint.verify_webhook(body, "00" * 32)

    def test_tampered_body_rejected(self):
        body = settled_webhook("pay-1", 1000)
        tampered = body.replace(b"10.00", b"25.00")
        with self.assertRaises(v.WebhookAuthError):
            self.mint.verify_webhook(tampered, self._sig(body))

    def test_replay_rejected(self):
        body = settled_webhook("pay-1", 1000)
        self.mint.verify_webhook(body, self._sig(body))
        with self.assertRaises(v.ReplayDetected):
            self.mint.verify_webhook(body, self._sig(body))

    def test_non_settlement_rejected(self):
        body = json.dumps({"type": "InvoiceProcessing", "payment_id": "x"}).encode()
        with self.assertRaises(v.PaymentNotSettled):
            self.mint.verify_webhook(body, self._sig(body))


class RedemptionTests(unittest.TestCase):
    def setUp(self):
        self.mint = v.Mint()
        v.set_mint_key_for_tests(self.mint.key.public_key())
        self.ledger_path = Path(tempfile.mkdtemp()) / "ledger.json"

    def _buy(self, tier="standard"):
        buyer = v.Buyer()
        blinded, unblinder = buyer.blinded()
        issued = self.mint.issue(blinded, tier)
        return buyer.finish(
            int(issued["blind_signature"], 16),
            unblinder,
            issued["epoch"],
            issued["tier"],
        )

    def test_double_spend_refused(self):
        ledger = mt.Ledger(self.ledger_path)
        voucher = self._buy()
        self.assertTrue(v.redeem_voucher(voucher, self.mint.key.public_key(), ledger)["ok"])
        with self.assertRaises(mt.DoubleSpend):
            v.redeem_voucher(voucher, self.mint.key.public_key(), ledger)

    def test_expired_voucher_refused(self):
        ledger = mt.Ledger(self.ledger_path)
        voucher = self._buy()
        voucher["epoch"] -= v.LIVE_EPOCHS + 1
        with self.assertRaises(mt.Expired):
            v.redeem_voucher(voucher, self.mint.key.public_key(), ledger)

    def test_tampered_signature_refused(self):
        ledger = mt.Ledger(self.ledger_path)
        voucher = self._buy()
        bad = (int(voucher["signature"], 16) ^ 1).to_bytes(384, "big").hex()
        voucher["signature"] = bad
        with self.assertRaises(mt.InvalidSignature):
            v.redeem_voucher(voucher, self.mint.key.public_key(), ledger)

    def test_foreign_mint_key_refused(self):
        other = v.Mint()
        ledger = mt.Ledger(self.ledger_path)
        voucher = self._buy()
        # A voucher from another mint fails verification under this
        # relay's published key (the signature cannot verify).
        with self.assertRaises(mt.InvalidSignature):
            v.redeem_voucher(voucher, other.key.public_key(), ledger)

    def test_unknown_tier_refused(self):
        ledger = mt.Ledger(self.ledger_path)
        voucher = self._buy()
        voucher["tier"] = "platinum"
        with self.assertRaises(v.TierError):
            v.redeem_voucher(voucher, self.mint.key.public_key(), ledger)


class UnlinkabilityTests(unittest.TestCase):
    def test_mint_cannot_link_issuance_to_voucher(self):
        """The mint saw the blinded value; the voucher's secret is
        unlinkable to it (the blind RSA property, exercised end to
        end: the serialized voucher contains neither the blinded value
        nor the unblinder)."""
        mint = v.Mint()
        v.set_mint_key_for_tests(mint.key.public_key())
        buyer = v.Buyer()
        blinded, unblinder = buyer.blinded()
        issued = mint.issue(blinded, "line")
        voucher = buyer.finish(
            int(issued["blind_signature"], 16),
            unblinder,
            issued["epoch"],
            issued["tier"],
        )
        blinded_hex = blinded.to_bytes(384, "big").hex()
        self.assertNotIn(blinded_hex, json.dumps(voucher))
        self.assertNotIn(unblinder.to_bytes(384, "big").hex(), json.dumps(voucher))


class ScratchCardTests(unittest.TestCase):
    def test_batch_printer_view_has_no_codes(self):
        mint = v.Mint()
        batch = v.scratch_batch(mint, "standard", 10)
        self.assertEqual(len(batch["cards"]), 10)
        self.assertEqual(len(batch["printer_view"]), 10)
        printer = json.dumps(batch["printer_view"])
        for card in batch["cards"]:
            self.assertNotIn(card["code"], printer)
            self.assertNotIn(card["signature"], printer)
        self.assertIn("digest", batch["printer_view"][0])

    def test_card_redeems_like_a_voucher(self):
        mint = v.Mint()
        batch = v.scratch_batch(mint, "fast", 1)
        card = batch["cards"][0]
        voucher_doc = {
            "schema": v.SCHEMA,
            "epoch": batch["epoch"],
            "tier": batch["tier"],
            "secret": card["code"],
            "signature": card["signature"],
            "issuer": mt.issuer_id(mint.key.public_key()),
        }
        with tempfile.TemporaryDirectory() as tmp:
            ledger = mt.Ledger(Path(tmp) / "l.json")
            result = v.redeem_voucher(voucher_doc, mint.key.public_key(), ledger)
        self.assertEqual(result["tier"], "fast")

    def test_bad_tier_rejected(self):
        mint = v.Mint()
        with self.assertRaises(v.TierError):
            v.scratch_batch(mint, "platinum", 1)


class CostHonestyTests(unittest.TestCase):
    def test_tier_costs_published(self):
        costs = v.refresh_tier_costs()
        self.assertEqual(costs["standard"]["price_usd"], 5)
        self.assertEqual(costs["standard"]["rate"], "standard")
        self.assertGreater(costs["standard"]["cover_cost_gib_month"], 0)
        # The line tier burns strictly more cover than standard.
        self.assertGreater(
            costs["line"]["cover_cost_gib_month"],
            costs["standard"]["cover_cost_gib_month"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

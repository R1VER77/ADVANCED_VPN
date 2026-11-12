#!/usr/bin/env python3
"""Tests for the blind-RSA credit scheme (tools/mesh_tokens.py)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


import mesh_tokens as mt  # noqa: E402


def fresh_key():
    return mt.generate_issuer_key()


class BlindSignatureTests(unittest.TestCase):
    def test_round_trip_verifies(self):
        key = fresh_key()
        token = mt.new_token()
        blinded, r = mt.blind(token, key.public_key())
        sig = mt.unblind(mt.sign_blinded(key, blinded), r, key.public_key())
        self.assertTrue(mt.verify(token, sig, key.public_key()))

    def test_blinding_hides_the_token_hash(self):
        key = fresh_key()
        token = mt.new_token()
        blinded, _ = mt.blind(token, key.public_key())
        n = key.public_key().public_numbers().n
        self.assertNotEqual(blinded, mt.fdh(token, n))

    def test_wrong_token_does_not_verify(self):
        key = fresh_key()
        token = mt.new_token()
        blinded, r = mt.blind(token, key.public_key())
        sig = mt.unblind(mt.sign_blinded(key, blinded), r, key.public_key())
        self.assertFalse(mt.verify(mt.new_token(), sig, key.public_key()))

    def test_wrong_key_does_not_verify(self):
        key, other = fresh_key(), fresh_key()
        token = mt.new_token()
        blinded, r = mt.blind(token, key.public_key())
        sig = mt.unblind(mt.sign_blinded(key, blinded), r, key.public_key())
        self.assertFalse(mt.verify(token, sig, other.public_key()))

    def test_unblinded_signature_is_unlinkable_to_blinded_value(self):
        # The issuer's view is (blinded, blind_signature); the spender's view is
        # (token, signature). No shared value may appear in both views.
        key = fresh_key()
        token = mt.new_token()
        blinded, r = mt.blind(token, key.public_key())
        blind_sig = mt.sign_blinded(key, blinded)
        sig = mt.unblind(blind_sig, r, key.public_key())
        self.assertNotEqual(blind_sig, sig)
        self.assertNotEqual(blinded, sig)

    def test_issuer_cannot_sign_without_the_private_key(self):
        pub = fresh_key().public_key()
        with self.assertRaises(ValueError):
            mt.sign_blinded(pub, 12345)

    def test_token_length_is_enforced(self):
        with self.assertRaises(ValueError):
            mt.fdh(b"short", fresh_key().public_key().public_numbers().n)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.json"
        self.key = fresh_key()

    def tearDown(self):
        self.tmp.cleanup()

    def test_redeem_records_the_digest_not_the_token(self):
        grant, spend = mt.issue_credit(self.key)
        mt.Ledger(self.path).redeem(spend, self.key.public_key())
        doc = self.path.read_text()
        self.assertIn(mt.token_digest(bytes.fromhex(grant["token"])), doc)
        self.assertNotIn(grant["token"], doc)

    def test_double_spend_is_rejected(self):
        _, spend = mt.issue_credit(self.key)
        ledger = mt.Ledger(self.path)
        ledger.redeem(spend, self.key.public_key())
        with self.assertRaises(mt.DoubleSpend):
            ledger.redeem(spend, self.key.public_key())

    def test_double_spend_is_rejected_across_ledger_reloads(self):
        _, spend = mt.issue_credit(self.key)
        mt.Ledger(self.path).redeem(spend, self.key.public_key())
        with self.assertRaises(mt.DoubleSpend):
            mt.Ledger(self.path).redeem(spend, self.key.public_key())

    def test_invalid_signature_is_rejected(self):
        _, spend = mt.issue_credit(self.key)
        spend["redemption"] = (int(spend["redemption"], 16) ^ 1).to_bytes(mt.KEY_BITS // 8, "big").hex()
        with self.assertRaises(mt.InvalidSignature):
            mt.Ledger(self.path).redeem(spend, self.key.public_key())

    def test_wrong_issuer_key_is_rejected(self):
        _, spend = mt.issue_credit(self.key)
        with self.assertRaises(mt.UntrustedIssuer):
            mt.Ledger(self.path).redeem(spend, fresh_key().public_key())

    def test_distinct_tokens_are_independent(self):
        ledger = mt.Ledger(self.path)
        for _ in range(3):
            _, spend = mt.issue_credit(self.key)
            self.assertTrue(ledger.redeem(spend, self.key.public_key())["ok"])

    def test_ledger_file_is_private(self):
        _, spend = mt.issue_credit(self.key)
        mt.Ledger(self.path).redeem(spend, self.key.public_key())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


class IssuerIdTests(unittest.TestCase):
    def test_issuer_id_shape(self):
        key = fresh_key()
        iid = mt.issuer_id(key.public_key())
        self.assertTrue(iid.startswith("!"))
        self.assertEqual(len(iid), 9)

    def test_issuer_id_is_stable(self):
        key = fresh_key()
        self.assertEqual(mt.issuer_id(key.public_key()), mt.issuer_id(key.public_key()))


if __name__ == "__main__":
    unittest.main()

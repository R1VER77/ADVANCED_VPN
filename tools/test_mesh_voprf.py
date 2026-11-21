#!/usr/bin/env python3
"""Tests for the private-group VOPRF credits (tools/mesh_voprf.py).

The earn/spend round trip, the unlinkability property that motivates the
scheme (the issuing node cannot correlate its issuance with the later
redemption), double-spend refusal, binding/replay refusal, expiry, wrong-
group refusal and tamper refusal — plus a deterministic key check against
the RFC 9497 DeriveKeyPair the group keys are built on.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mesh_voprf as mv  # noqa: E402
import voprf  # noqa: E402


def fresh_group():
    seed = bytes(range(32))
    node = mv.GroupNode(seed)
    return seed, node.public_key()


def earn(node, member, token_input=None):
    wire, secret = member.request(token_input)
    response = node.issue(wire)
    return member.finish(secret, response)


class RoundTripTests(unittest.TestCase):
    def test_earn_spend_round_trip(self):
        seed, pk = fresh_group()
        node = mv.GroupNode(seed)
        member = mv.Member(pk)
        credit = earn(node, member)
        spend = member.spend(credit, "chain-42:!member")
        result = node.redeem(spend, "chain-42:!member")
        self.assertTrue(result["ok"])
        self.assertEqual(result["issuer"], credit["issuer"])

    def test_earn_request_carries_only_the_blinded_element(self):
        _, pk = fresh_group()
        member = mv.Member(pk)
        wire, _ = member.request()
        self.assertEqual(set(wire), {"schema", "blinded"})

    def test_same_input_same_token_distinct_inputs_distinct_tokens(self):
        # The VOPRF evaluation is deterministic in the input — that is
        # what lets a node re-derive the token at redemption. Distinct
        # members using the same input therefore hold the same credit
        # (a double-spend by construction), which is why inputs are
        # drawn fresh 256-bit randoms per credit in `request`.
        seed, pk = fresh_group()
        node = mv.GroupNode(seed)
        token_input = bytes([0x5A] * 32)
        credit1 = earn(node, mv.Member(pk), token_input)
        credit2 = earn(node, mv.Member(pk), token_input)
        self.assertEqual(credit1["token"], credit2["token"])
        credit3 = earn(node, mv.Member(pk))
        credit4 = earn(node, mv.Member(pk))
        self.assertNotEqual(credit3["token"], credit4["token"])


class UnlinkabilityTests(unittest.TestCase):
    """The property the HMAC scheme lacks: the issuer that answered an
    earn request cannot tell which redemption came from that issuance."""

    def test_issuance_view_differs_from_redemption_view(self):
        seed, pk = fresh_group()
        node = mv.GroupNode(seed)
        member = mv.Member(pk)
        wire, secret = member.request()
        blinded_seen_by_node = wire["blinded"]
        response = node.issue(wire)
        credit = member.finish(secret, response)
        # The redemption reveals the input and the HMAC, never the
        # blinded element or the blind; the node's issuance record
        # (blinded_seen_by_node) does not appear in the spend.
        spend = member.spend(credit, "chain-1:!x")
        self.assertNotIn("blinded", spend)
        self.assertNotIn("blind", spend)
        self.assertNotIn("token", spend)
        serialized = str(spend)
        self.assertNotIn(blinded_seen_by_node, serialized)
        self.assertNotIn(credit["token"], serialized)

    def test_two_issuances_indistinguishable_after_redemption(self):
        seed, pk = fresh_group()
        node = mv.GroupNode(seed)
        records = []
        credits = []
        for _ in range(2):
            wire, secret = mv.Member(pk).request()
            records.append(wire["blinded"])
            credits.append(mv.Member(pk).finish(secret, node.issue(wire)))
        spends = [mv.Member(pk).spend(c, f"chain-{i}") for i, c in enumerate(credits)]
        # Knowing both issuance records and both spends, nothing matches:
        for record in records:
            for spend in spends:
                self.assertNotIn(record, str(spend))


class FailureTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.pk = fresh_group()
        self.node = mv.GroupNode(self.seed)
        self.member = mv.Member(self.pk)

    def test_double_spend_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.node = mv.GroupNode(self.seed, ledger_path=Path(tmp) / "ledger.json")
            credit = earn(self.node, self.member)
            spend = self.member.spend(credit, "chain-1")
            self.assertTrue(self.node.redeem(spend, "chain-1")["ok"])
            with self.assertRaises(mv.DoubleSpend):
                self.node.redeem(spend, "chain-1")

    def test_replay_on_other_binding_refused(self):
        credit = earn(self.node, self.member)
        spend = self.member.spend(credit, "chain-1")
        with self.assertRaises(mv.InvalidAuthenticator):
            self.node.redeem(spend, "chain-2")

    def test_tampered_authenticator_refused(self):
        credit = earn(self.node, self.member)
        spend = self.member.spend(credit, "chain-1")
        bad = (int(spend["redemption"], 16) ^ 1).to_bytes(32, "big").hex()
        spend["redemption"] = bad
        with self.assertRaises(mv.InvalidAuthenticator):
            self.node.redeem(spend, "chain-1")

    def test_expired_epoch_refused(self):
        credit = earn(
            self.node,
            self.member,
        )  # epoch = current
        spend = self.member.spend(credit, "chain-1")
        far_future = (credit["epoch"] + mv.LIVE_EPOCHS + 1) * mv.EPOCH_SECONDS + 5
        with self.assertRaises(mv.Expired):
            self.node.redeem(spend, "chain-1", now=far_future)

    def test_wrong_group_refused(self):
        other_seed = bytes(range(1, 33))
        other_node = mv.GroupNode(other_seed)
        credit = earn(self.node, self.member)
        spend = self.member.spend(credit, "chain-1")
        with self.assertRaises(mv.UntrustedGroup):
            other_node.redeem(spend, "chain-1")

    def test_tampered_evaluation_refused_at_finish(self):
        wire, secret = self.member.request()
        response = self.node.issue(wire)
        response["evaluated"] = (int(response["evaluated"], 16) ^ 1).to_bytes(32, "big").hex()
        with self.assertRaises(ValueError):
            self.member.finish(secret, response)


class KeyTests(unittest.TestCase):
    def test_group_keys_deterministic_and_epoch_distinct(self):
        seed = bytes(range(32))
        sk1, pk1 = mv.group_epoch_key(seed, 7)
        sk1b, pk1b = mv.group_epoch_key(seed, 7)
        sk2, pk2 = mv.group_epoch_key(seed, 8)
        self.assertEqual(pk1, pk1b)
        self.assertEqual(sk1, sk1b)
        self.assertNotEqual(pk1, pk2)

    def test_group_key_is_rfc9497_derive_key_pair(self):
        seed = bytes(range(32))
        sk, _ = mv.group_epoch_key(seed, 5)
        expected, _ = voprf.derive_key_pair(seed, mv.DOMAIN + b"|key|5", voprf.MODE_VOPRF)
        self.assertEqual(sk, expected)

    def test_issuer_id_shape(self):
        seed, pk = fresh_group()
        self.assertRegex(mv.issuer_id(pk), r"^![0-9a-f]{8}$")


if __name__ == "__main__":
    unittest.main(verbosity=2)

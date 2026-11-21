"""Tests for tools/dcnet_validation.py: the ROADMAP section 6 row
"complete DLEQ batches, authenticated event effects, jamming/fallback
dependencies", executed against the real ristretto255 VOPRF
(tools/voprf.py) and the byte-exact DC-net round core
(tools/dcnet_reference.py).

Everything here is real crypto or the real round math: no mocks, no
skips. The one substitution the repo already documents is the pad books:
in-person Nitrokey bytes are stood in for by the public test books, the
same convention every other DC-net vector in this repo uses.
"""

import sys
import secrets
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dcnet_reference as dcnet  # noqa: E402
import dcnet_validation as dv  # noqa: E402


class CompleteDleqBatches(unittest.TestCase):
    """The whitepaper corrections, executable over the real implementation."""

    def setUp(self):
        self.server, self.client = dv.epoch_server(b"test-seed-batch", 0)

    def test_a_complete_batch_verifies_and_finalizes(self):
        batch = dv.issue_batch(self.server, self.client, [b"voucher-%d" % i for i in range(8)])
        outs = dv.redeem_batch(self.client, batch)
        self.assertEqual(len(outs), 8)
        self.assertEqual(len(set(outs)), 8, "distinct inputs give distinct PRF outputs")

    def test_a_proof_from_another_batch_is_refused(self):
        a = dv.issue_batch(self.server, self.client, [b"first-%d" % i for i in range(4)])
        b = dv.issue_batch(self.server, self.client, [b"second-%d" % i for i in range(4)])
        self.assertFalse(dv.verify_batch(self.client, a["blinded"], a["evaluated"], b["proof"]))

    def test_a_subset_of_a_verified_batch_is_refused(self):
        a = dv.issue_batch(self.server, self.client, [b"subset-%d" % i for i in range(4)])
        self.assertTrue(
            dv.verify_batch(self.client, a["blinded"], a["evaluated"], a["proof"]), "the complete batch verifies"
        )
        self.assertFalse(
            dv.verify_batch(self.client, a["blinded"][:2], a["evaluated"][:2], a["proof"]),
            "the proof binds every element; a subset is a different batch",
        )

    def test_a_verified_proof_cannot_be_amortized_to_more_elements(self):
        a = dv.issue_batch(self.server, self.client, [b"amort-%d" % i for i in range(4)])
        more = dv.issue_batch(self.server, self.client, [b"more-%d" % i for i in range(2)])
        self.assertFalse(
            dv.verify_batch(
                self.client, a["blinded"] + more["blinded"], a["evaluated"] + more["evaluated"], a["proof"]
            ),
            "amortization cannot extend a proof to evaluations it never covered",
        )

    def test_cached_proofs_die_with_the_issuer_epoch(self):
        a = dv.issue_batch(self.server, self.client, [b"epoch-%d" % i for i in range(4)])
        server2, _ = dv.epoch_server(b"test-seed-batch", 1)  # the key rotates
        evaluated2, proof2 = server2.blind_evaluate_batch(a["blinded"])
        self.assertFalse(
            dv.verify_batch(self.client, a["blinded"], evaluated2, a["proof"]),
            "the old proof does not cover the new key's evaluations",
        )
        self.assertFalse(
            dv.verify_batch(self.client, a["blinded"], evaluated2, proof2),
            "the new proof does not verify under the old public key either",
        )

    def test_every_negative_check_holds(self):
        checks = dv.batch_negative_checks()
        self.assertEqual(
            sorted(checks),
            [
                "amortization_to_more_elements_refused",
                "cached_proof_refused_across_epochs",
                "cross_batch_replay_refused",
                "subset_of_batch_refused",
            ],
        )
        for name, holds in checks.items():
            self.assertTrue(holds, name)

    def test_the_benchmark_measures_the_real_protocol(self):
        bench = dv.benchmark_batch((1, 8, 64))
        self.assertEqual(sorted(int(k) for k in bench["sizes"]), [1, 8, 64])
        self.assertLess(
            bench["sizes"][str(8)]["total_ms"],
            bench["sizes"][str(64)]["total_ms"],
            "verification work grows with the batch, as the correction demands",
        )
        for row in bench["sizes"].values():
            self.assertGreater(row["per_element_us"], 0)


class AuthenticatedEventEffects(unittest.TestCase):
    """A valid public tag is a check, not authority (DCNET_CONTROL_DESIGN section 4)."""

    def setUp(self):
        n = 4
        self.n = n
        self.pads = dv.cell_pads(n)
        self.rnd = dcnet.FIRST_ROUND
        self.known = dcnet.encode_event(2, 111, b"chain-setup-commit")
        self.replacement = dcnet.encode_event(2, 112, b"evil-replacement")

    def bodies(self, events_by_member):
        bodies = [self.pads[i].body(1, self.rnd) for i in range(self.n)]
        for member, event in events_by_member.items():
            bodies[member] = dcnet.xor(bodies[member], event)
        return bodies

    def test_the_substitution_attack_passes_the_public_check(self):
        # The documented attack, run as a full round: member 1 sends the real
        # event; member 3, who knows it, folds in the delta to the replacement.
        bodies = self.bodies({1: self.known, 3: dv.substitute_encoding(self.known, self.replacement)})
        decoded = dv.round_decode(bodies)
        self.assertEqual(
            decoded,
            ("event", 2, 112, b"evil-replacement".ljust(46, b"\x00")),
            "the round decodes the replacement with a valid public tag",
        )

    def test_the_substituted_event_is_refused_at_the_effect_gate(self):
        gate = dv.EffectGate([dv.event_digest(self.known)])  # only the real one authorized
        bodies = self.bodies({1: self.known, 3: dv.substitute_encoding(self.known, self.replacement)})
        decoded = dv.round_decode(bodies)
        self.assertEqual(gate.apply(decoded), "refused")
        self.assertEqual(len(gate.applied), 0)
        self.assertEqual(gate.refused[0]["kind"], 2)

    def test_an_authorized_event_applies_its_effect(self):
        gate = dv.EffectGate([dv.event_digest(self.known)])
        decoded = dv.round_decode(self.bodies({1: self.known}))
        self.assertEqual(gate.apply(decoded), "applied")
        self.assertEqual(gate.applied[0]["payload"], b"chain-setup-commit".ljust(46, b"\x00"))

    def test_an_unauthorized_event_decodes_but_never_applies(self):
        # Even with no attacker: a member sends a real, valid event whose
        # digest was never authorized out-of-band. The decode succeeds; the
        # effect does not fire. That is the gate's whole point.
        gate = dv.EffectGate([])
        decoded = dv.round_decode(self.bodies({2: self.known}))
        self.assertEqual(decoded[0], "event")
        self.assertEqual(gate.apply(decoded), "refused")

    def test_identical_events_cancel_to_null(self):
        # Two members submit the byte-identical encoding: the group decode
        # cancels to null — indistinguishable from no event, and benign.
        decoded = dv.round_decode(self.bodies({0: self.known, 2: self.known}))
        self.assertEqual(decoded, "null")
        self.assertEqual(dv.EffectGate().apply(decoded), "null")

    def test_a_collision_of_two_events_is_lost_not_decoded(self):
        other = dcnet.encode_event(2, 999, b"other-event")
        decoded = dv.round_decode(self.bodies({1: self.known, 3: other}))
        self.assertEqual(decoded, "garbled", "two different events garble; neither fires, both retransmit later")
        self.assertEqual(dv.EffectGate([dv.event_digest(self.known)]).apply(decoded), "garbled")


class JammingAndFallback(unittest.TestCase):
    """Accept-DoS with its fallbacks, fault-tested at the dependency level."""

    def setUp(self):
        n = 4
        self.n = n
        self.pads = dv.cell_pads(n)
        self.rnd = dcnet.FIRST_ROUND
        self.event = dcnet.encode_event(1, 7, b"tofu-reverify")
        self.lane = dv.FallbackLane(secrets.token_bytes(32), expiry_round=self.rnd + 10, members=range(n))

    def round_(self, sender=1, jammer=None):
        bodies = [self.pads[i].body(1, self.rnd) for i in range(self.n)]
        bodies[sender] = dcnet.xor(bodies[sender], self.event)
        if jammer is not None:
            bodies[jammer] = secrets.token_bytes(dcnet.BODY_LEN)
        return dv.round_decode(bodies)

    def test_a_jammed_round_is_garbled_detected_and_attributed_to_no_one(self):
        verdict = dv.JamVerdict(self.round_(jammer=2) == "garbled")
        self.assertTrue(verdict.detected)
        self.assertIsNone(verdict.attributed, "the no-tracing policy: detection without attribution")

    def test_the_jammed_rounds_event_rides_the_mix_lane_fallback(self):
        entry = self.lane.send(1, self.event, self.rnd)
        self.assertIn("tag", entry)
        self.assertEqual(len(self.lane.delivered), 1)
        self.assertEqual(
            self.lane.delivered[0]["event"], self.event, "the stronger DC-net guarantee is lost, delivery is not"
        )

    def test_an_expired_fallback_key_fails_closed_and_queues(self):
        late = self.rnd + 10  # at expiry the epoch key is dead
        with self.assertRaises(dv.FallbackExpired):
            self.lane.send(1, self.event, late)
        self.assertEqual(self.lane.delivered, [], "nothing silently delivered")
        self.assertEqual(self.lane.queues[1], [(late, self.event)], "the event is explicitly owed, not dropped")

    def test_renewal_delivers_the_queued_events(self):
        late = self.rnd + 10
        with self.assertRaises(dv.FallbackExpired):
            self.lane.send(1, self.event, late)
        self.lane.renew(secrets.token_bytes(32), expiry_round=late + 10)
        self.assertEqual([e["event"] for e in self.lane.delivered], [self.event])
        self.assertEqual(self.lane.queues[1], [])

    def test_revocation_refuses_only_the_revoked_member(self):
        self.lane.revoke(2)
        with self.assertRaises(dv.MemberRevoked):
            self.lane.send(2, self.event, self.rnd)
        self.lane.send(3, self.event, self.rnd)  # everyone else is unaffected
        self.assertEqual([e["member"] for e in self.lane.delivered], [3])

    def test_fallback_expiry_leaves_bulk_traffic_untouched(self):
        bulk = dv.BulkPath()
        bulk.flow(1_000_000)
        with self.assertRaises(dv.FallbackExpired):
            self.lane.send(1, self.event, self.rnd + 10)
        self.assertEqual(
            bulk.flow(1_000_000), 2_000_000, "the data plane never depended on the control plane's fallback key"
        )


class FullValidationGate(unittest.TestCase):
    """The one-pass evidence run: every boolean must hold."""

    def test_every_gate_in_full_validation_passes(self):
        result = dv.full_validation()
        for name, value in result["batch"].items():
            self.assertTrue(value, "batch: " + name)
        for name, value in result["events"].items():
            self.assertTrue(value, "events: " + name)
        for name in ("honest_round_decodes", "jammed_round_is_garbled", "detected", "fallback_delivered"):
            self.assertTrue(result["jamming"][name], "jamming: " + name)
        self.assertIsNone(result["jamming"]["attributed"])
        self.assertIn("64", result["benchmark"]["sizes"])


if __name__ == "__main__":
    unittest.main()

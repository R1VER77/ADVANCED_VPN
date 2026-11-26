"""Guard the timing holdout against ambiguous and split-crossing ground truth."""

import unittest

import gpa
from mix_holdout import align, margin_checks, score_phase, timing_sensitivity
from mix_qualification import OBSERVERS, qualify


class MixHoldoutTests(unittest.TestCase):
    def test_time_blocks_preserve_empty_windows_and_fractional_ties(self):
        arrivals = [(5.0, 0), (6.0, 0), (9.9, 1)]
        scores = [([0, 1], 0, 1.0), ([0], 0, 0.0), ([1], 1, 0.0)]
        result = timing_sensitivity(arrivals, scores, start=5, stop=10, clients=2, permutations=20)
        self.assertEqual([block["events"] for block in result["time_blocks"]], [1, 1, 0, 0, 1])
        self.assertEqual([block["accuracy"] for block in result["time_blocks"]], [0.5, 1.0, None, None, 1.0])
        self.assertLess(result["identity_permutation_exceedance"], 1.0)

    def test_repeated_dns_does_not_vote_twice_and_overlapping_requests_are_ambiguous(self):
        rows = [dict(site="lab.invalid", client=0, sent=1, done=3), dict(site="lab.invalid", client=1, sent=2, done=4)]
        lookups = [(1.1, "lab.invalid"), (1.2, "lab.invalid"), (2.1, "lab.invalid"), (3.1, "lab.invalid")]
        self.assertEqual(align(rows, lookups), ([(1.1, 0, 1), (3.1, 1, 2)], 1))

    def test_request_crossing_the_split_is_in_neither_set(self):
        rows = [
            dict(site="one.invalid", client=0, sent=1.0, done=2),
            dict(site="two.invalid", client=1, sent=4.9, done=5.3),
            dict(site="two.invalid", client=1, sent=6.0, done=7),
        ]
        capture = [
            "c 0 1.0 8888 100",
            "d 1.1 one.invalid",
            "c 1 4.9 8888 100",
            "d 5.1 two.invalid",
            "c 1 6.0 8888 100",
            "d 6.1 two.invalid",
            "c 2 6.05 8888 100",
        ]
        with self.assertRaisesRegex(ValueError, "undeclared client 2"):
            score_phase("baseline", rows, capture, start=0, stop=10, clients=2)
        result = score_phase("baseline", rows, capture, start=0, stop=10, clients=2, cover_clients=1)
        self.assertEqual(
            (result["training_arrivals"], result["split_crossing_arrivals"], result["arrivals"]), (1, 1, 1)
        )
        self.assertEqual(result["chance"], 0.5)

    def test_margin_rejects_a_hot_block_and_identifiable_cover(self):
        paper = dict(
            profile="timing-margin",
            clients=20,
            clients_ready=20,
            cover_clients=0,
            workload_seed=5,
            lane="katzenpost",
            fetch_plugin="tools/kp_pq_fetch.py (PQ-only)",
            pki_scheme="Ed25519 Sphincs+",
            sphinx={"PacketLength": "22458"},
            katzenpost_parameters={"Mu": 0.01, "LambdaP": 0.001, "LambdaL": 0.0005},
        )
        mix = dict(
            chance=0.05,
            top1_accuracy=0.06,
            prior_top1_accuracy=0.05,
            arrivals=300,
            request_count=600,
            successful_requests=575,
            heldout_requests=302,
            heldout_senders=20,
            active_senders_per_block=[20] * 5,
            timing_sensitivity={"time_blocks": [dict(accuracy=0.06, events=60) for _ in range(5)]},
            prior_timing_sensitivity={"time_blocks": [dict(accuracy=0.05, events=60) for _ in range(5)]},
        )
        baseline = dict(top1_accuracy=0.99, arrivals=100, request_count=200, successful_requests=195)
        self.assertTrue(all(margin_checks(paper, mix, baseline).values()))
        mix["prior_timing_sensitivity"]["time_blocks"][0]["accuracy"] = 0.09
        self.assertFalse(margin_checks(paper, mix, baseline)["worst_window_margin"])
        paper["cover_clients"] = 10
        self.assertFalse(margin_checks(paper, mix, baseline)["fixed_profile"])
        mix["chance"] = 0.1
        self.assertFalse(margin_checks(paper, mix, baseline)["overall_margin"])

    def test_combined_observer_uses_the_training_prior_when_timing_ties(self):
        sends = {0: [1.0], 1: [1.0]}
        model = gpa.DelayModel([0.25])
        self.assertEqual(gpa.attack(sends, [(1.25, 1)], model)[0][0], [0, 1])
        self.assertEqual(gpa.attack(sends, [(1.25, 1)], model, prior={0: 1, 1: 4})[0][0], [1])

    @staticmethod
    def trials():
        return [
            dict(
                region=region,
                report=dict(
                    capture_sha256=str(day),
                    timing_margin_trial=dict(seed=day, started=f"2026-11-{day:02}T12:00:00+00:00", passed=True),
                    mix=dict(
                        request_count=720,
                        arrivals=360,
                        **{
                            observer: {"time_blocks": [dict(top1_hits=4, events=72) for _ in range(5)]}
                            for observer in OBSERVERS
                        },
                    ),
                ),
            )
            for day, region in enumerate(("us-central1", "europe-west3", "asia-southeast1"), start=1)
        ]

    def test_qualification_requires_replication_and_every_observer_passes(self):
        trials = self.trials()
        self.assertTrue(qualify(trials)["passed"])
        self.assertFalse(qualify(trials[:1])["passed"])
        blocks = trials[0]["report"]["mix"]["combined_timing_sensitivity"]["time_blocks"]
        blocks[0]["top1_hits"] = 7
        failed = qualify(trials)
        self.assertTrue(failed["observers"]["timing_sensitivity"]["passed"])
        self.assertFalse(failed["passed"])

    def test_duplicate_capture_cannot_count_as_independent_evidence(self):
        trial = self.trials()[0]
        with self.assertRaisesRegex(ValueError, "duplicate capture"):
            qualify([trial, trial])

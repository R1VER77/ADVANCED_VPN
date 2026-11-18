"""Regression cases for fresh controls, failed captures and held-out filter leakage."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import wf_replication as replication

HAVE = all(importlib.util.find_spec(name) is not None for name in ("numpy", "sklearn"))


class Metadata(unittest.TestCase):
    def test_a_strong_classifier_or_unobserved_protection_cannot_pass_local_acceptance(self):
        def variant(control=False):
            view = dict(
                accuracy=0.95 if control else 0.05,
                ci95_round_bootstrap=[0.9, 1.0] if control else [0.03, 0.08],
                p_holm_all_nine_primary_views=0.001 if control else 0.9,
            )
            return dict(
                chance=0.05,
                excluded=[],
                sources=[dict(capture=dict(unexpected_outgoing=0))],
                window_evidence=[
                    dict(protection_observations=dict(all_samples_protected=not control, control_samples_valid=control))
                ],
                views=dict(both=dict(primary=view)),
            )

        variants = {name: variant(name == "undefended") for name in replication.VARIANTS}
        paired = {name: dict(success_difference_two_way_cluster_ci95=[-0.02, 0.01]) for name in ["relay30", "relay5"]}
        self.assertEqual(replication.local_acceptance(variants, paired)["status"], "passed_local_only")
        variants["relay5"]["views"]["both"]["primary"]["ci95_round_bootstrap"] = [0.2, 0.4]
        self.assertEqual(replication.local_acceptance(variants, paired)["status"], "failed")
        variants["relay5"] = variant()
        variants["relay30"]["window_evidence"][0]["protection_observations"]["all_samples_protected"] = False
        self.assertEqual(replication.local_acceptance(variants, paired)["status"], "failed")

    def test_frozen_analysis_and_actual_variant_order_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = [
                dict(round=i, seed=seed, variant=variant)
                for i, (seed, order) in enumerate(zip(replication.ROUND_SEEDS, replication.ORDERS, strict=True), 1)
                for variant in order
            ]
            names = ("wf_replication.py", "wf_ab.py", "wf_deep.py", "wf_attack.py", "wf_validity.py", "wf_protocol.py")
            manifest = dict(
                schedule=expected, capture_cpus="4", files={"frozen/tools/" + name: "hash" for name in names}
            )
            run = dict(
                status="complete",
                manifest_sha256="hash",
                arms=[
                    dict(arm, status="complete", exit_code=0, attempts=40, started=2 * i + 1, stopped=2 * i + 2)
                    for i, arm in enumerate(expected)
                ],
            )
            (root / "manifest.json").write_text(json.dumps(manifest))
            (root / "RUN.json").write_text(json.dumps(run))
            for arm in expected:
                (root / f"r{arm['round']}-{arm['variant']}.host.jsonl").write_text(
                    json.dumps(dict(power=dict(on_mains=True), concurrent_build_or_inference=[])) + "\n"
                )
            with mock.patch.object(replication.wf_ab, "sha256", return_value="hash"):
                replication.validate_protocol(root, {})
                first = root / "r1-relay30.host.jsonl"
                saved = first.read_text()
                first.write_text(json.dumps(dict(power=dict(on_mains=False), concurrent_build_or_inference=[])) + "\n")
                with self.assertRaisesRegex(ValueError, "power"):
                    replication.validate_protocol(root, {})
                first.write_text(saved)
                run["arms"][0], run["arms"][1] = run["arms"][1], run["arms"][0]
                (root / "RUN.json").write_text(json.dumps(run))
                with self.assertRaisesRegex(ValueError, "actual arm order"):
                    replication.validate_protocol(root, {})

    def test_a_positive_control_with_an_active_clock_is_refused(self):
        replication.validate_settings(dict(config="undefended", wire_clock_pps=None), "undefended")
        with self.assertRaisesRegex(ValueError, "positive control"):
            replication.validate_settings(dict(config="undefended", wire_clock_pps="4000"), "undefended")
        good = dict(config="fast", wire_clock_pps="4000", wire_clock_downstream=True, wire_clock_relay_ms="30")
        replication.validate_settings(good, "relay30")
        for wrong in (dict(good, config="standard"), dict(good, wire_clock_downstream=False)):
            with self.assertRaisesRegex(ValueError, "defended arm"):
                replication.validate_settings(wrong, "relay30")

    def test_held_out_counts_cannot_poison_the_training_reference(self):
        rows = [dict(site="s", status="ok", resources=n) for n in [40, 40, 1, 100000]]
        train, test, refs = replication.training_filter(rows, [0, 1], [2, 3])
        self.assertEqual((train, test, refs), ([0, 1], [3], {"s": 40}))
        rows[3]["resources"] = 1
        self.assertEqual(replication.training_filter(rows, [0, 1], [2, 3]), ([0, 1], [], {"s": 40}))

    def test_failed_attempts_with_no_browser_time_stay_in_cost(self):
        result = replication.costs([dict(status="browser_failed"), dict(status="TimeoutException")])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["success"], 0)
        self.assertIsNone(result["successful_load_seconds_median"])

    def test_round_seed_and_order_mismatches_are_refused(self):
        rows = [dict(round=i, site="s", label=0) for i in [1, 2]]
        sources = [dict(round=i, settings=dict(load_order_seed=i)) for i in [1, 2]]
        replication.validate_matching([(rows, sources), (rows, sources)])
        with self.assertRaisesRegex(ValueError, "recorded seed"):
            replication.validate_matching(
                [(rows, sources), (rows, [dict(round=i, settings=dict(load_order_seed=9)) for i in [1, 2]])]
            )
        with self.assertRaisesRegex(ValueError, "distinct"):
            replication.validate_matching([(rows, [dict(round=i, settings=dict(load_order_seed=9)) for i in [1, 2]])])


@unittest.skipUnless(HAVE, "needs optional numpy and scikit-learn")
class CaptureAndScores(unittest.TestCase):
    def test_shared_round_failures_widen_control_relative_availability_uncertainty(self):
        control = [
            dict(site=site, round=round_id, status="ok", start=0, loaded=1)
            for round_id in (1, 2)
            for site in ("a", "b")
        ]
        defended = [dict(row, status="TimeoutException" if row["round"] == 1 else "ok", loaded=2) for row in control]
        result = replication.paired_outcomes(control, defended)
        self.assertEqual(result["success_difference"], -0.5)
        self.assertEqual(result["success_difference_site_cluster_ci95"], [-0.5, -0.5])
        self.assertEqual(result["success_difference_two_way_cluster_ci95"], [-1.0, 0.0])
        self.assertEqual(result["paired_success_latency_difference_median"], 1)

    def test_silent_window_with_recorder_evidence_stays_in_the_primary_dataset(self):
        import numpy as np
        import wf_deep

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "r1-undefended/w0"
            worker.mkdir(parents=True)
            (worker / "settings.json").write_text(json.dumps(dict(config="undefended", wire_clock_pps=None)))
            (worker / "loads.jsonl").write_text(
                json.dumps(dict(label=0, site="s", status="TimeoutException", start=10)) + "\n"
            )
            np.empty(0, wf_deep.RECORD).tofile(worker / "packets.bin")
            (worker / "capture.json").write_text(
                json.dumps(
                    dict(
                        schema=1,
                        timestamp_source="kernel_time64",
                        clean_stop=True,
                        drops=0,
                        malformed=0,
                        unexpected_outgoing=0,
                    )
                )
            )
            records = [dict(time=9 + n / 2, monotonic=20 + n / 2, drops=0, protection="control") for n in range(29)]
            for name in ("capture-heartbeats.jsonl", "protection.jsonl"):
                (worker / name).write_text("".join(json.dumps(row) + "\n" for row in records))
            features, labels, _, kept, _, excluded, _ = replication.load(root, "undefended")
            self.assertEqual(labels.tolist(), [0])
            self.assertFalse(features["both"].any())
            self.assertEqual(excluded, [])
            self.assertTrue(kept[0]["capture_validity"]["valid"])

    def test_complete_failed_load_and_empty_direction_are_retained_without_fake_packets(self):
        import numpy as np
        import wf_deep

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "r1-undefended/w0"
            worker.mkdir(parents=True)
            (worker / "settings.json").write_text(json.dumps(dict(config="undefended", wire_clock_pps=None)))
            rows = [
                dict(label=0, site="s", status="WebDriverException", start=10, resources=0),
                dict(label=0, site="s", status="browser_failed"),
            ]
            (worker / "loads.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
            np.array([(9, 100), (11, 200), (12, 300), (23, 100)], wf_deep.RECORD).tofile(worker / "packets.bin")
            features, labels, _, kept, attempts, exclusions, _ = replication.load(root, "undefended")
            self.assertEqual(labels.tolist(), [0])
            self.assertEqual(len(kept), 1)
            self.assertEqual(len(attempts), 2)
            self.assertEqual(exclusions[0]["reason"], "no_valid_browser_start")
            self.assertEqual(features["both"].shape, features["downstream_only"].shape)
            self.assertFalse(features["downstream_only"].any())
            self.assertTrue(features["upstream_only"].any())

    def test_unfiltered_holdout_scores_all_rows_while_secondary_reports_exclusions(self):
        import numpy as np

        y = np.array([0, 0, 1, 1] * 3)
        groups = np.repeat([1, 2, 3], 4)
        x = np.column_stack([y, y * 50.0])
        rows = [dict(site=str(label), status="ok", resources=40) for label in y]
        rows[0]["status"] = "WebDriverException"
        rows[5]["resources"] = 0
        primary = replication.score(x, y, groups, rows)
        secondary = replication.score(x, y, groups, rows, filtered=True)
        self.assertEqual(primary["evaluated"], 12)
        self.assertEqual(primary["accuracy"], 1)
        self.assertEqual(secondary["evaluated"], 10)
        self.assertEqual(secondary["excluded"], 2)
        self.assertEqual(replication.accuracy_interval(primary["by_round"]), [1.0, 1.0])

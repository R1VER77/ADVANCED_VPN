"""Regression cases for fresh controls, failed captures and held-out filter leakage."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import wf_replication as replication

HAVE = all(importlib.util.find_spec(name) is not None for name in ("numpy", "sklearn"))


class Metadata(unittest.TestCase):
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

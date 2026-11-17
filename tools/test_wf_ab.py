"""A/B analysis must preserve repeated attempts, round boundaries and loader semantics."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import wf_ab

HAVE = {name: importlib.util.find_spec(name) is not None for name in ("numpy", "sklearn")}


class Attempts(unittest.TestCase):
    def test_multiple_view_adjustment_is_monotone_and_restores_original_order(self):
        adjusted = wf_ab.holm([0.2, 0.01, 0.04])
        self.assertEqual(adjusted, [0.2, 0.03, 0.08])

    def test_pairing_uses_site_round_and_repeat_and_refuses_missing_attempts(self):
        left = [dict(site=s, round=r, marker=i) for r in [1, 2] for s in ["a", "b"] for i in [0, 1]]
        right = sorted(left, key=lambda x: (x["site"], x["round"]))
        pairs = wf_ab.paired_rows(left, right)
        self.assertEqual(len(pairs), 8)
        self.assertTrue(all(a == b for a, b in pairs))
        with self.assertRaises(ValueError):
            wf_ab.paired_rows(left, right[:-1])

    def test_failed_loads_stay_in_cost_but_not_in_the_classifier_filter(self):
        rows = [
            dict(site="s", status="ok", resources=40),
            dict(site="s", status="TimeoutException", resources=30),
            dict(site="s", status="WebDriverException", resources=40),
            dict(site="s", status="ok", resources=1),
        ]
        usual = wf_ab.resource_medians(rows)
        self.assertEqual([wf_ab.accepted(r, usual) for r in rows], [True, True, False, False])
        self.assertTrue(wf_ab.accepted(rows[-1], usual, minimum=0))
        self.assertEqual([wf_ab.round_number("r10-relay5"), wf_ab.round_number("r2-relay5")], [10, 2])


@unittest.skipUnless(HAVE["numpy"], "needs optional numpy")
class FeatureLoading(unittest.TestCase):
    def test_features_and_resource_filter_match_the_existing_loader_with_rounds_retained(self):
        import numpy as np
        import test_wf_deep
        import wf_deep

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            combined = root / "all"
            combined.mkdir()
            for number in [1, 2]:
                directory = root / f"r{number}-relay30"
                test_wf_deep.write_collection(directory, sites=2, loads=3)
                worker = directory / "w0"
                (worker / "settings.json").write_text(json.dumps(dict(wire_clock_relay_ms="30")))
                (combined / f"w{number}").symlink_to(worker)
            features, labels, groups, mask, attempts, _, _ = wf_ab.load_features(root, "relay30")
            expected = wf_deep.load_run(combined)
            self.assertEqual(labels.tolist(), [label for label, _, _ in expected])
            self.assertEqual(groups.tolist(), [1] * 6 + [2] * 6)
            self.assertEqual(len(attempts), 14)
            self.assertTrue(mask.all())
            np.testing.assert_allclose(features["both"], wf_deep.kfp_features([trace for _, _, trace in expected]))
            # A mislabeled look-ahead invalidates the comparison before it can score.
            (root / "r2-relay30/w0/settings.json").write_text(json.dumps(dict(wire_clock_relay_ms="5")))
            with self.assertRaisesRegex(ValueError, "look-ahead"):
                wf_ab.load_features(root, "relay30")

    def test_label_permutations_preserve_repeats_within_each_round(self):
        import numpy as np

        y = np.tile(np.repeat(np.arange(6), 2), 3)
        groups = np.repeat(np.arange(3), 12)
        shuffled = wf_ab.permute_round_labels(y, groups, 1)
        self.assertTrue(np.array_equal(shuffled[::2], shuffled[1::2]))
        self.assertEqual(sorted(shuffled.tolist()), sorted(y.tolist()))
        self.assertFalse(np.array_equal(shuffled[:12], shuffled[12:24]))
        self.assertTrue(np.array_equal(shuffled, wf_ab.permute_round_labels(y, groups, 1)))


@unittest.skipUnless(HAVE["numpy"] and HAVE["sklearn"], "needs optional analysis environment")
class Scoring(unittest.TestCase):
    def test_random_load_splits_can_memorize_round_local_tokens_that_do_not_generalize(self):
        import numpy as np

        y = np.tile(np.repeat(np.arange(4), 10), 5)
        groups = np.repeat(np.arange(5), 40)
        tokens = np.random.default_rng(4).permutation(20)
        features = np.repeat(tokens, 10)[:, None].astype(float)
        legacy, _ = wf_ab.cv_score(features, y, groups, "legacy_stratified")
        held_out, _ = wf_ab.cv_score(features, y, groups, "round_holdout")
        self.assertGreater(legacy, 0.95)
        self.assertLess(held_out, 0.7)

    def test_round_holdout_detects_a_clear_signal_and_refuses_an_unknown_split(self):
        import numpy as np

        y = np.tile(np.repeat(np.arange(3), 3), 3)
        groups = np.repeat(np.arange(3), 9)
        features = np.column_stack([y * 100.0, y * 200.0])
        accuracy, by_round = wf_ab.cv_score(features, y, groups, "round_holdout")
        self.assertEqual(accuracy, 1.0)
        self.assertEqual(by_round, {str(i): dict(correct=9, loads=9) for i in range(3)})
        with self.assertRaises(ValueError):
            wf_ab.cv_score(features, y, groups, "invalid")


if __name__ == "__main__":
    unittest.main()

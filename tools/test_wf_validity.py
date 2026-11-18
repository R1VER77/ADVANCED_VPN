"""Sparse captures, stopped recorders and sampled protection must have different meanings."""

import unittest

import wf_validity as v


def observations():
    """One half-second observation cadence with a stable realtime/monotonic relation."""
    return [dict(time=10 + n / 2, monotonic=20 + n / 2, drops=0, protection="protected") for n in range(29)]


class WindowEvidence(unittest.TestCase):
    def test_a_silent_but_covered_zero_drop_window_is_valid(self):
        report = dict(
            schema=1, timestamp_source="kernel_time64", clean_stop=True, drops=0, malformed=0, unexpected_outgoing=0
        )
        self.assertTrue(v.capture_window(report, observations(), 10.5, 22.5)["valid"])
        self.assertFalse(v.capture_window(dict(report, drops=1), observations(), 10.5, 22.5)["valid"])
        self.assertFalse(v.capture_window(dict(report, clean_stop=False), observations(), 10.5, 22.5)["valid"])

    def test_missing_samples_and_clock_steps_do_not_count_as_coverage(self):
        rows = observations()
        self.assertEqual(v.bracket(rows[3:], 10.5, 22.5)[1], "observations_do_not_cover_window")
        self.assertEqual(v.bracket(rows[:4] + rows[10:], 10.5, 22.5)[1], "observation_gap")
        rows[10]["time"] += 0.3
        self.assertEqual(v.bracket(rows, 10.5, 22.5)[1], "observation_clock_step")

    def test_an_unknown_mid_load_sample_is_reported_without_dropping_the_capture(self):
        rows = observations()
        rows[10]["protection"] = "unknown"
        result = v.protection_window(rows, 10.5, 22.5, defended=True)
        self.assertTrue(result["observed"])
        self.assertFalse(result["all_samples_protected"])
        self.assertEqual(result["unexpected_samples"], 1)

#!/usr/bin/env python3
"""Tests for the multihop presets (tools/multihop_presets.py): preset
resolution against a planner stub with the real refusal semantics,
downward-only degradation with visible reasons, the 3-hop ceiling, and
the workload-profile flags."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import multihop_presets as mp  # noqa: E402


class RecordingSelect:
    """A stand-in for mesh.select_chain that records the hop counts it
    was asked for and refuses the ones the test wants refused (the real
    planner raises SystemExit when diversity cannot be met)."""

    def __init__(self, refuse=()):
        self.asked = []
        self.refuse = set(refuse)

    def __call__(self, nodes, hops, **kwargs):
        self.asked.append(hops)
        if hops in self.refuse:
            raise SystemExit(f"no chain at {hops} hops under the diversity rule")
        return [{"node_id": f"hop{i}", "hops": hops} for i in range(hops)]


class ResolutionTests(unittest.TestCase):
    def test_always_gets_three_hops(self):
        plan = mp.resolve("always", RecordingSelect(), [])
        self.assertEqual(plan["hops"], 3)
        self.assertFalse(plan["degraded"])
        self.assertEqual(len(plan["chain"]), 3)

    def test_when_needed_is_the_two_hop_default(self):
        plan = mp.resolve("when-needed", RecordingSelect(), [])
        self.assertEqual(plan["hops"], 2)
        self.assertFalse(plan["degraded"])

    def test_never_is_one_hop(self):
        plan = mp.resolve("never", RecordingSelect(), [])
        self.assertEqual(plan["hops"], 1)

    def test_degradation_is_downward_only_with_reason(self):
        select = RecordingSelect(refuse={3})
        plan = mp.resolve("always", select, [])
        self.assertEqual(plan["hops"], 2)
        self.assertTrue(plan["degraded"])
        self.assertIn("fell to 2", plan["reason"])
        self.assertEqual(select.asked, [3, 2])

    def test_when_needed_falls_to_one(self):
        select = RecordingSelect(refuse={2})
        plan = mp.resolve("when-needed", select, [])
        self.assertEqual(plan["hops"], 1)
        self.assertTrue(plan["degraded"])

    def test_unstaffable_pool_refused(self):
        select = RecordingSelect(refuse={1, 2, 3})
        with self.assertRaises(mp.PresetError):
            mp.resolve("always", select, [])

    def test_unknown_preset_refused(self):
        with self.assertRaises(mp.PresetError):
            mp.resolve("sometimes", RecordingSelect(), [])

    def test_planner_kwargs_forwarded(self):
        captured = {}

        def select(nodes, hops, **kwargs):
            captured.update(kwargs, hops=hops)
            return []

        mp.resolve("when-needed", select, [], exit_country="GB")
        self.assertEqual(captured["exit_country"], "GB")
        self.assertEqual(captured["hops"], 2)


class CeilingTests(unittest.TestCase):
    def test_no_preset_exceeds_three_hops(self):
        """The documented ceiling: depth parity is already true in the
        live market; a 4th hop would be a headline feature, not a
        preset."""
        for name, preset in mp.PRESETS.items():
            self.assertLessEqual(preset["hops"], mp.MAX_HOPS, name)

    def test_every_preset_has_a_protection_label(self):
        for name, preset in mp.PRESETS.items():
            self.assertTrue(preset["label"], name)
            self.assertTrue(preset["description"], name)


class ProfileFlagTests(unittest.TestCase):
    def test_streaming_carries_line_rate(self):
        flags = mp.apply_preset_flags("streaming")
        self.assertEqual(flags["rate"], "line")
        self.assertEqual(flags["hops"], 2)

    def test_plain_presets_carry_no_rate(self):
        self.assertNotIn("rate", mp.apply_preset_flags("always"))
        self.assertNotIn("rate", mp.apply_preset_flags("when-needed"))

    def test_bulk_preset_documents_its_gate(self):
        self.assertIn("bulk admission", mp.PRESETS["bulk"]["requires"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

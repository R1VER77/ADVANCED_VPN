"""Tests for the versioned-migration drill (tools/curve_rotation.py): the
migration half of ROADMAP section 6's interface/curve inventory row - stages
in order, a bounded dual period, no key reset, no downgrade, and a cutover
gated by the interface's own PQ test.
"""

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import test_curve_inventory as curve_inventory  # noqa: E402  (the one inventory: its scan and registry live there)
import curve_rotation as cr  # noqa: E402


def make(**overrides):
    base = dict(
        interface="test interface",
        current="v1",
        target="v2",
        classification="hybrid",
        hardware="the enrolled identity key",
        pq_test="tools/test_units.py",
    )
    base.update(overrides)
    return cr.Migration(**base)


class StageTests(unittest.TestCase):
    def test_stages_advance_in_order_and_only_in_order(self):
        m = make()
        self.assertEqual(m.stage, "announce")
        self.assertEqual(m.advance(), "dual")
        self.assertEqual(m.advance(lambda: True), "cutover")
        self.assertEqual(m.advance(), "done")
        with self.assertRaisesRegex(cr.DrillError, "already_done"):
            m.advance()

    def test_cutover_needs_a_passing_pq_test(self):
        m = make()
        m.advance()
        for bad in (None, lambda: False, lambda: None):
            with self.assertRaisesRegex(cr.DrillError, "without_a_passing_pq_test"):
                m.advance(bad)

    def test_the_dual_period_is_bounded_and_overrun_is_refused(self):
        m = make(dual_rounds=2)
        m.advance()
        self.assertTrue(m.advance(lambda: True))  # round 1: cutover allowed
        m2 = make(dual_rounds=1)
        m2.advance()
        # round 1 is the last round; a second attempt without a cutover is an overrun
        m2.rounds_in_dual = 1
        with self.assertRaisesRegex(cr.DrillError, "overrun"):
            m2.advance(lambda: False)

    def test_a_key_reset_blocks_the_cutover_forever(self):
        m = make()
        m.advance()
        m.reset_keys()  # the forbidden act
        with self.assertRaisesRegex(cr.DrillError, "after_a_key_reset"):
            m.advance(lambda: True)
        self.assertFalse(m.report()["hardware_preserved"])

    def test_the_same_version_twice_is_not_a_migration(self):
        with self.assertRaisesRegex(cr.DrillError, "two different versions"):
            make(current="v2", target="v2")


class DowngradeTests(unittest.TestCase):
    def test_weaker_targets_are_refused_in_order(self):
        for bad in (("pq", "hybrid"), ("pq", "classical"), ("hybrid", "classical")):
            with self.assertRaisesRegex(cr.DrillError, "downgrade_refused"):
                cr.downgrade_check(*bad)

    def test_upgrades_pass_and_sideways_moves_are_flagged(self):
        self.assertEqual(cr.downgrade_check("classical", "hybrid"), "upgrade")
        self.assertEqual(cr.downgrade_check("hybrid", "pq"), "upgrade")
        self.assertIn("explicit reason", cr.downgrade_check("classical", "classical"))

    def test_unknown_classifications_are_refused(self):
        for bad in ("quantum", "", None, "HYBRID"):
            with self.assertRaisesRegex(cr.DrillError, "unknown_classification"):
                cr.downgrade_check(bad, "pq")


class RegistryDrillTests(unittest.TestCase):
    def test_the_whole_inventory_registry_drills_to_done(self):
        report = cr.drill_registry(curve_inventory.REGISTRY)
        self.assertEqual(report["drilled"], len(report["plans"]))
        self.assertGreater(report["drilled"], 0, "the inventory records open migrations")
        for plan in report["plans"]:
            self.assertEqual(plan["stage"], "done", plan.get("failed"))
            self.assertTrue(plan["hardware_preserved"])
            self.assertLessEqual(plan["dual_rounds"], cr.MAX_DUAL_ROUNDS)
        # the already-landed half is recorded, not drilled
        self.assertTrue(report["already_landed"])
        self.assertIn("procedure", report["note"].lower())

    def test_a_failing_pq_test_stops_that_row_at_dual(self):
        report = cr.drill_registry(curve_inventory.REGISTRY, dual_check=lambda row: False)
        self.assertEqual(report["drilled"], len(report["plans"]))
        for plan in report["plans"]:
            self.assertEqual(plan.get("failed"), "cutover_refused_without_a_passing_pq_test")
            self.assertEqual(plan["stage"], "dual")

    def test_the_drill_reports_the_preserved_hardware_dependency(self):
        report = cr.drill_registry(curve_inventory.REGISTRY)
        hardware_rows = [p for p in report["plans"] if p["hardware"] != "none"]
        for plan in hardware_rows:
            self.assertTrue(plan["hardware_preserved"])
            self.assertTrue(plan["hardware"])  # the dependency is named, never silently reset

    def test_the_inventory_still_cross_checks_with_its_own_scan(self):
        """The drill builds on the inventory; the inventory must still build."""
        inventory = curve_inventory.build_inventory()
        self.assertEqual(inventory["schema"], curve_inventory.SCHEMA)
        self.assertGreater(len(inventory["summary"]["open_migrations"]), 0)


if __name__ == "__main__":
    unittest.main()

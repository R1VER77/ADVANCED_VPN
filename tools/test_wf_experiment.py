"""A live replication must counterbalance arms, clear overrides and preserve existing data."""

import itertools
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

import wf_experiment as experiment


class ExperimentBoundaries(unittest.TestCase):
    def test_power_changes_or_builds_stop_an_in_progress_arm(self):
        for bad in (
            dict(power=dict(on_mains=False), concurrent_build_or_inference=[]),
            dict(power=dict(on_mains=True), concurrent_build_or_inference=["rustc"]),
        ):
            with self.assertRaises(RuntimeError):
                experiment.validate_host_conditions(bad)
        experiment.validate_host_conditions(dict(power=dict(on_mains=True), concurrent_build_or_inference=[]))

    def test_interpreter_inventory_works_before_pip_is_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = Path(temporary) / "no-pip"
            subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(env)], check=True)
            self.assertEqual(json.loads(experiment.package_inventory(env / "bin/python")), [])

    def test_each_variant_order_and_round_seed_is_used_as_prespecified(self):
        arms = experiment.schedule()
        self.assertEqual(len(arms), 18)
        orders, seeds = [], []
        for number in range(1, 7):
            selected = [a for a in arms if a["round"] == number]
            orders.append(tuple(a["variant"] for a in selected))
            self.assertEqual(len({a["seed"] for a in selected}), 1)
            seeds.append(selected[0]["seed"])
        self.assertEqual(set(orders), set(itertools.permutations(("relay30", "relay5", "undefended"))))
        self.assertEqual(len(set(seeds)), 6)

    def test_arms_do_not_inherit_another_experiments_clock_settings(self):
        parent = dict(CPVPN_WIRE_CLOCK_PPS="999", CPVPN_RUNTIME_ROOT="wrong", CPVPN_OTHER="wrong", KEEP="yes")
        control = experiment.arm_environment(parent, "undefended")
        self.assertFalse(any(k.startswith("CPVPN_") for k in control))
        self.assertEqual(control["KEEP"], "yes")
        defended = experiment.arm_environment(parent, "relay5")
        self.assertEqual(defended["CPVPN_WIRE_CLOCK_PPS"], "4000")
        self.assertEqual(defended["CPVPN_WIRE_CLOCK_RELAY_MS"], "5")
        self.assertNotIn("CPVPN_RUNTIME_ROOT", defended)

    def test_changed_frozen_source_is_refused_before_an_arm_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "tool.py"
            path.write_text("original")
            manifest = dict(
                schema=1, schedule=experiment.schedule(), files={"tool.py": experiment.sha256(path)}, executables={}
            )
            path.write_text("changed")
            with self.assertRaisesRegex(RuntimeError, "frozen experiment file changed"):
                experiment.verify_frozen(root, manifest)

    def test_different_output_paths_cannot_start_simultaneous_experiments(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(tempfile, "gettempdir", return_value=temporary),
        ):
            with experiment.host_lock():
                with self.assertRaises(BlockingIOError), experiment.host_lock():
                    self.fail("second collection acquired the host lock")
            path = Path(temporary) / f"cypherpunk-wf-collection-{os.getuid()}.lock"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

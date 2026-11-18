"""Persistent guard intent precedes network changes and survives partial failures.

Filesystem ownership and systemctl are simulated here; physical boot evidence is
provided separately by bootguard_vm.py, never by these unit tests.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import guard_policy as policy


class PersistentGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = self.root / "etc/whole-device.guard"
        self.state = self.root / "etc/enrolled"
        self.units = self.root / "units"
        self.units.mkdir(mode=0o755)
        self.calls = []
        self.arming = True
        original_stat = Path.stat

        def root_owned(path, **kwargs):
            value = original_stat(path, **kwargs)
            fields = list(value)
            fields[4] = 0  # Simulated root ownership, not an assertion about the host.
            return os.stat_result(fields)

        for patcher in (
            mock.patch.object(policy, "MARKER", self.marker),
            mock.patch.object(policy, "STATE", self.state),
            mock.patch.object(policy, "UNITS", self.units),
            mock.patch.object(policy.os, "geteuid", return_value=0),
            mock.patch.object(policy, "native_guard", return_value="/usr/libexec/cypherpunk-vpn-bootguard"),
            mock.patch.object(policy, "protected_directory"),
            mock.patch.object(policy, "trusted_exe", return_value="/usr/bin/systemctl"),
            mock.patch.object(policy, "read_private", side_effect=lambda path: path.read_bytes()),
            mock.patch.object(Path, "stat", root_owned),
            mock.patch.object(policy.subprocess, "run", side_effect=self.command),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[1:] == ["disable", policy.UNIT]:
            self.arming = False
        if self.arming and argv[1:] in (["daemon-reload"], ["enable", policy.UNIT]):
            self.assertEqual(self.marker.read_bytes(), policy.MARKER_BYTES)
            self.assertTrue(all((self.units / (name + ".d") / policy.DROPIN).exists() for name in policy.MANAGERS))
        return subprocess.CompletedProcess(argv, 0)

    def test_arm_is_idempotent_and_intent_precedes_commands(self):
        policy.arm(apply=True, state=self.state)
        policy.arm(state=self.state)
        self.assertIn(["/usr/libexec/cypherpunk-vpn-bootguard"], self.calls)
        self.assertEqual(self.marker.read_bytes(), policy.MARKER_BYTES)

    def test_failed_dependency_install_keeps_durable_deny_intent(self):
        foreign = self.units / (policy.MANAGERS[0] + ".d") / policy.DROPIN
        foreign.parent.mkdir(mode=0o755)
        foreign.write_bytes(b"administrator policy")
        with self.assertRaisesRegex(ValueError, "foreign"):
            policy.arm(state=self.state)
        self.assertEqual(self.marker.read_bytes(), policy.MARKER_BYTES)
        self.assertFalse(self.calls)
        self.assertEqual(foreign.read_bytes(), b"administrator policy")

    def test_explicit_disarm_checks_every_dependency_before_mutation(self):
        policy.arm(state=self.state)
        foreign = self.units / (policy.MANAGERS[-1] + ".d") / policy.DROPIN
        foreign.write_bytes(b"changed")
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, "foreign"):
            policy.disarm(state=self.state)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.calls)
        foreign.write_bytes(policy.REQUIRE)
        policy.disarm(state=self.state)
        self.assertFalse(self.marker.exists())
        self.assertTrue(all(not (self.units / (name + ".d") / policy.DROPIN).exists() for name in policy.MANAGERS))

    def test_custom_state_cannot_arm_or_disarm_the_installed_guard(self):
        for function in (policy.arm, policy.disarm):
            with self.assertRaisesRegex(ValueError, "state"):
                function(state=self.root / "other-state")
        self.assertFalse(self.marker.exists())

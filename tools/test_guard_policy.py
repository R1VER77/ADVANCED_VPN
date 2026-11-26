"""Persistent guard intent precedes network changes and survives partial failures.

Filesystem ownership and systemctl are simulated here; physical boot evidence is
provided separately by bootguard_vm.py, never by these unit tests.
"""

import os
import contextlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import guard_policy as policy
import cypherpunkctl


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

    def test_disconnect_only_restores_ordinary_networking_with_lockdown_off(self):
        self.state.mkdir(parents=True)
        (self.state / "profile.json").touch()
        prefs = self.state / "preferences.json"
        for lockdown, keep_guard in ((True, False), (False, True), (False, False)):
            with (
                self.subTest(lockdown=lockdown, keep_guard=keep_guard),
                mock.patch.object(cypherpunkctl, "stop_supervisor", return_value=True),
                mock.patch.object(cypherpunkctl, "supervisor_locks", side_effect=lambda _: contextlib.nullcontext()),
                mock.patch.object(cypherpunkctl, "load_profile", return_value={"role": "client"}),
                mock.patch.object(cypherpunkctl, "reset") as reset,
                mock.patch.object(cypherpunkctl, "emit"),
            ):
                prefs.write_text(json.dumps(dict(mode="whole-device", lockdown=lockdown)))
                prefs.chmod(0o600)
                argv = ["--state", str(self.state), "disconnect"]
                if keep_guard:
                    argv.append("--keep-guard")
                with mock.patch.object(cypherpunkctl, "read_private", side_effect=lambda path: path.read_bytes()):
                    cypherpunkctl.dispatch(cypherpunkctl.build_parser().parse_args(argv))
                if lockdown or keep_guard:
                    reset.assert_not_called()
                else:
                    reset.assert_called_once_with(self.state, clear_lockdown=False)

    def test_lockdown_off_for_reconnect_preserves_runtime_guard(self):
        self.state.mkdir(parents=True)
        args = cypherpunkctl.build_parser().parse_args(
            ["--state", str(self.state), "preferences", "--lockdown", "off", "--keep-guard"]
        )
        with (
            mock.patch.object(cypherpunkctl, "load_profile", return_value={"role": "client"}),
            mock.patch.object(cypherpunkctl, "supervisor_locks", side_effect=lambda _: contextlib.nullcontext()),
            mock.patch.object(cypherpunkctl, "reset") as reset,
            mock.patch.object(cypherpunkctl, "save") as save,
            mock.patch.object(cypherpunkctl, "emit"),
            mock.patch.object(policy, "disarm") as disarm,
        ):
            cypherpunkctl.dispatch(args)
        disarm.assert_called_once_with(self.state)
        reset.assert_not_called()
        save.assert_called_once_with(self.state / "preferences.json", {"lockdown": False})

    def test_saved_applications_are_literal_and_do_not_change_scope(self):
        self.state.mkdir(parents=True)
        prefs = self.state / "preferences.json"
        prefs.write_text('{"mode":"applications","lockdown":false}')
        prefs.chmod(0o600)
        parser = cypherpunkctl.build_parser()
        with (
            mock.patch.object(cypherpunkctl, "load_profile", return_value={"role": "client"}),
            mock.patch.object(cypherpunkctl, "emit"),
            mock.patch.object(cypherpunkctl, "read_private", side_effect=lambda path: path.read_bytes()),
        ):
            for option, expected in [
                ("--protect-app=/usr/bin/firefox", ["/usr/bin/firefox"]),
                ("--protect-app=/usr/bin/firefox", ["/usr/bin/firefox"]),
                ("--forget-app=/usr/bin/firefox", []),
            ]:
                cypherpunkctl.dispatch(parser.parse_args(["--state", str(self.state), "preferences", option]))
                self.assertEqual(
                    json.loads(prefs.read_text()),
                    {
                        "mode": "applications",
                        "lockdown": False,
                        "protected_apps": expected,
                    },
                )

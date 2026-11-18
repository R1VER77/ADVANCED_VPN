"""Removal must refuse protected/enabled/running states without issuing any mutations."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import install
import guard_policy


class RemovalGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name) / "proc"
        self.proc.mkdir()
        self.target = Path(self.temp.name) / "installation"
        self.states = {}
        self.tables, self.namespaces, self.links = [], [], []
        self.calls = []
        for name, path in (
            ("MARKER", Path(self.temp.name) / "whole-device.guard"),
            ("UNITS", Path(self.temp.name) / "units"),
        ):
            patcher = mock.patch.object(guard_policy, name, path)
            patcher.start()
            self.addCleanup(patcher.stop)

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "show":
            state = self.states.get(argv[2], dict(LoadState="loaded", ActiveState="inactive", UnitFileState="disabled"))
            out = "\n".join(k + "=" + v for k, v in state.items())
        elif argv == ["/usr/bin/nft", "-j", "list", "tables"]:
            out = json.dumps(dict(nftables=self.tables))
        elif argv == ["/usr/bin/ip", "-j", "netns", "list"]:
            out = json.dumps(self.namespaces)
        elif argv == ["/usr/bin/ip", "-j", "link", "show"]:
            out = json.dumps(self.links)
        else:
            self.fail("unexpected mutation or command: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0, out, "")

    def check(self):
        with (
            mock.patch.object(install, "trusted_exe", side_effect=lambda name: "/usr/bin/" + name),
            mock.patch.object(install.subprocess, "run", side_effect=self.command),
        ):
            install.removal_checks(self.target, self.proc)

    def test_inactive_disabled_empty_host_passes_with_only_read_operations(self):
        self.check()
        self.assertEqual(len(self.calls), 6)

    def test_each_active_or_enabled_unit_blocks_before_network_queries(self):
        for unit in ("advanced-vpn.service", "advanced-vpn-guard.service", "cypherpunk-vpn-controller.service"):
            for update in (dict(ActiveState="active"), dict(ActiveState="activating"),
                           dict(UnitFileState="enabled"), dict(UnitFileState="enabled-runtime"),
                           dict(ActiveState="unknown"), dict(UnitFileState="unknown")):  # fmt: skip
                with self.subTest(unit=unit, update=update):
                    self.calls.clear()
                    state = dict(LoadState="loaded", ActiveState="inactive", UnitFileState="disabled")
                    state.update(update)
                    self.states = {unit: state}
                    with self.assertRaisesRegex(RuntimeError, "active, enabled or unverified"):
                        self.check()
                    self.assertTrue(all(call[1] == "show" for call in self.calls))

    def test_disconnected_guard_tables_still_block_removal(self):
        for name in ("advanced_vpn", "advanced_vpn_meter", "advanced_vpn_upstream", "advanced_vpn_front"):
            with self.subTest(name=name):
                self.tables = [dict(table=dict(family="inet", name=name))]
                with self.assertRaisesRegex(RuntimeError, "guard is retained"):
                    self.check()

    def test_persistent_intent_and_manager_dependency_block_removal_without_queries(self):
        guard_policy.MARKER.write_bytes(b"intent")
        with self.assertRaisesRegex(RuntimeError, "persistent whole-device"):
            self.check()
        guard_policy.MARKER.unlink()
        dependency = guard_policy.UNITS / (guard_policy.MANAGERS[0] + ".d") / guard_policy.DROPIN
        dependency.parent.mkdir(parents=True)
        dependency.write_bytes(guard_policy.REQUIRE)
        with self.assertRaisesRegex(RuntimeError, "network manager"):
            self.check()
        self.assertEqual(self.calls, [])

    def test_protected_namespace_and_owned_interface_block_removal(self):
        self.namespaces = [dict(name="avpn-app")]
        with self.assertRaisesRegex(RuntimeError, "namespace or interface"):
            self.check()
        self.namespaces = []
        self.links = [dict(ifname="avpn0", ifalias="advanced-vpn-managed")]
        with self.assertRaisesRegex(RuntimeError, "namespace or interface"):
            self.check()

    def test_running_program_blocks_even_without_a_service(self):
        for exe in (self.target / "bin/advanced-vpn", self.target / "venv/bin/python3.13"):
            p = self.proc / "12345"
            p.mkdir(exist_ok=True)
            link = p / "exe"
            link.symlink_to(exe)
            with self.assertRaisesRegex(RuntimeError, "still running"):
                self.check()
            link.unlink()
        (p / "exe").symlink_to(str(self.target / "bin/avpn") + " (deleted)")
        with self.assertRaisesRegex(RuntimeError, "still running"):
            self.check()

    def test_unrelated_process_and_disappeared_process_do_not_block(self):
        p = self.proc / "12345"
        p.mkdir()
        (p / "exe").symlink_to("/usr/bin/other-program")
        (self.proc / "12346").mkdir()  # vanished executable / kernel thread
        self.check()

    def test_command_failure_and_inaccessible_process_fail_closed(self):
        with (
            mock.patch.object(install, "trusted_exe", return_value="/usr/bin/systemctl"),
            mock.patch.object(install.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "systemctl")),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                install.removal_checks(self.target, self.proc)
        (self.proc / "12345").mkdir()
        with mock.patch.object(install.os, "readlink", side_effect=PermissionError("cannot inspect process")):
            with self.assertRaises(PermissionError):
                self.check()

    def test_root_removal_never_proceeds_past_a_failed_gate(self):
        # A real system root (/opt) satisfies the preliminary parent check. The
        # injected guard refusal must occur before any host/file mutation.
        with (
            mock.patch.object(install.os, "geteuid", return_value=0),
            mock.patch.object(install, "removal_checks", side_effect=RuntimeError("guard retained")),
            mock.patch.object(install.shutil, "rmtree", side_effect=AssertionError("deleted files")),
            mock.patch.object(Path, "unlink", side_effect=AssertionError("removed unit")),
            mock.patch.object(install.subprocess, "run", side_effect=AssertionError("changed service")),
        ):
            with self.assertRaises(RuntimeError):
                install.uninstall_system(Path("/opt/cypherpunk-vpn-nonexistent-test"))

    def test_removal_needs_root(self):
        with mock.patch.object(install.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                install.uninstall_system()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Security-key software: what a detected key needs, and install versus upgrade."""

from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import key_software  # noqa: E402


def fake_system(installed, candidates):
    """A stand-in for dpkg-query, apt-cache and dpkg --compare-versions."""

    def run(argv, **_):
        if argv[0] == "dpkg-query":
            v = installed.get(argv[-1])
            out = "install ok installed\t%s" % v if v else ""
            return subprocess.CompletedProcess(argv, 0 if v else 1, out, "")
        if argv[0] == "apt-cache":
            c = candidates.get(argv[-1])
            return subprocess.CompletedProcess(
                argv, 0, "%s:\n  Installed: x\n  Candidate: %s\n" % (argv[-1], c or "(none)"), ""
            )
        if argv[0] == "dpkg":
            a, b = argv[2], argv[4]
            return subprocess.CompletedProcess(
                argv, 0 if tuple(map(int, a.split("."))) < tuple(map(int, b.split("."))) else 1
            )
        raise AssertionError(argv)

    return run


class KeySoftware(unittest.TestCase):
    def test_each_family_gets_its_own_tool_and_every_key_the_base(self):
        self.assertEqual(key_software.wanted(["Nitrokey 3"]), ["libfido2-1"])
        self.assertEqual(
            key_software.wanted(["YubiKey", "Trezor", "YubiKey"]), ["libfido2-1", "trezor", "yubikey-manager"]
        )
        self.assertEqual(key_software.wanted([]), ["libfido2-1"])

    def test_missing_is_installed_but_a_newer_version_is_only_offered(self):
        run = fake_system(
            {"libfido2-1": "1.15", "yubikey-manager": "5.6"},
            {"libfido2-1": "1.15", "yubikey-manager": "5.7", "trezor": "0.13"},
        )
        rows = key_software.status(["YubiKey", "Trezor"], run)
        self.assertEqual({r["package"]: r["state"] for r in rows},
                         {"libfido2-1": "ok", "yubikey-manager": "upgrade", "trezor": "missing"})  # fmt: skip
        # Setup's install never upgrades: an older or custom build may be kept on purpose.
        self.assertEqual(key_software.selection(rows, "install"), ["trezor"])
        self.assertEqual(key_software.selection(rows, "upgrade"), ["yubikey-manager"])
        with self.assertRaises(ValueError):
            key_software.selection(rows, "purge")

    def test_a_package_the_sources_do_not_offer_is_reported_not_installed(self):
        rows = key_software.status(["Trezor"], fake_system({"libfido2-1": "1.15"}, {"libfido2-1": "1.15"}))
        self.assertEqual(rows[1], dict(package="trezor", installed=None, candidate=None, state="unavailable"))
        self.assertEqual(key_software.selection(rows, "install"), [])

    def test_the_command_is_apt_in_a_transient_unit_for_allowlisted_packages_only(self):
        cmd = key_software.command("install", ["trezor"])
        self.assertEqual(cmd[:2], ["systemd-run", "--wait"])
        self.assertEqual(cmd[-2:], ["--", "trezor"])  # no package name can be read as an option
        self.assertNotIn("--only-upgrade", cmd)
        self.assertIn("--only-upgrade", key_software.command("upgrade", ["yubikey-manager"]))
        for bad in (["bash"], ["-oDPkg::Pre-Invoke=id"], [], ["trezor", "openssh-server"]):
            with self.assertRaises(ValueError):
                key_software.command("install", bad)
        with self.assertRaises(ValueError):
            key_software.command("remove", ["trezor"])


if __name__ == "__main__":
    unittest.main()

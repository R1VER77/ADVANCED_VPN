"""Tests for tools/preflight.py against simulated systems (a temporary root tree with
os-release, /proc, /sys, /dev and programs). Standard library only: runs on Python 3.8."""

import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import preflight as pf

DEBIAN13 = 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n'


class Sim:
    """A healthy simulated Debian 13 host; tests break one thing at a time."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.systemd = "systemd 257 (257.13-1)\n+PAM"
        self.kw = dict(machine="x86_64", kernel="6.12.0", glibc="glibc 2.41", python=(3, 13), ensurepip=True,
                       free_mb=lambda p: 20000)  # fmt: skip
        self.write("etc/os-release", DEBIAN13)
        self.write("dev/net/tun", "")
        self.write("proc/self/status", "Name:\tpython\nSeccomp:\t0\nSeccomp_filters:\t0\n")
        self.write("sys/kernel/security/lsm", "lockdown,capability,landlock,yama,apparmor")
        (self.root / "sys/module/nf_tables").mkdir(parents=True)
        (self.root / "sys/class/net/lo").mkdir(parents=True)
        (self.root / "opt").mkdir()
        for p in ("ip", "nft", "mount", "systemctl", "apt-get"):
            self.program(p)

    def write(self, rel, text):
        f = self.root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def program(self, name, where="usr/bin"):
        f = self.root / where / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("#!/bin/sh\n")
        f.chmod(0o755)

    def remove(self, rel):
        f = self.root / rel
        if f.is_dir():
            f.rmdir()
        else:
            f.unlink()

    def host(self):
        def run(argv):
            return subprocess.CompletedProcess(argv, 0, self.systemd, "")

        return pf.Host(self.root, path="/usr/bin", run=run, **self.kw)

    def findings(self, opts=None):
        return pf.run_checks(self.host(), opts)

    def codes(self, severity=None, opts=None):
        return [f.code for f in self.findings(opts) if severity is None or f.severity == severity]


class Opts:
    package = None
    target = "/opt"
    protect = None


class Healthy(unittest.TestCase):
    def test_a_healthy_tested_system_is_ready(self):
        s = Sim()
        summary = pf.summary(s.host(), s.findings())
        self.assertTrue(summary["ready"], summary)
        self.assertEqual((summary["blockers"], summary["warnings"], summary["install"]), (0, 0, None))
        s.tmp.cleanup()


class Blockers(unittest.TestCase):
    def setUp(self):
        self.s = Sim()

    def tearDown(self):
        self.s.tmp.cleanup()

    def blockers(self):
        return self.s.codes("blocker")

    def test_unknown_os(self):
        self.s.write("etc/os-release", 'ID=haiku\nVERSION_ID="1"\n')
        self.assertEqual(self.blockers(), ["os_unknown"])

    def test_architecture(self):
        self.s.kw["machine"] = "aarch64"
        self.assertEqual(self.blockers(), ["arch_unsupported"])

    def test_old_glibc_and_no_glibc(self):
        self.s.kw["glibc"] = "glibc 2.31"
        self.assertEqual(self.blockers(), ["glibc_old"])
        self.s.kw["glibc"] = ""
        self.assertEqual(self.blockers(), ["glibc_unknown"])

    def test_glibc_need_comes_from_the_packages_binaries(self):
        pkg = self.s.root / "pkg"
        pkg.mkdir()
        (pkg / "advanced-vpn").write_bytes(b"\x7fELF" + b"\0" * 8 + b"GLIBC_2.34\0GLIBC_2.39\0")
        (pkg / "README").write_text("GLIBC_2.99 is mentioned here but this is not a binary")
        self.assertEqual(pf.glibc_need(pkg), (2, 39))
        self.assertEqual(pf.glibc_need(None), pf.RELEASE_GLIBC)
        self.s.kw["glibc"] = "glibc 2.36"
        opts = Opts()
        opts.package = pkg
        self.assertEqual([f.code for f in self.s.findings(opts) if f.severity == "blocker"], ["glibc_old"])

    def test_no_tun(self):
        self.s.remove("dev/net/tun")
        self.assertEqual(self.blockers(), ["tun_missing"])

    def test_each_missing_program_and_one_install_command(self):
        self.s.remove("usr/bin/nft")
        self.s.remove("usr/bin/ip")
        summary = pf.summary(self.s.host(), self.s.findings())
        self.assertEqual(self.blockers(), ["program_missing", "program_missing"])
        self.assertEqual(summary["install"], "sudo apt-get install -y iproute2 nftables")

    def test_programs_in_sbin_are_found_even_off_the_users_path(self):
        self.s.remove("usr/bin/nft")
        self.s.program("nft", "usr/sbin")  # Debian: nft is in /usr/sbin, not on a user's PATH
        self.assertEqual(self.blockers(), [])

    def test_no_nf_tables_but_a_module_or_builtin_counts(self):
        self.s.remove("sys/module/nf_tables")
        self.assertEqual(self.blockers(), ["nf_tables_missing"])
        self.s.write("lib/modules/6.12.0/kernel/net/netfilter/nf_tables.ko.xz", "")
        self.assertEqual(self.blockers(), [])
        self.s.remove("lib/modules/6.12.0/kernel/net/netfilter/nf_tables.ko.xz")
        self.s.write("lib/modules/6.12.0/modules.builtin", "kernel/net/netfilter/nf_tables.ko\n")
        self.assertEqual(self.blockers(), [])

    def test_no_seccomp(self):
        self.s.write("proc/self/status", "Name:\tpython\n")
        self.assertEqual(self.blockers(), ["seccomp_missing"])

    def test_old_python_and_no_venv(self):
        self.s.kw["python"] = (3, 8)
        self.assertEqual(self.blockers(), ["python_old"])
        self.s.kw["python"] = (3, 12)
        self.s.kw["ensurepip"] = False
        summary = pf.summary(self.s.host(), self.s.findings())
        self.assertEqual(self.blockers(), ["venv_missing"])
        self.assertEqual(summary["install"], "sudo apt-get install -y python3-venv")

    def test_low_space_looks_at_the_nearest_existing_directory(self):
        seen = []
        self.s.kw["free_mb"] = lambda p: seen.append(p) or 100
        self.s.remove("opt")
        self.assertEqual(self.blockers(), ["space_low"])
        self.assertEqual(seen[-1], self.s.root)


class Warnings(unittest.TestCase):
    def setUp(self):
        self.s = Sim()

    def tearDown(self):
        self.s.tmp.cleanup()

    def test_an_untested_version_of_a_known_family_warns(self):
        self.s.write("etc/os-release", 'ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\n')
        self.assertEqual(self.s.codes("warning"), ["os_untested"])
        self.assertEqual(self.s.codes("blocker"), [])

    def test_no_landlock_warns_but_does_not_block(self):
        self.s.write("sys/kernel/security/lsm", "lockdown,capability,yama,apparmor")
        self.assertEqual((self.s.codes("warning"), self.s.codes("blocker")), (["landlock_off"], []))

    def test_old_systemd_is_info_unless_systemd_creds_is_wanted(self):
        self.s.systemd = "systemd 249 (249.11-0ubuntu3)"
        self.assertEqual(self.s.codes("info"), ["systemd_old"])
        opts = Opts()
        opts.protect = "systemd-creds"
        self.assertEqual(self.s.codes("warning", opts), ["systemd_old"])

    def test_other_vpns_are_noted(self):
        for n in ("wg0", "proton0", "eth0"):
            (self.s.root / "sys/class/net" / n).mkdir()
        [f] = [f for f in self.s.findings() if f.code == "other_vpns"]
        self.assertEqual((f.severity, f.detail["interfaces"]), ("info", ["proton0", "wg0"]))

    def test_a_crashing_check_is_reported_not_hidden(self):
        def broken(host, opts):
            raise RuntimeError("boom")

        pf.CHECKS.append(broken)
        try:
            self.assertIn("check_failed", self.s.codes("blocker"))
        finally:
            pf.CHECKS.remove(broken)


class PackageManagers(unittest.TestCase):
    def test_each_manager_gets_its_own_package_names(self):
        for pm, program, expect in (("dnf", "dnf", "sudo dnf install -y iproute nftables"),
                                    ("pacman", "pacman", "sudo pacman -S --needed iproute2 nftables"),
                                    ("zypper", "zypper", "sudo zypper install -y iproute2 nftables")):  # fmt: skip
            with self.subTest(pm=pm):
                s = Sim()
                s.remove("usr/bin/apt-get")
                s.program(program)
                s.remove("usr/bin/nft")
                s.remove("usr/bin/ip")
                self.assertEqual(pf.summary(s.host(), s.findings())["install"], expect)
                s.tmp.cleanup()

    def test_unknown_severities_are_refused(self):
        with self.assertRaises(ValueError):
            pf.Finding("x", "fatal", "x")


class OptionalChecks(unittest.TestCase):
    def test_provider_readiness_is_opt_in_and_uses_the_existing_contract(self):
        s = Sim()
        with patch("providers.readiness", return_value=(False, "not configured")) as readiness:
            self.assertTrue(pf.inspect_host(Opts(), s.host())["ready"])
            readiness.assert_not_called()
            opts = Opts()
            opts.provider = ["own"]
            opts.profile = None
            report = pf.inspect_host(opts, s.host())
            self.assertFalse(report["ready"])
            self.assertEqual(readiness.call_count, 1)
            self.assertIn("provider_not_ready", [f["code"] for f in report["findings"]])
        s.tmp.cleanup()

    def test_unknown_provider_cannot_be_reported_ready(self):
        s = Sim()
        opts = Opts()
        opts.provider = ["not-a-provider"]
        report = pf.inspect_host(opts, s.host())
        self.assertFalse(report["ready"])
        self.assertIn("check_failed", [f["code"] for f in report["findings"]])
        s.tmp.cleanup()


class PrivilegeBoundaries(unittest.TestCase):
    def test_provider_environment_overrides_never_run_under_root(self):
        s = Sim()
        opts = Opts()
        opts.provider = ["own"]
        opts.profile = None
        with patch("preflight.os.geteuid", return_value=0), patch("providers.readiness") as readiness:
            report = pf.inspect_host(opts, s.host())
        readiness.assert_not_called()
        self.assertFalse(report["ready"])
        self.assertIn("provider_user_required", [f["code"] for f in report["findings"]])
        s.tmp.cleanup()

    def test_systemd_version_check_uses_the_resolved_executable(self):
        s = Sim()
        host = s.host()
        calls = []
        host.run = lambda argv: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "systemd 257", "")
        pf.check_systemd(host, Opts())
        self.assertEqual(calls[0][0], str(s.root / "usr/bin/systemctl"))
        s.tmp.cleanup()


class PackageValidation(unittest.TestCase):
    def test_an_explicit_missing_or_empty_package_blocks_readiness(self):
        s = Sim()
        opts = Opts()
        opts.package = s.root / "missing"
        for create in (False, True):
            if create:
                opts.package.mkdir()
            report = pf.inspect_host(opts, s.host())
            self.assertFalse(report["ready"])
            self.assertIn("check_failed", [f["code"] for f in report["findings"]])
        s.tmp.cleanup()

    def test_staged_package_size_is_added_to_installation_margin(self):
        s = Sim()
        pkg = s.root / "package"
        pkg.mkdir()
        (pkg / "program").write_bytes(b"\x7fELFGLIBC_2.35\0")
        opts = Opts()
        opts.package = pkg
        s.kw["free_mb"] = lambda p: pf.NEED_MB
        report = pf.inspect_host(opts, s.host())
        space = next(f for f in report["findings"] if f["code"] == "space_low")
        self.assertEqual(space["detail"]["need_mb"], pf.NEED_MB + 1)
        self.assertFalse(report["ready"])
        s.tmp.cleanup()

    def test_root_does_not_resolve_a_program_from_the_callers_path(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "systemctl"
            p.write_text("#!/bin/sh\n")
            p.chmod(0o755)
            with patch("preflight.os.geteuid", return_value=0):
                host = pf.Host(path=temp)
                self.assertNotEqual(host.which("systemctl"), str(p))


class OperatorInstallation(unittest.TestCase):
    def test_cli_only_install_does_not_require_tun_nft_or_systemd(self):
        s = Sim()
        s.remove("dev/net/tun")
        s.remove("usr/bin/nft")
        s.remove("usr/bin/systemctl")
        opts = Opts()
        opts.operator_only = True
        self.assertTrue(pf.inspect_host(opts, s.host())["ready"])
        opts.operator_only = False
        self.assertFalse(pf.inspect_host(opts, s.host())["ready"])
        s.tmp.cleanup()


if __name__ == "__main__":
    unittest.main()

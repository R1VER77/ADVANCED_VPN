"""Native package metadata/lifecycle boundaries without installing or invoking root."""

import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import native_package as package
import test_bundled_runtime as runtime_tests


class NativePackages(unittest.TestCase):
    def setUp(self):
        self.fixture = runtime_tests.RuntimeManifest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root / "source"
        (self.root / "tools").mkdir(parents=True)
        (self.root / "tools/hardware-requirements.txt").write_bytes(self.fixture.lock.read_bytes())
        (self.root / "tools/install-offline.sh").write_text("#!/bin/sh\nexit 99\n")
        (self.root / "tools/install-offline.sh").chmod(0o755)
        (self.root / "target/release").mkdir(parents=True)
        (self.root / "target/release/avpn").write_text("test binary, never run")
        (self.root / "target/release/avpn").chmod(0o755)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "1.2.3"\n')
        (self.root / "LICENSE").write_text("fixture license")
        self.output = self.fixture.root / "output"
        self.output.mkdir(mode=0o755)
        for patcher in (
            mock.patch.object(package.install, "SOURCES", ["tools", "LICENSE"]),
            mock.patch.object(package.install, "BINARIES", ["avpn"]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_staged_payload_has_no_services_or_secret_state_and_only_fixed_aliases(self):
        tree = self.output / "root"
        payload = package.stage(self.root, self.fixture.bundle, tree)
        self.assertFalse((tree / "etc").exists())
        for name, target in package.COMMANDS.items():
            self.assertEqual(os.readlink(tree / "usr/bin" / name), "/opt/advanced-vpn/bin/" + target)
        package.bundled_runtime.verify(payload / "runtime", payload / "tools/hardware-requirements.txt")
        self.assertTrue((payload / "PACKAGE_CONTENTS.json").is_file())

    def test_bad_runtime_refused_before_any_staging(self):
        (self.fixture.bundle / "lib/dependency.py").write_text("corrupt")
        tree = self.output / "root"
        with self.assertRaises(ValueError):
            package.stage(self.root, self.fixture.bundle, tree)
        self.assertFalse(tree.exists())

    def test_version_cannot_inject_control_fields_or_script(self):
        for value in ("1.2.3$(id)", "1.2.3;exit", "1.2.3\\nDepends: shell", "$(whoami)"):
            (self.root / "Cargo.toml").write_text('[package]\nversion = "' + value + '"\n')
            with self.assertRaises(ValueError):
                package.version(self.root)
        with self.assertRaises(ValueError):
            package.rpm_spec("1.2.3-pre.1")

    def test_scripts_parse_without_execution_and_upgrade_never_runs_removal(self):
        for script in (package.preinstall(), package.configure(), package.remove(), package.remove(False)):
            subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)
        for script, argument in (
            (package.remove(), "upgrade"),
            (package.remove(False), "1"),
            (package.configure(), "abort-upgrade"),
        ):
            subprocess.run(["/bin/sh", "-c", script, "script", argument], check=True)
        recipe = package.rpm_spec("1.2.3")
        self.assertIn("%global __os_install_post %{nil}", recipe)
        self.assertIn("%defattr(-,root,root,-)", recipe)
        self.assertIn("%%u:%%a", recipe)

    @unittest.skipUnless(Path("/usr/bin/dpkg-deb").exists(), "dpkg-deb required for archive inspection")
    def test_deb_archive_can_be_inspected_without_running_its_scripts(self):
        built = package.debian(self.root, self.fixture.bundle, self.output, epoch=1_700_000_000)
        fields = subprocess.run(
            ["/usr/bin/dpkg-deb", "--field", str(built)], capture_output=True, text=True, check=True
        ).stdout
        self.assertIn("Package: cypherpunk-vpn", fields)
        self.assertIn("Version: 1.2.3-1", fields)
        self.assertNotIn("python3", fields)
        controls = self.output / "control"
        subprocess.run(["/usr/bin/dpkg-deb", "--control", str(built), str(controls)], check=True)
        self.assertEqual((controls / "postinst").read_text(), package.configure())
        self.assertEqual((controls / "prerm").read_text(), package.remove())
        with self.assertRaises(FileExistsError):
            package.debian(self.root, self.fixture.bundle, self.output, epoch=1_700_000_000)

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
        (self.root / "target/release/avpn").write_bytes(b"\x7fELF test ABI marker, never run GLIBC_2.35\x00")
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

    def test_newer_glibc_binary_cannot_be_mislabelled_as_the_release_baseline(self):
        (self.root / "target/release/avpn").write_bytes(b"\x7fELF test ABI marker, never run GLIBC_2.38\x00")
        with self.assertRaisesRegex(ValueError, "exceeds the declared release baseline"):
            package.debian(self.root, self.fixture.bundle, self.output, epoch=1_700_000_000)
        self.assertFalse(list(self.output.glob("*.deb")))

    def test_version_cannot_inject_control_fields_or_script(self):
        for value in ("1.2.3$(id)", "1.2.3;exit", "1.2.3\\nDepends: shell", "$(whoami)"):
            (self.root / "Cargo.toml").write_text('[package]\nversion = "' + value + '"\n')
            with self.assertRaises(ValueError):
                package.version(self.root)
        with self.assertRaises(ValueError):
            package.rpm_spec("1.2.3-pre.1")
        for value in ("1.2.3$(id)-1", "1.2.3'; rm -rf /", "1.2.3-2", ""):
            with self.assertRaises(ValueError):
                package.preinstall(value)
        for value in ("1.2.3$(id)", "1.2.3'; rm -rf /", "1.2.3-pre.1", "1.2"):
            with self.assertRaises(ValueError):
                package.preinstall(value, debian=False)

    def test_package_downgrades_are_refused_before_extraction(self):
        deb = "#!/bin/sh\nset -eu\n" + package.debian_upgrade_guard("1.2.3-1")
        for old, refused in (
            ("1.2.4-1", True),
            ("1.2.4~alpha.1-1", True),
            ("2.0.0-1", True),
            ("1.2.3-1", False),
            ("1.2.3~rc.1-1", False),
            ("1.2.2-1", False),
        ):
            with self.subTest(deb=old):
                script = subprocess.run(
                    ["/bin/sh", "-c", deb, "preinst", "upgrade", old], capture_output=True, text=True
                )
                self.assertEqual(bool(script.returncode), refused)
                if refused:
                    self.assertIn("Refusing package downgrade", script.stderr)
        for arguments in (("install",), ("install", "1.9.9-1"), ("abort-upgrade", "1.9.9-1")):
            with self.subTest(deb=arguments):
                subprocess.run(["/bin/sh", "-c", deb, "preinst", *arguments], check=True)

    def test_rpm_scriptlet_uses_the_installed_database_not_a_nonexistent_second_argument(self):
        script = package.preinstall("1.2.3", debian=False)
        self.assertIn("/usr/bin/rpm -q --qf", script)
        self.assertIn("rpm.vercmp", script)
        self.assertNotIn('"$2"', script)
        self.assertNotIn("rpm_part", script)
        subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)

    @unittest.skipUnless(Path("/usr/bin/rpm").exists(), "native RPM required for EVR compatibility")
    def test_native_rpm_epoch_version_release_ordering(self):
        for old, expected in (
            ("0\t1.2.4\t1", "newer"),
            ("1\t1.0.0\t1", "newer"),
            ("0\t1.2.3\t2", "newer"),
            ("0\t1.2.3\t1", "allowed"),
            ("0\t1.2.3~rc1\t1", "allowed"),
            ("0\t1.2.2\t999", "allowed"),
            ("0\t1.2.3^git1\t1", "newer"),
            ("0\t1.2.10\t1", "newer"),
            ("0\t1.2\t999", "allowed"),
            ("unparseable", "invalid"),
            ("", "invalid"),
            ("0\t1.2.2\t1\n1\t1.0\t1", "newer"),
        ):
            with self.subTest(installed=old):
                result = subprocess.run(
                    ["/usr/bin/rpm", "--eval", package.rpm_compare_expression()],
                    env=dict(os.environ, CYPHERPUNK_RPM_INSTALLED=old, CYPHERPUNK_RPM_TARGET="1.2.3"),
                    check=True,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.stdout.strip(), expected)

    def test_scripts_parse_without_execution_and_upgrade_never_runs_removal(self):
        for script in (
            package.preinstall("1.2.3-1"),
            package.preinstall("1.2.3", debian=False),
            package.configure(),
            package.remove(),
            package.remove(False),
        ):
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
        # The RPM scriptlet must not depend on dpkg; its %pre guard is shell-only.
        self.assertNotIn("dpkg", recipe)
        self.assertIn("rpm.vercmp", recipe)

    def run_configure(self, installer_status, controller_active, argument="configure"):
        """Run the real postinst against a stand-in installer and systemctl; return the calls."""
        bin_dir = self.fixture.root / "postinst"
        bin_dir.mkdir(exist_ok=True)
        log = bin_dir / "calls"
        log.write_text("")
        (bin_dir / "install.sh").write_text('#!/bin/sh\necho "install $*" >> %s\nexit %d\n' % (log, installer_status))
        (bin_dir / "systemctl").write_text(
            '#!/bin/sh\necho "systemctl $*" >> %s\n[ "$1" != is-active ] || exit %d\n'
            % (log, 0 if controller_active else 3)
        )
        for name in ("install.sh", "systemctl"):
            (bin_dir / name).chmod(0o755)
        script = (
            package.configure()
            .replace(package.PAYLOAD, str(bin_dir))
            .replace(package.SYSTEMCTL, str(bin_dir / "systemctl"))
        )
        result = subprocess.run(["/bin/sh", "-c", script, "postinst", argument], capture_output=True, text=True)
        return result.returncode, log.read_text().splitlines()

    def test_upgrade_stops_a_running_controller_only_after_the_new_install_succeeds(self):
        code, calls = self.run_configure(0, controller_active=True)
        self.assertEqual(code, 0)
        self.assertEqual(calls[0], "install --apply --package-managed")
        self.assertEqual(calls[-1], "systemctl stop " + package.CONTROLLER_UNIT)
        self.assertFalse(any(" start " in c or " restart" in c or "enable" in c for c in calls))
        # Not running: nothing is stopped and nothing is started.
        self.assertNotIn("systemctl stop " + package.CONTROLLER_UNIT, self.run_configure(0, controller_active=False)[1])
        # A failed install leaves the running controller (and its old slot) alone.
        code, calls = self.run_configure(1, controller_active=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, ["install --apply --package-managed"])
        self.assertEqual(self.run_configure(0, True, "abort-upgrade"), (0, []))

    def gui_fixture(self, marker=b"GLIBC_2.35"):
        icon = self.root / package.GUI_ICON
        icon.parent.mkdir(parents=True, exist_ok=True)
        icon.write_bytes(b"\x89PNG fixture icon")
        gui = self.fixture.root / "cypherpunk-vpn-gui"
        gui.write_bytes(b"\x7fELF desktop app fixture, never run " + marker + b"\x00")
        gui.chmod(0o755)
        return gui

    def test_desktop_app_is_staged_unprivileged_with_its_launcher(self):
        tree = self.output / "root"
        package.stage(self.root, self.fixture.bundle, tree, self.gui_fixture())
        app = tree / package.GUI.lstrip("/")
        self.assertTrue(app.read_bytes().startswith(b"\x7fELF"))
        self.assertEqual(app.stat().st_mode & 0o7777, 0o755)
        self.assertEqual(os.readlink(tree / "usr/bin/cypherpunk-vpn-gui"), package.GUI)
        entry = (tree / "usr/share/applications/cypherpunk-vpn.desktop").read_text()
        self.assertIn("Exec=cypherpunk-vpn-gui\n", entry)
        self.assertIn("Terminal=false\n", entry)
        self.assertNotIn("pkexec", entry)
        self.assertNotIn("sudo", entry)
        self.assertTrue((tree / "usr/share/icons/hicolor/128x128/apps/cypherpunk-vpn.png").is_file())
        # Nothing setuid, and no privileged file appears outside the reviewed payload.
        for path in tree.rglob("*"):
            if not path.is_symlink():
                self.assertFalse(path.stat().st_mode & 0o6000, path)
        self.assertFalse((tree / "etc").exists())

    def test_without_the_desktop_app_nothing_of_it_is_staged(self):
        tree = self.output / "root"
        package.stage(self.root, self.fixture.bundle, tree)
        self.assertFalse((tree / "usr/share").exists())
        self.assertFalse((tree / "usr/bin/cypherpunk-vpn-gui").exists())

    def test_desktop_app_built_on_a_newer_glibc_is_refused(self):
        tree = self.output / "root"
        with self.assertRaisesRegex(ValueError, "desktop app ABI 2.38 exceeds the declared release baseline"):
            package.stage(self.root, self.fixture.bundle, tree, self.gui_fixture(b"GLIBC_2.38"))

    def test_desktop_app_must_be_a_regular_elf_file(self):
        gui = self.gui_fixture()
        gui.write_bytes(b"#!/bin/sh\nexec id\n")
        with self.assertRaisesRegex(ValueError, "not an ELF"):
            package.stage(self.root, self.fixture.bundle, self.output / "a", gui)
        link = self.fixture.root / "gui-link"
        link.symlink_to("/bin/true")
        with self.assertRaisesRegex(ValueError, "regular file"):
            package.stage(self.root, self.fixture.bundle, self.output / "b", link)

    def test_rpm_recipe_lists_the_desktop_app_only_when_shipped(self):
        plain, with_gui = package.rpm_spec("1.2.3"), package.rpm_spec("1.2.3", True)
        self.assertNotIn("webkit2gtk", plain)
        self.assertNotIn("cypherpunk-vpn.desktop", plain)
        self.assertIn(package.GUI_RPM_REQUIRES, with_gui)
        self.assertIn("/usr/bin/cypherpunk-vpn-gui\n", with_gui)
        self.assertIn("/usr/share/applications/cypherpunk-vpn.desktop\n", with_gui)

    @unittest.skipUnless(Path("/usr/bin/dpkg-deb").exists(), "dpkg-deb required for archive inspection")
    def test_deb_with_the_desktop_app_depends_on_webkit_and_owns_its_files(self):
        built = package.debian(self.root, self.fixture.bundle, self.output, epoch=1_700_000_000, gui=self.gui_fixture())
        depends = subprocess.run(
            ["/usr/bin/dpkg-deb", "--field", str(built), "Depends"], capture_output=True, text=True, check=True
        ).stdout
        self.assertIn(package.GUI_DEB_DEPENDS, depends)
        listing = subprocess.run(
            ["/usr/bin/dpkg-deb", "--contents", str(built)], capture_output=True, text=True, check=True
        ).stdout
        self.assertIn("." + package.GUI, listing)
        self.assertIn("./usr/share/applications/cypherpunk-vpn.desktop", listing)
        self.assertIn("./usr/bin/cypherpunk-vpn-gui -> " + package.GUI, listing)

    @unittest.skipUnless(Path("/usr/bin/dpkg-deb").exists(), "dpkg-deb required for archive inspection")
    def test_deb_archive_can_be_inspected_without_running_its_scripts(self):
        built = package.debian(self.root, self.fixture.bundle, self.output, epoch=1_700_000_000)
        fields = subprocess.run(
            ["/usr/bin/dpkg-deb", "--field", str(built)], capture_output=True, text=True, check=True
        ).stdout
        self.assertIn("Package: cypherpunk-vpn", fields)
        self.assertIn("Version: 1.2.3-1", fields)
        self.assertNotIn("python3", fields)
        self.assertNotIn("webkit", fields)
        controls = self.output / "control"
        subprocess.run(["/usr/bin/dpkg-deb", "--control", str(built), str(controls)], check=True)
        self.assertEqual((controls / "postinst").read_text(), package.configure())
        self.assertEqual((controls / "prerm").read_text(), package.remove())
        self.assertEqual((controls / "preinst").read_text(), package.preinstall("1.2.3-1"))
        with self.assertRaises(FileExistsError):
            package.debian(self.root, self.fixture.bundle, self.output, epoch=1_700_000_000)

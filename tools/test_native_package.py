"""Native package metadata/lifecycle boundaries without installing or invoking root."""

import os
from pathlib import Path
import re
import subprocess
import unittest
from unittest import mock

import native_package as package
import test_bundled_runtime as runtime_tests

ROOT = Path(__file__).resolve().parents[1]


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
        (self.root / "target/release/cypherpunk").write_bytes(b"\x7fELF test ABI marker, never run GLIBC_2.35\x00")
        (self.root / "target/release/cypherpunk").chmod(0o755)
        (self.root / "Cargo.toml").write_text('[package]\nversion = "1.2.3"\n')
        (self.root / "LICENSE").write_text("fixture license")
        self.output = self.fixture.root / "output"
        self.output.mkdir(mode=0o755)
        for patcher in (
            mock.patch.object(package.install, "SOURCES", ["tools", "LICENSE"]),
            mock.patch.object(package.install, "BINARIES", ["cypherpunk"]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_staged_payload_has_no_services_or_secret_state_and_only_fixed_aliases(self):
        tree = self.output / "root"
        payload = package.stage(self.root, self.fixture.bundle, tree)
        self.assertFalse((tree / "etc").exists())
        for name, target in package.COMMANDS.items():
            self.assertEqual(os.readlink(tree / "usr/bin" / name), "/opt/cypherpunk-vpn/bin/" + target)
        package.bundled_runtime.verify(payload / "runtime", payload / "tools/hardware-requirements.txt")
        self.assertTrue((payload / "PACKAGE_CONTENTS.json").is_file())

    def test_bad_runtime_refused_before_any_staging(self):
        (self.fixture.bundle / "lib/dependency.py").write_text("corrupt")
        tree = self.output / "root"
        with self.assertRaises(ValueError):
            package.stage(self.root, self.fixture.bundle, tree)
        self.assertFalse(tree.exists())

    def test_newer_glibc_binary_cannot_be_mislabelled_as_the_release_baseline(self):
        (self.root / "target/release/cypherpunk").write_bytes(b"\x7fELF test ABI marker, never run GLIBC_2.38\x00")
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
        script = self.sandboxed(package.configure(), bin_dir)
        result = subprocess.run(["/bin/sh", "-c", script, "postinst", argument], capture_output=True, text=True)
        return result.returncode, log.read_text().splitlines()

    def sandboxed(self, script, bin_dir):
        """Point a package script's paths into the fixture, and prove it deletes nothing outside.

        On 22 Nov 2026 the postinst's removal of the pre-rename install ran
        `rm -rf` on the pre-rename install directory of the machine running these tests.
        """
        host = self.fixture.root / "host"
        script = (
            script.replace(package.PAYLOAD, str(bin_dir))
            .replace(package.SYSTEMCTL, str(bin_dir / "systemctl"))
            .replace(package.NFT, str(bin_dir / "nft"))
            .replace(package.LEGACY_ROOT, str(host) + package.LEGACY_ROOT)
            .replace(package.SYSTEMD_UNITS, str(host) + package.SYSTEMD_UNITS)
            .replace("/usr/bin/avpn", str(host) + "/usr/bin/avpn")
        )
        for line in script.splitlines():
            if re.search(r"\brm\s+-", line):
                for target in re.findall(r"(?<![\w$\"])(/[\w./*-]+)", line.split("rm", 1)[1]):
                    self.assertTrue(target.startswith(str(self.fixture.root)), "unsandboxed delete: " + target)
        return script

    def stand_ins(self, active=(), table=False):
        """systemctl and nft stand-ins: which old units are active, whether the old table is loaded."""
        bin_dir = self.fixture.root / "legacy-bin"
        bin_dir.mkdir(exist_ok=True)
        log = bin_dir / "calls"
        log.write_text("")
        (bin_dir / "systemctl").write_text(
            '#!/bin/sh\necho "systemctl $*" >> %s\nif [ "$1" = is-active ]; then\n  case " %s " in *" $3 "*) exit 0;; esac\n'
            "  exit 3\nfi\nexit 0\n" % (log, " ".join(active))
        )
        (bin_dir / "nft").write_text('#!/bin/sh\necho "nft $*" >> %s\nexit %d\n' % (log, 0 if table else 1))
        for name in ("systemctl", "nft"):
            (bin_dir / name).chmod(0o755)
        return bin_dir, log

    def run_legacy_guard(self, **kw):
        bin_dir, log = self.stand_ins(**kw)
        script = "#!/bin/sh\nset -eu\n" + self.sandboxed(package.legacy_running_guard(), bin_dir)
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
        return r.returncode, r.stderr

    def test_an_upgrade_over_a_running_old_vpn_is_refused_with_how_to_stop_it(self):
        for unit in package.LEGACY_UNITS:
            with self.subTest(unit=unit):
                code, err = self.run_legacy_guard(active=(unit,))
                self.assertNotEqual(code, 0)
                self.assertIn("previous version's " + unit + " is running", err)
                self.assertIn("sudo systemctl stop " + " ".join(package.LEGACY_UNITS), err)
        code, err = self.run_legacy_guard(table=True)
        self.assertNotEqual(code, 0)
        self.assertIn("sudo nft delete table " + package.LEGACY_TABLE, err)
        self.assertEqual(self.run_legacy_guard(), (0, ""))  # nothing old running: no refusal
        # Both package formats refuse before extraction.
        for script in (package.preinstall("1.2.3-1"), package.preinstall("1.2.3", debian=False)):
            self.assertIn(package.legacy_running_guard(), script)

    def test_a_stopped_old_install_is_removed_and_the_owner_told(self):
        bin_dir, log = self.stand_ins()
        host = self.fixture.root / "host"
        old = host / package.LEGACY_ROOT.lstrip("/")
        (old / "bin").mkdir(parents=True)
        units = host / package.SYSTEMD_UNITS.lstrip("/")
        units.mkdir(parents=True)
        (units / "advanced-vpn.service").write_text("")
        (units / "other.service").write_text("")
        script = "#!/bin/sh\nset -eu\n" + self.sandboxed(package.legacy_cleanup(), bin_dir)
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(old.exists())
        self.assertFalse((units / "advanced-vpn.service").exists())
        self.assertTrue((units / "other.service").exists())
        self.assertIn("systemctl disable " + " ".join(package.LEGACY_UNITS), log.read_text())
        self.assertIn("Removed the previous version", r.stderr)
        # Without an old install it does nothing and says nothing.
        log.write_text("")
        r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr, log.read_text()), (0, "", ""))

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

    def assistant_fixture(self, marker=b"GLIBC_2.35"):
        model = self.fixture.root / "gemma-3-1b-it-Q8_0.gguf"
        model.write_bytes(b"GGUF fixture model")
        server = self.fixture.root / "llama-server"
        server.write_bytes(b"\x7fELF assistant server fixture, never run " + marker + b"\x00")
        server.chmod(0o755)
        return model, server

    def test_the_assistant_package_ships_only_the_pinned_model_with_gemmas_terms(self):
        import assistant

        model, server = self.assistant_fixture()
        tree = self.fixture.root / "assistant-tree"
        with self.assertRaisesRegex(ValueError, "not the pinned Gemma file"):
            package.stage_assistant(ROOT, model, server, tree)
        digest = __import__("hashlib").sha256(model.read_bytes()).hexdigest()
        with mock.patch.object(assistant, "MODEL_SHA256", digest):
            package.stage_assistant(ROOT, model, server, tree)
        home = tree / package.ASSISTANT_HOME.lstrip("/")
        self.assertEqual(sorted(x.name for x in home.iterdir()),
                         ["gemma-3-1b-it-Q8_0.gguf", "gemma-3-1b-it-Q8_0.gguf.sha256", "llama-server"])  # fmt: skip
        self.assertEqual((home / "gemma-3-1b-it-Q8_0.gguf.sha256").read_text().split()[0], digest)
        self.assertEqual(os.stat(home / "llama-server").st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(home / package.ASSISTANT_MODEL).st_mode & 0o777, 0o644)
        docs = tree / "usr/share/doc" / package.ASSISTANT_PACKAGE
        notice = "Gemma is provided under and subject to the Gemma Terms of Use found at gemma.ai/resources/terms"
        self.assertIn(notice, (docs / "NOTICE").read_text())
        self.assertIn(notice, (docs / "copyright").read_text())
        for name in ("GEMMA_TERMS_OF_USE.md", "GEMMA_PROHIBITED_USE_POLICY.md"):
            self.assertTrue((docs / name).is_file(), name)
        # Nothing setuid, nothing outside its own folders.
        for path in tree.rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o6000, path)
        self.assertEqual(sorted(x.name for x in (tree / "usr").iterdir()), ["lib", "share"])

    def test_an_assistant_server_that_is_not_an_elf_or_too_new_is_refused(self):
        import assistant

        model, server = self.assistant_fixture()
        digest = __import__("hashlib").sha256(model.read_bytes()).hexdigest()
        with mock.patch.object(assistant, "MODEL_SHA256", digest):
            server.write_bytes(b"#!/bin/sh\n")
            with self.assertRaisesRegex(ValueError, "not an ELF"):
                package.stage_assistant(ROOT, model, server, self.fixture.root / "t1")
            _, server = self.assistant_fixture(marker=b"GLIBC_2.39")
            with self.assertRaisesRegex(ValueError, "exceeds the release baseline"):
                package.stage_assistant(ROOT, model, server, self.fixture.root / "t2")

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
        recommends = subprocess.run(
            ["/usr/bin/dpkg-deb", "--field", str(built), "Recommends"], capture_output=True, text=True, check=True
        ).stdout.strip()
        self.assertEqual(recommends, package.ASSISTANT_PACKAGE)  # the app suggests its local assistant
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

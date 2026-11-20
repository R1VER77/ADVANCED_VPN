"""Offline runtime integrity boundaries and transactional installation without pip/network."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import bundled_runtime as runtime
import install


class RuntimeManifest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = self.root / "requirements.txt"
        self.lock.write_text("reviewed lock\n")
        self.bundle = self.root / "runtime"
        (self.bundle / "bin").mkdir(parents=True)
        (self.bundle / "bin/python3.13").write_text("test executable, never executed\n")
        (self.bundle / "bin/python3.13").chmod(0o755)
        (self.bundle / "bin/python3").symlink_to("python3.13")
        (self.bundle / "lib").mkdir()
        (self.bundle / "lib/dependency.py").write_text("test package\n")
        for path in [self.bundle, *self.bundle.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.parent.name == "bin" else 0o644)
        self.manifest()

    def manifest(self, **overrides):
        platform_name, _, archive_sha256 = runtime.pin()
        m = dict(schema=1, python=runtime.VERSION, platform=platform_name,
                 archive_sha256=archive_sha256, requirements_sha256=runtime.sha256(self.lock),
                 entries=runtime.inventory(self.bundle))  # fmt: skip
        m.update(overrides)
        (self.bundle / runtime.MANIFEST).write_text(json.dumps(m))
        (self.bundle / runtime.MANIFEST).chmod(0o644)

    def test_complete_runtime_and_internal_symlinks_are_verified_without_execution(self):
        with mock.patch.object(runtime.subprocess, "run", side_effect=AssertionError("executed runtime")):
            result = runtime.verify(self.bundle, self.lock)
        self.assertEqual(result["entries"]["bin/python3"]["target"], "python3.13")

    def test_corruption_missing_files_and_extra_code_are_all_refused(self):
        dependency = self.bundle / "lib/dependency.py"
        original = dependency.read_bytes()
        dependency.write_bytes(b"changed code")
        with self.assertRaisesRegex(ValueError, "differ"):
            runtime.verify(self.bundle, self.lock)
        dependency.unlink()
        with self.assertRaisesRegex(ValueError, "differ"):
            runtime.verify(self.bundle, self.lock)
        dependency.write_bytes(original)
        dependency.chmod(0o644)
        (self.bundle / "lib/injected.py").write_text("unlisted code")
        (self.bundle / "lib/injected.py").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "differ"):
            runtime.verify(self.bundle, self.lock)

    def test_wrong_lock_or_upstream_pin_cannot_reuse_a_runtime(self):
        self.lock.write_text("different lock")
        with self.assertRaisesRegex(ValueError, "dependency lock"):
            runtime.verify(self.bundle, self.lock)
        self.manifest(archive_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "reviewed pin"):
            runtime.verify(self.bundle, self.lock)

    def test_escaping_broken_and_absolute_symlinks_are_refused(self):
        link = self.bundle / "bin/escape"
        for target in ("../../requirements.txt", "/usr/bin/python3", "does-not-exist", "escape"):
            link.symlink_to(target)
            with self.assertRaises((ValueError, RuntimeError)):
                runtime.inventory(self.bundle)
            link.unlink()

    def test_special_files_and_writable_or_setid_code_are_refused(self):
        f = self.bundle / "lib/dependency.py"
        for mode in (0o666, 0o4775):
            f.chmod(mode)
            with self.assertRaisesRegex(ValueError, "permissions"):
                runtime.verify(self.bundle, self.lock)
        f.chmod(0o644)
        os.mkfifo(self.bundle / "fifo")
        with self.assertRaisesRegex(ValueError, "special file"):
            runtime.inventory(self.bundle)

    def test_each_processor_has_its_own_pin_and_a_bundle_is_not_another_processors(self):
        self.assertEqual(set(runtime.PINS), {"x86_64", "aarch64"})
        self.assertEqual(runtime.PINS["x86_64"][1:], (runtime.ARCHIVE_URL, runtime.ARCHIVE_SHA256))
        with self.assertRaisesRegex(RuntimeError, "no reviewed runtime pin"):
            runtime.pin("riscv64")
        other = next(m for m in runtime.PINS if m != runtime.platform.machine())
        name, _, sha = runtime.PINS[other]
        self.manifest(platform=name, archive_sha256=sha)
        with self.assertRaisesRegex(ValueError, "reviewed pin"):
            runtime.verify(self.bundle, self.lock)

    def test_bad_archive_is_rejected_before_extraction_or_execution(self):
        archive = self.root / "bad.tar.gz"
        archive.write_bytes(b"wrong download")
        out = self.root / "new-runtime"
        with mock.patch.object(runtime.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                runtime.build(archive, out, self.lock)
        self.assertFalse(out.exists())

    def test_system_install_uses_bundle_offline_and_does_not_reuse_old_venv(self):
        package = self.root / "package"
        (package / "bin").mkdir(parents=True)
        (package / "tools").mkdir(parents=True)
        (package / "tools/hardware-requirements.txt").write_bytes(self.lock.read_bytes())
        self.bundle.rename(package / "venv")
        target = self.root / "installed"
        (target / "venv").mkdir(parents=True)
        (target / "venv/old-runtime").write_text("old environment")
        target.chmod(0o755)
        with (
            mock.patch.object(install.os, "chown"),
            mock.patch.object(install, "check_application"),
            mock.patch.object(install.subprocess, "run", side_effect=AssertionError("pip/network during install")),
        ):
            self.assertTrue(install.install_system(package, target, adopt_legacy=True))
        self.assertFalse((target / "venv/old-runtime").exists())
        runtime.verify((target / "venv").resolve(), target / "tools/hardware-requirements.txt")
        self.assertTrue((target / "venv/bin/python3").is_symlink())

    def test_invalid_bundle_preserves_previous_installation(self):
        package = self.root / "package"
        (package / "tools").mkdir(parents=True)
        (package / "tools/hardware-requirements.txt").write_bytes(self.lock.read_bytes())
        self.bundle.rename(package / "venv")
        (package / "venv/lib/dependency.py").write_text("corrupt")
        target = self.root / "installed"
        target.mkdir()
        (target / "preserve").write_text("previous working installation")
        with mock.patch.object(install.os, "chown", side_effect=AssertionError("write before verification")):
            with self.assertRaisesRegex(ValueError, "differ"):
                install.install_system(package, target)
        self.assertEqual((target / "preserve").read_text(), "previous working installation")
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["preserve"])
        self.assertFalse(list(self.root.glob("installed.new-*")))

    def test_final_swap_failure_restores_the_previous_system_runtime(self):
        package = self.root / "package"
        (package / "bin").mkdir(parents=True)
        (package / "tools").mkdir(parents=True)
        (package / "tools/hardware-requirements.txt").write_bytes(self.lock.read_bytes())
        self.bundle.rename(package / "venv")
        target = self.root / "installed"
        with mock.patch.object(install.os, "chown"), mock.patch.object(install, "check_application"):
            install.install_system(package, target)
        previous = (target / "venv").resolve()
        before = (previous / "lib/dependency.py").read_bytes()
        replace = os.replace

        def refuse_stage(path, destination):
            if Path(destination).name == "current":
                raise OSError("injected final rename failure")
            return replace(path, destination)

        with (
            mock.patch.object(install.os, "chown"),
            mock.patch.object(os, "replace", refuse_stage),
            mock.patch.object(install, "check_application"),
        ):
            with self.assertRaisesRegex(OSError, "final rename"):
                install.install_system(package, target)
        self.assertEqual((target / "venv").resolve(), previous)
        self.assertEqual((previous / "lib/dependency.py").read_bytes(), before)
        self.assertFalse(list((target / "releases").glob(".prepare-*")))

    def test_label_failure_never_publishes_the_new_system_slot(self):
        package = self.root / "package"
        (package / "bin").mkdir(parents=True)
        (package / "tools").mkdir(parents=True)
        (package / "tools/hardware-requirements.txt").write_bytes(self.lock.read_bytes())
        self.bundle.rename(package / "venv")
        target = self.root / "installed"
        with mock.patch.object(install.os, "chown"), mock.patch.object(install, "check_application"):
            install.install_system(package, target)
        previous = (target / "current").resolve()

        def cannot_label(slot):
            self.assertEqual(slot.parent, target / "releases")
            self.assertTrue(slot.is_dir())
            self.assertNotEqual(slot, previous)
            self.assertEqual((target / "current").resolve(), previous)
            raise PermissionError("host file-context restoration failed")

        with (
            mock.patch.object(install.os, "chown"),
            mock.patch.object(install, "label_system_slot", side_effect=cannot_label),
            mock.patch.object(install, "check_application") as application_check,
        ):
            with self.assertRaisesRegex(PermissionError, "file-context"):
                install.install_system(package, target)
            application_check.assert_not_called()
        self.assertEqual((target / "current").resolve(), previous)
        runtime.verify(previous / "venv", package / "tools/hardware-requirements.txt")


if __name__ == "__main__":
    unittest.main()

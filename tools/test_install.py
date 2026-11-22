"""User installation and release packaging (`install.py --user` / `--pack`)."""

import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import install

BUILT = all((install.ROOT / "target/release" / b).is_file() for b in install.BINARIES)


class Launchers(unittest.TestCase):
    def test_a_launcher_called_through_a_symlink_elsewhere_finds_its_own_slot(self):
        # /usr/local/bin/avpnctl is a symlink to /opt/advanced-vpn/bin/avpnctl: the launcher
        # must resolve itself, or it looks for /usr/local/venv (found on 20 November 2026).
        with tempfile.TemporaryDirectory() as d:
            slot, elsewhere = Path(d) / "releases" / "slot", Path(d) / "usr-local-bin"
            (slot / "bin").mkdir(parents=True)
            (slot / "tools").mkdir()
            elsewhere.mkdir()
            (slot / "tools/avpnctl.py").write_text("import sys; print('SLOT', sys.argv[1:])\n")
            install.write_tool_launchers(slot, python=sys.executable)
            (elsewhere / "avpnctl").symlink_to(slot / "bin/avpnctl")
            r = subprocess.run([str(elsewhere / "avpnctl"), "status"], capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "SLOT ['--bin-dir', '%s', 'status']" % (slot.resolve() / "bin"))


@unittest.skipUnless(BUILT, "build the release binaries first")
class UserInstallTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0 and self._testMethodName not in (
            "test_root_is_refused",
            "test_pack_holds_exactly_the_package",
        ):
            self.skipTest("--user refuses root by design")
        self.tmp = tempfile.TemporaryDirectory()
        # A space in every path proves the launchers quote what they exec.
        self.home = Path(self.tmp.name) / "home dir"
        self.data, self.bin = self.home / "data dir" / "advanced-vpn", self.home / ".local" / "bin"
        self.data.parent.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def install(self):
        # The test interpreter already holds the hash-locked dependencies, so no venv is built.
        return install.install_user(self.data, self.bin, python=sys.executable)

    def avpn(self, *args):
        env = dict(os.environ, HOME=str(self.home))
        env.pop("AVPN_CONTROLLER", None)
        return subprocess.run([str(self.bin / "avpn"), *args], capture_output=True, text=True, env=env, timeout=60)

    def test_installs_a_working_command_line(self):
        app = self.install()
        for b in install.BINARIES + ["avpnctl", "avpn-cloud", "avpn-mesh", "avpn-desktop"]:
            self.assertTrue(os.access(app / "bin" / b, os.X_OK), b)
        self.assertTrue((app / "docs/cli/overview.md").exists())
        self.assertFalse(list(app.rglob("__pycache__")))
        r = self.avpn("--version")
        version = re.search(r'^version = "([^"]+)"', (install.ROOT / "Cargo.toml").read_text(), re.M).group(1)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "avpn " + version))
        alias = subprocess.run([str(self.bin / "cypherpunk"), "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(alias.stdout, r.stdout)
        # End to end through the installed controller: JSON from a real (empty) state.
        r = self.avpn("--json", "--state", str(self.home / "no-state"), "hops")
        self.assertEqual(json.loads(r.stdout)["chain"], [], r.stderr)
        self.assertIn("• Chain  not enrolled", self.avpn("--state", str(self.home / "no-state"), "hops").stdout)
        # docs/NAME_MIGRATION.md: the new name drives the same controller, with the same JSON.
        env = dict(os.environ, HOME=str(self.home))
        env.pop("AVPN_CONTROLLER", None)
        for args in (
            ["--json", "--state", str(self.home / "no-state"), "hops"],
            ["--state", str(self.home / "no-state"), "hops"],
        ):
            new = subprocess.run(
                [str(self.bin / "cypherpunk"), *args], capture_output=True, text=True, env=env, timeout=60
            )
            self.assertEqual((new.returncode, new.stdout), (0, self.avpn(*args).stdout), new.stderr)

    def assert_no_preparation_leftovers(self):
        self.assertFalse(list((self.data / "releases").glob(".prepare-*")))
        self.assertFalse(list(self.data.glob(".current-*")))

    def test_a_pending_pointer_left_by_a_kill_is_swept_by_the_next_run(self):
        # Deterministic form of the window the kill test hits only sometimes (aarch64 CI,
        # 21 Nov 2026): killed between creating `.current-<hex>` and renaming it.
        self.install()
        stale = self.data / (".current-" + "ab" * 16)
        stale.symlink_to("releases/nonexistent")
        decoy = self.data / ".current-notours"  # another name: left alone
        decoy.symlink_to("x")
        self.install()
        self.assertFalse(stale.is_symlink())
        self.assertTrue(decoy.is_symlink())
        decoy.unlink()
        self.assert_no_preparation_leftovers()

    def test_upgrade_retains_the_previous_verified_slot(self):
        self.install()
        previous = (self.data / "app").resolve()
        self.install()
        self.assertTrue(previous.exists())
        self.assertNotEqual(previous, (self.data / "app").resolve())
        self.assertEqual(len(list((self.data / "releases").iterdir())), 2)
        self.assert_no_preparation_leftovers()
        self.assertEqual(self.avpn("--version").returncode, 0)

    def test_swap_failure_restores_the_previous_application(self):
        app = self.install()
        before = (app / "bin/avpnctl").read_bytes()
        replace = os.replace

        def refuse_stage(path, destination):
            if Path(destination).name == "current":
                raise OSError("injected final rename failure")
            return replace(path, destination)

        with mock.patch.object(os, "replace", refuse_stage):
            with self.assertRaisesRegex(OSError, "final rename"):
                self.install()
        self.assertEqual((app / "bin/avpnctl").read_bytes(), before)
        self.assert_no_preparation_leftovers()
        self.assertEqual(self.avpn("--version").returncode, 0)

    def test_failed_dependency_upgrade_preserves_the_old_runtime(self):
        app = self.install()
        venv = app / "venv"
        venv.mkdir()
        (venv / ".advanced-vpn-requirements.sha256").write_text("previous lock")
        (venv / "preserve").write_text("previous working runtime")
        with mock.patch.object(install.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "pip")):
            with self.assertRaises(subprocess.CalledProcessError):
                install.install_user(self.data, self.bin)
        self.assertEqual((venv / "preserve").read_text(), "previous working runtime")
        self.assert_no_preparation_leftovers()

    def test_an_upgrade_killed_at_any_point_leaves_a_working_command_and_reruns_cleanly(self):
        # Interrupted upgrades (docs/ROADMAP.md): SIGKILL, as a power cut would, at points
        # spread over a whole upgrade. After each, the command still works (old release or
        # new, never a broken one), and a plain re-run completes and leaves nothing behind.
        import signal
        import time

        self.install()
        here = str(Path(install.__file__).resolve().parent)
        run = [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; sys.path.insert(0, %r); import install; "
            "install.install_user(Path(%r), Path(%r), python=sys.executable)" % (here, str(self.data), str(self.bin)),
        ]
        start = time.monotonic()
        subprocess.run(run, check=True, capture_output=True, timeout=300)
        duration = time.monotonic() - start
        for k in range(1, 13):
            p = subprocess.Popen(run, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(duration * k / 13)
            p.send_signal(signal.SIGKILL)
            p.wait()
            with self.subTest(killed_at="%d/13" % k):
                self.assertEqual(self.avpn("--version").returncode, 0)
        self.install()
        self.assert_no_preparation_leftovers()
        self.assertEqual(self.avpn("--version").returncode, 0)

    def test_failed_install_leaves_the_old_one_and_no_leftovers(self):
        self.install()
        before = (self.data / "app" / "bin" / "avpnctl").read_text()

        def network_down(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0])

        with mock.patch.object(install.subprocess, "run", network_down):
            with self.assertRaises(subprocess.CalledProcessError):
                install.install_user(self.data, self.bin)  # needs a venv build, which fails
        self.assert_no_preparation_leftovers()
        self.assertEqual((self.data / "app" / "bin" / "avpnctl").read_text(), before)
        self.assertEqual(self.avpn("--version").returncode, 0)

    def test_user_wrapper_exports_the_mesh_tool(self):
        app = self.install()
        wrapper = (self.bin / "avpn").read_text()
        self.assertIn("AVPN_MESH=", wrapper)
        self.assertIn('AVPN_MESH="$slot/bin/avpn-mesh"', wrapper)
        self.assertIn(str(app), wrapper)
        mesh_launcher = (app / "bin" / "avpn-mesh").read_text()
        self.assertIn("tools/mesh.py", mesh_launcher)

    def test_root_is_refused(self):
        with mock.patch.object(install.os, "geteuid", lambda: 0):
            with self.assertRaisesRegex(RuntimeError, "normal user"):
                self.install()

    def test_uninstall_removes_only_the_installation(self):
        self.install()
        config = self.home / ".config" / "advanced-vpn"
        config.mkdir(parents=True)
        (config / "cloud.json").write_text("{}")
        install.uninstall_user(self.data, self.bin)
        self.assertFalse((self.bin / "avpn").exists())
        self.assertFalse((self.data / "app").exists())
        self.assertTrue((config / "cloud.json").exists())

    def test_uninstall_leaves_a_foreign_avpn_alone(self):
        self.bin.mkdir(parents=True)
        (self.bin / "avpn").write_text("#!/bin/sh\necho someone else's avpn\n")
        install.uninstall_user(self.data, self.bin)
        self.assertTrue((self.bin / "avpn").exists())

    def test_install_refuses_a_foreign_avpn_without_staging_or_overwriting(self):
        self.bin.mkdir(parents=True)
        foreign = b"#!/bin/sh\nprintf unrelated\\n\n"
        (self.bin / "avpn").write_bytes(foreign)
        with self.assertRaisesRegex(ValueError, "foreign avpn"):
            self.install()
        self.assertEqual((self.bin / "avpn").read_bytes(), foreign)
        self.assertFalse(self.data.exists())

    def test_pack_holds_exactly_the_package(self):
        with tempfile.TemporaryDirectory() as d:
            out = install.pack(install.ROOT, Path(d) / "p.tar.gz")
            names = tarfile.open(out).getnames()
        tops = {n.split("/")[0] for n in names}
        self.assertEqual(tops, {s.split("/")[0] for s in install.SOURCES} | {"target"})
        for b in install.BINARIES:
            self.assertIn("target/release/" + b, names)
        self.assertFalse([n for n in names if "__pycache__" in n or n.endswith(".pyc")])
        self.assertFalse([n for n in names if n.startswith("codex-")])


class NextStepTests(unittest.TestCase):
    """The installer's closing line must match reality (no 'No servers yet?' after an
    upgrade of a machine that has servers)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        (self.home / ".config" / "advanced-vpn").mkdir(parents=True)
        # An explicit home wins over the caller's own XDG variable.
        self.xdg = Path(self.tmp.name) / "xdg"
        (self.xdg / "advanced-vpn").mkdir(parents=True)
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.xdg)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def inventory(self, resources):
        (self.home / ".config" / "advanced-vpn" / "cloud.json").write_text(
            json.dumps(dict(schema=1, resources=resources))
        )

    def test_no_inventory_or_an_empty_one_says_no_servers_yet(self):
        self.assertEqual(install.next_servers_step(home=self.home), install.SUGGEST)
        self.inventory({})
        self.assertEqual(install.next_servers_step(home=self.home), install.SUGGEST)

    def test_servers_on_record_are_acknowledged_instead(self):
        self.inventory({"avpn-relay": dict(provider="aws")})
        line = install.next_servers_step(home=self.home)
        self.assertNotIn("No servers yet", line)
        self.assertIn("avpn cloud status", line)

    def test_a_broken_inventory_file_is_treated_as_empty(self):
        (self.home / ".config" / "advanced-vpn" / "cloud.json").write_text("{not json")
        self.assertEqual(install.next_servers_step(home=self.home), install.SUGGEST)

    def test_the_install_paths_print_the_checked_line_not_a_fixed_one(self):
        # The wiring, not just the helper: both install exits must print what
        # next_servers_step returns, never the unconditional suggestion.
        source = Path(install.__file__).read_text()
        self.assertEqual(source.count("print(next_servers_step())"), 2, "both call sites must use the check")
        self.assertNotIn("print(SUGGEST)", source)


if __name__ == "__main__":
    unittest.main()

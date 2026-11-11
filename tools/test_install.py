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
        for b in install.BINARIES + ["avpnctl", "avpn-cloud", "avpn-mesh"]:
            self.assertTrue(os.access(app / "bin" / b, os.X_OK), b)
        self.assertTrue((app / "docs/cli/overview.md").exists())
        self.assertFalse(list(app.rglob("__pycache__")))
        r = self.avpn("--version")
        version = re.search(r'^version = "([^"]+)"', (install.ROOT / "Cargo.toml").read_text(), re.M).group(1)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "avpn " + version))
        # End to end through the installed controller: JSON from a real (empty) state.
        r = self.avpn("--json", "--state", str(self.home / "no-state"), "hops")
        self.assertEqual(json.loads(r.stdout)["chain"], [], r.stderr)
        self.assertIn("• Chain  not enrolled", self.avpn("--state", str(self.home / "no-state"), "hops").stdout)

    def test_upgrade_replaces_in_place_without_leftovers(self):
        self.install()
        (self.data / "app" / "stale-file").write_text("old version")
        self.install()
        self.assertFalse((self.data / "app" / "stale-file").exists())
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), ["app"])
        self.assertEqual(self.avpn("--version").returncode, 0)

    def test_failed_install_leaves_the_old_one_and_no_leftovers(self):
        self.install()
        before = (self.data / "app" / "bin" / "avpnctl").read_text()

        def network_down(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0])

        with mock.patch.object(install.subprocess, "run", network_down):
            with self.assertRaises(subprocess.CalledProcessError):
                install.install_user(self.data, self.bin)  # needs a venv build, which fails
        self.assertEqual(sorted(p.name for p in self.data.iterdir()), ["app"])
        self.assertEqual((self.data / "app" / "bin" / "avpnctl").read_text(), before)
        self.assertEqual(self.avpn("--version").returncode, 0)

    def test_user_wrapper_exports_the_mesh_tool(self):
        app = self.install()
        wrapper = (self.bin / "avpn").read_text()
        self.assertIn("AVPN_MESH=", wrapper)
        self.assertIn(str(app / "bin/avpn-mesh"), wrapper)
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


if __name__ == "__main__":
    unittest.main()

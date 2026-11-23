"""The OpenTofu workspace runner (tools/tofu_run.py). The live counterpart, a read-only plan
against the owner's Oracle tenancy (20 Nov 2026), showed the module creating exactly the
route table, security list, subnet and instance `cloud.py` creates, a plan file no wrong key
opens, and no file holding the key."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tofu_run  # noqa: E402

KEY = bytes(range(32))


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.dict(os.environ, XDG_DATA_HOME=self.tmp.name)
        patch.start()
        self.addCleanup(patch.stop)

    def make(self):
        return tofu_run.workspace(
            "cpvpn-exit-x", "oci-server", dict(name="cpvpn-exit-x", port=4444), dict(profile="DEFAULT", region="r")
        )

    def test_the_workspace_pins_the_provider_and_holds_no_secret(self):
        d = self.make()
        main = (d / "main.tf").read_text()
        self.assertIn('oci = { source = "oracle/oci" }', main)
        self.assertIn('config_file_profile = "DEFAULT"', main)
        self.assertNotIn("passphrase", main)
        self.assertEqual(
            (d / ".terraform.lock.hcl").read_bytes(),
            (tofu_run.MODULES / "oci-server" / ".terraform.lock.hcl").read_bytes(),
        )
        self.assertEqual(json.loads((d / "terraform.tfvars.json").read_text())["port"], 4444)
        for f in ("main.tf", "terraform.tfvars.json"):
            self.assertEqual(oct((d / f).stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(d.stat().st_mode & 0o777), "0o700")

    def test_the_key_travels_in_the_environment_and_encryption_is_enforced(self):
        d = self.make()
        seen = []

        def fake(argv, **kw):
            seen.append((argv, kw["env"]))
            return mock.Mock(returncode=0, stdout="{}", stderr="")

        with mock.patch.object(tofu_run.tofu, "ensure", lambda: Path("/x/tofu")):
            tofu_run.run(d, "init", "-lockfile=readonly", key=KEY, run=fake)
        argv, env = seen[0]
        self.assertNotIn(KEY.hex(), " ".join(argv))
        config = env["TF_ENCRYPTION"]
        self.assertIn(KEY.hex(), config)
        self.assertEqual(config.count("enforced = true"), 2)  # state and plans
        self.assertIn("aes_gcm", config)
        with self.assertRaisesRegex(tofu_run.TofuRunError, "32 bytes"):
            tofu_run.encryption(b"short")

    def test_init_accepts_only_the_locked_provider_and_plan_summarises_changes(self):
        d = self.make()
        calls = []
        shown = {"resource_changes": [
            {"address": "module.server.oci_core_subnet.this", "change": {"actions": ["create"]}},
            {"address": "module.server.oci_core_vcn.own", "change": {"actions": ["no-op"]}},
            {"address": "module.server.oci_core_instance.this", "change": {"actions": ["delete", "create"]}},
        ]}  # fmt: skip

        def fake(d, *args, key=None):
            calls.append(args)
            return json.dumps(shown) if args[:2] == ("show", "-json") else ""

        with mock.patch.object(tofu_run, "run", fake):
            tofu_run.init(d, KEY)
            summary = tofu_run.plan(d, KEY)
        self.assertIn("-lockfile=readonly", calls[0])
        self.assertIn("-out=plan.bin", calls[1])
        self.assertEqual(summary, {"create": ["module.server.oci_core_subnet.this"],
                                   "delete/create": ["module.server.oci_core_instance.this"]})  # fmt: skip

    def test_a_failing_step_reports_its_error_line(self):
        d = self.make()

        def fake(argv, **kw):
            return mock.Mock(returncode=1, stdout="", stderr="\nError: Provider dependency changes detected\nmore\n")

        with (
            mock.patch.object(tofu_run.tofu, "ensure", lambda: Path("/x/tofu")),
            self.assertRaisesRegex(tofu_run.TofuRunError, "Provider dependency changes"),
        ):
            tofu_run.run(d, "init", key=KEY, run=fake)


class Packaging(unittest.TestCase):
    def test_the_package_keeps_modules_and_lock_files_but_not_provider_downloads(self):
        import tarfile

        import install

        self.assertIn("tofu/modules", install.SOURCES)
        keep = ["tofu/modules/oci-server/main.tf", "tofu/modules/oci-server/.terraform.lock.hcl"]
        drop = ["tofu/modules/oci-server/.terraform", "tofu/modules/oci-server/.terraform/providers/x",
                "tools/__pycache__/a.pyc"]  # fmt: skip
        for name in keep:
            self.assertIsNotNone(install._package_filter(tarfile.TarInfo(name)), name)
        for name in drop:
            self.assertIsNone(install._package_filter(tarfile.TarInfo(name)), name)


if __name__ == "__main__":
    unittest.main()

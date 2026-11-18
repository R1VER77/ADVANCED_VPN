"""System artifacts survive interrupted replacement and preserve administrator policy."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import install
import release_slots


class StableArtifacts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.destination = self.root / "source", self.root / "system/policy"
        self.source.write_bytes(b"verified release policy\n")
        self.source.chmod(0o644)

    def test_policy_replacement_recovers_cut_between_artifact_and_receipt(self):
        install.install_stable_file(self.source, self.destination, mode=0o644)
        original = release_slots.durable_json
        self.source.write_bytes(b"next verified release policy\n")

        def interrupted(path, value):
            if value.get("sha256") == release_slots.digest(self.source) and "pending_sha256" not in value:
                raise OSError("cut after artifact replacement")
            original(path, value)

        with mock.patch.object(release_slots, "durable_json", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "cut after"):
                install.install_stable_file(self.source, self.destination, mode=0o644)
        self.assertEqual(self.source.read_bytes(), self.destination.read_bytes())
        install.install_stable_file(self.source, self.destination, mode=0o644)
        receipt = json.loads(self.destination.with_name(".policy.json").read_text())
        self.assertNotIn("pending_sha256", receipt)

    def test_intent_does_not_authorize_unrecognized_policy_edits(self):
        install.install_stable_file(self.source, self.destination, mode=0o644)
        self.destination.write_bytes(b"administrator changed policy\n")
        with self.assertRaisesRegex(ValueError, "modified"):
            install.install_stable_file(self.source, self.destination, mode=0o644)
        self.assertEqual(self.destination.read_bytes(), b"administrator changed policy\n")

    def test_unowned_and_symlink_artifacts_refused(self):
        self.destination.parent.mkdir(mode=0o755)
        self.destination.write_bytes(b"foreign")
        self.destination.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "known owned"):
            install.install_stable_file(self.source, self.destination, mode=0o644)
        self.destination.unlink()
        self.destination.symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, "foreign"):
            install.install_stable_file(self.source, self.destination)

    def test_apparmor_preserves_unrelated_rules_and_is_idempotent(self):
        unrelated = b"# Site policy\n/opt/local/** r,\n"
        self.destination.parent.mkdir(mode=0o755)
        self.destination.write_bytes(unrelated)
        self.destination.chmod(0o644)
        install.install_apparmor_fragment(self.source, self.destination)
        installed = self.destination.read_bytes()
        self.assertTrue(installed.startswith(unrelated))
        self.assertIn(self.source.read_bytes(), installed)
        install.install_apparmor_fragment(self.source, self.destination)
        self.assertEqual(installed, self.destination.read_bytes())
        self.assertEqual(os.stat(self.destination).st_mode & 0o777, 0o644)

    def test_apparmor_refuses_modified_or_duplicate_managed_blocks(self):
        block = install.apparmor_update(self.source.read_bytes(), b"")
        for altered in (
            block.replace(b"verified", b"edited"),
            block + block,
            install.APPARMOR_END + install.APPARMOR_BEGIN,
        ):
            with self.assertRaisesRegex(ValueError, "AppArmor"):
                install.apparmor_update(self.source.read_bytes(), altered)

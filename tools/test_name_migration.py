#!/usr/bin/env python3
"""Tests for the name migration's state-custody engine
(tools/name_migration.py): inventory classification and hashing, the
ownership and permission rules, plan refusal for unmanaged installs
and unknown entries, never-migrate for hardware keys, atomic apply
with hash verification, rollback on failure, receipts, and the
restore-from-receipt path."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import name_migration as nm  # noqa: E402


def build_root(base: Path, *, unmanaged=False, unknown=False, permissive_vault=False, wrong_owner_vault=False) -> Path:
    """A realistic (simulated) /etc/advanced-vpn."""
    root = base / "advanced-vpn"
    (root / "keys").mkdir(parents=True)
    (root / "vaults").mkdir()
    (root / "state").mkdir()
    (root / "cloud").mkdir()
    (root / "enrolled").mkdir(parents=True)
    (root / "recovery").mkdir()
    (root / "keys" / "hw.key").write_bytes(b"hardware-key-material")
    (root / "vaults" / "operator.vault").write_bytes(b"sealed-vault-bytes")
    (root / "state" / "counters.json").write_text('{"sessions": 41}\n')
    (root / "cloud" / "inventory.json").write_text('{"servers": []}\n')
    (root / "enrolled" / "bundle.json").write_text('{"chain": "signed"}\n')
    (root / "recovery" / "recovery.json").write_text('{"paths": []}\n')
    (root / "operator.json").write_text('{"key": "public"}\n')
    # Realistic custody permissions: private material is 0600.
    for private in (root / "keys" / "hw.key", root / "vaults" / "operator.vault", root / "operator.json"):
        os.chmod(private, 0o600)
    if unmanaged:
        (root / "unmanaged").write_text("another tool owns this")
    if unknown:
        (root / "mystery").write_text("?")
    if permissive_vault:
        os.chmod(root / "vaults" / "operator.vault", 0o644)
    return root


class InventoryTests(unittest.TestCase):
    def test_classification_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp))
            inv = nm.inventory(root)
            roles = {e["path"]: e["role"] for e in inv["entries"]}
            self.assertEqual(roles["keys/hw.key"], "hardware-key")
            self.assertEqual(roles["vaults/operator.vault"], "vault")
            self.assertEqual(roles["state/counters.json"], "state")
            self.assertEqual(roles["cloud/inventory.json"], "cloud-inventory")
            self.assertEqual(roles["enrolled/bundle.json"], "enrolled")
            self.assertEqual(roles["recovery/recovery.json"], "recovery")
            self.assertEqual(roles["operator.json"], "operator")
            for e in inv["entries"]:
                self.assertEqual(len(e["sha256"]), 64)

    def test_missing_root_refused(self):
        with self.assertRaises(nm.MigrationError):
            nm.inventory(Path("/nonexistent-etc"))


class OwnershipTests(unittest.TestCase):
    def test_permissive_vault_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp), permissive_vault=True)
            inv = nm.inventory(root)
            problems = nm.check_ownership(inv)
            self.assertTrue(any("operator.vault" in p for p in problems))

    def test_tight_vault_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp))  # fixture sets 0600 on private files
            self.assertEqual(nm.check_ownership(nm.inventory(root)), [])


class PlanTests(unittest.TestCase):
    def test_unmanaged_install_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp), unmanaged=True)
            with self.assertRaises(nm.MigrationError) as cm:
                nm.plan(nm.inventory(root))
            self.assertIn("unmanaged", str(cm.exception))

    def test_unknown_entry_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp), unknown=True)
            with self.assertRaises(nm.MigrationError) as cm:
                nm.plan(nm.inventory(root))
            self.assertIn("unknown", str(cm.exception))

    def test_hardware_key_never_migrates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp))
            plan_doc = nm.plan(nm.inventory(root))
            by_path = {s["path"]: s for s in plan_doc["steps"]}
            self.assertEqual(by_path["keys/hw.key"]["action"], "never-migrate")
            self.assertEqual(by_path["vaults/operator.vault"]["action"], "copy")
            self.assertEqual(by_path["state/counters.json"]["action"], "move")

    def test_recovery_copies_last(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp))
            plan_doc = nm.plan(nm.inventory(root))
            actions = [s["action"] for s in plan_doc["steps"]]
            self.assertEqual(actions[-1], "preserve")


class ApplyTests(unittest.TestCase):
    def _plan(self, tmp):
        root = build_root(Path(tmp))
        return root, nm.plan(nm.inventory(root)), Path(tmp) / "cypherpunk-vpn"

    def test_apply_and_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plan_doc, dest = self._plan(tmp)
            receipts = Path(tmp) / "receipt.json"
            result = nm.apply(plan_doc, root, dest, receipts)
            self.assertTrue(result["ok"])
            self.assertTrue((dest / "state" / "counters.json").exists())
            # moved entries leave the old root
            self.assertFalse((root / "state" / "counters.json").exists())
            # copied vaults stay
            self.assertTrue((root / "vaults" / "operator.vault").exists())
            # hardware keys untouched on both sides
            self.assertTrue((root / "keys" / "hw.key").exists())
            self.assertFalse((dest / "keys" / "hw.key").exists())
            doc = json.loads(receipts.read_text())
            statuses = [s["status"] for s in doc["steps"]]
            self.assertIn("not-migrated (hardware custody)", statuses)

    def test_refuses_nonempty_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plan_doc, dest = self._plan(tmp)
            dest.mkdir()
            (dest / "foreign").write_text("x")
            with self.assertRaises(nm.MigrationError):
                nm.apply(plan_doc, root, dest)

    def test_hash_mismatch_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plan_doc, dest = self._plan(tmp)
            # Corrupt one MOVE step's recorded hash: the copy must fail
            # verification and roll everything back.
            move_steps = [s for s in plan_doc["steps"] if s["action"] == "move"]
            move_steps[0]["sha256_before"] = "00" * 32
            with self.assertRaises(nm.MigrationError):
                nm.apply(plan_doc, root, dest)
            self.assertFalse(dest.exists() and any(dest.iterdir()))
            # nothing was half-moved: every source entry is still there
            self.assertTrue((root / "state" / "counters.json").exists())

    def test_rollback_from_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, plan_doc, dest = self._plan(tmp)
            receipts = Path(tmp) / "receipt.json"
            nm.apply(plan_doc, root, dest, receipts)
            result = nm.rollback_plan(receipts, root, dest)
            self.assertTrue(result["ok"])
            # everything restored: the moved files are back
            self.assertTrue((root / "state" / "counters.json").exists())
            self.assertTrue((root / "enrolled" / "bundle.json").exists())
            # the destination is drained of what it received
            self.assertFalse((dest / "state" / "counters.json").exists())
            self.assertFalse((dest / "enrolled" / "bundle.json").exists())
            # hardware keys never moved, so nothing to restore for them
            self.assertTrue((root / "keys" / "hw.key").exists())


class RoundTripTests(unittest.TestCase):
    def test_migrated_bytes_identical(self):
        """The acceptance core: every migrated entry is byte-identical
        to its source (enrolled identities, counters and signatures
        preserved — the plan's row-5 gate)."""
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            root = build_root(Path(tmp))
            before = {
                str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob("*")
                if p.is_file()
            }
            plan_doc = nm.plan(nm.inventory(root))
            dest = Path(tmp) / "cypherpunk-vpn"
            nm.apply(plan_doc, root, dest)
            for rel, digest in before.items():
                if plan_steps(plan_doc, rel) == "never-migrate":
                    continue
                p = dest / rel
                self.assertTrue(p.exists(), rel)
                self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), digest, rel)


def plan_steps(plan_doc, path):
    for s in plan_doc["steps"]:
        if s["path"] == path:
            return s["action"]
    return None


if __name__ == "__main__":
    unittest.main(verbosity=2)

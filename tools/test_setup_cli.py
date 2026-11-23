"""Setup/controller boundaries: no implicit repair, wrong-device writes or cached safety claims."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cypherpunkctl
import hwkey
import setup_cli as cli
import setup_flow as sf


class ConfirmedRepair(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.before = [
            hwkey.Finding(
                "fido2_disabled",
                "blocker",
                "disabled",
                detail=dict(serial="12345678", vendor="1050"),
                repair="yubikey_enable_fido2",
            )
        ]
        self.ready = [hwkey.Finding("key_ready", "ok", "ready", "hidraw3", dict(vendor="1050"))]
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, *extra):
        return cypherpunkctl.build_parser().parse_args(
            ["--state", str(self.root), "setup", "--repair", "yubikey_enable_fido2", *extra]
        )

    def apply(self, plan, confirmed):
        self.calls.append(plan)
        self.assertIs(confirmed, True)
        return [0]

    def test_a_plan_is_read_only_and_bound_to_a_vendor_serial(self):
        r = cli.setup(self.args(), diagnose=lambda: self.before, apply=self.apply)
        self.assertEqual(self.calls, [])
        self.assertFalse(r["repair"]["applied"])
        self.assertEqual(r["repair"]["plan"]["selector"], "12345678")
        self.assertIn("12345678", r["repair"]["plan"]["commands"][0])

    def test_apply_needs_the_current_confirmation_and_device(self):
        p = cli.setup(self.args(), diagnose=lambda: self.before)["repair"]
        for token in ("", "wrong"):
            with self.assertRaises(PermissionError):
                cli.setup(self.args("--apply", "--confirm", token), diagnose=lambda: self.before, apply=self.apply)
        changed = [
            hwkey.Finding(
                "fido2_disabled",
                "blocker",
                "disabled",
                detail=dict(serial="87654321", vendor="1050"),
                repair="yubikey_enable_fido2",
            )
        ]
        with self.assertRaises(PermissionError):
            cli.setup(self.args("--apply", "--confirm", p["confirmation"]), diagnose=lambda: changed, apply=self.apply)
        self.assertEqual(self.calls, [])

    def test_exit_zero_without_fresh_vendor_confirmation_is_not_success(self):
        p = cli.setup(self.args(), diagnose=lambda: self.before)["repair"]
        results = iter([self.before, self.ready])
        r = cli.setup(
            self.args("--apply", "--confirm", p["confirmation"]),
            diagnose=lambda: next(results),
            apply=self.apply,
            vendor_info=lambda: dict(serial="87654321", fido2="Enabled"),
        )
        self.assertTrue(r["repair"]["commands_succeeded"])
        self.assertFalse(r["repair"]["verified"])

    def test_selected_key_must_pass_both_vendor_and_ctap_checks(self):
        p = cli.setup(self.args(), diagnose=lambda: self.before)["repair"]
        results = iter([self.before, self.ready])
        r = cli.setup(
            self.args("--apply", "--confirm", p["confirmation"]),
            diagnose=lambda: next(results),
            apply=self.apply,
            vendor_info=lambda: dict(serial="12345678", fido2="Enabled"),
        )
        self.assertTrue(r["repair"]["verified"])
        results = iter([self.before, []])
        r = cli.setup(
            self.args("--apply", "--confirm", p["confirmation"]),
            diagnose=lambda: next(results),
            apply=self.apply,
            vendor_info=lambda: dict(serial="12345678", fido2="Enabled"),
        )
        self.assertFalse(r["repair"]["verified"])

    def test_unknown_or_ambiguous_findings_authorize_nothing(self):
        for findings in ([], self.before * 2):
            with self.assertRaises(ValueError):
                cli.repair_plan("yubikey_enable_fido2", findings)
        with self.assertRaises(ValueError):
            cli.repair_plan("yubikey_enable_fido2", self.before, "87654321")

    def test_existing_rule_is_not_overwritten(self):
        path = self.root / "rule"
        path.write_text("administrator rule")
        f = [hwkey.Finding("permission_denied", "blocker", "permission", device="hidraw2", repair="install_udev_rule")]
        with patch.object(hwkey, "UDEV_RULE_PATH", str(path)):
            with self.assertRaises(ValueError):
                cli.repair_plan("install_udev_rule", f)
        self.assertEqual(path.read_text(), "administrator rule")

    def test_changed_or_unbound_builtin_plan_cannot_run(self):
        for confirmed in (False, "false", 1):
            with self.assertRaises(PermissionError):
                hwkey.apply(hwkey.plan("install_udev_rule"), confirmed, run=self.apply)
        r = hwkey.plan("install_udev_rule")
        r.commands = [["sh", "-c", "not allowed"]]
        with self.assertRaises(ValueError):
            hwkey.apply(r, True, run=self.apply)
        with self.assertRaises(ValueError):
            hwkey.apply(hwkey.plan("yubikey_enable_fido2"), True, run=self.apply)
        self.assertEqual(self.calls, [])


class CheckpointBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_checkpoint_symlink_is_refused_without_changing_target(self):
        target = self.root / "target"
        target.write_text("original")
        (self.root / sf.CHECKPOINT).symlink_to(target)
        with self.assertRaises(OSError):
            sf.run([], {}, self.root)
        self.assertEqual(target.read_text(), "original")

    def test_world_readable_checkpoint_and_symlink_directory_are_refused(self):
        p = self.root / sf.CHECKPOINT
        p.write_text("{}")
        p.chmod(0o644)
        with self.assertRaises(ValueError):
            sf.run([], {}, self.root)
        other = self.root / "other"
        other.mkdir(mode=0o700)
        link = self.root / "linked"
        link.symlink_to(other, target_is_directory=True)
        with self.assertRaises(OSError):
            sf.run([], {}, link)

    def test_untrusted_checkpoint_cannot_inject_completed_or_removed_steps(self):
        p = self.root / sf.CHECKPOINT
        p.write_text(json.dumps(dict(schema=1, steps={"deleted": {"state": "complete"}, "a": 123})))
        p.chmod(0o600)
        steps = [sf.Step("a", "A", (), lambda c: sf.Result("waiting_for_user", "wait"))]
        sf.run(steps, {}, self.root)
        r = sf.load(self.root)
        self.assertEqual(r["complete"], 0)
        self.assertEqual(list(r["steps"]), ["a"])

    def test_raw_exception_text_never_enters_checkpoint(self):
        def fail(ctx):
            raise RuntimeError("SECRET_CREDENTIAL_DO_NOT_STORE")

        sf.run([sf.Step("a", "A", (), fail)], {}, self.root)
        s = (self.root / sf.CHECKPOINT).read_text()
        self.assertNotIn("SECRET_CREDENTIAL", s)
        self.assertEqual(sf.load(self.root)["steps"]["a"]["state"], "failed")

    def test_invalid_dependency_graph_is_refused(self):
        step = sf.Step("a", "A", ("missing",), lambda c: sf.Result("complete", "ok"))
        with self.assertRaises(ValueError):
            sf.run([step], {}, self.root)

    def test_two_ready_keys_cannot_complete_key_selection(self):
        findings = [
            hwkey.Finding("key_ready", "ok", "ready", device="hidraw1"),
            hwkey.Finding("key_ready", "ok", "ready", device="hidraw2"),
        ]
        self.assertEqual(sf.check_key(dict(diagnose=lambda: findings)).state, "waiting_for_user")


class MachineInterface(unittest.TestCase):
    def test_preflight_is_one_json_object_and_does_not_create_runtime_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "not-enrolled"
            controller = Path(cypherpunkctl.__file__)
            proc = subprocess.run(
                [sys.executable, str(controller), "--state", str(state), "--json", "preflight"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            lines = proc.stdout.strip().splitlines()
            self.assertEqual(len(lines), 1, proc.stderr)
            data = json.loads(lines[0])
            self.assertEqual(data["action"], "preflight")
            self.assertEqual(proc.returncode, 0 if data["preflight"]["ready"] else 1)
            self.assertFalse(state.exists())

    def test_runtime_snapshot_requires_a_live_identity_and_fresh_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            rt = Path(tmp)
            path = rt / "status.json"
            path.write_text("{}")
            now = path.stat().st_mtime
            good = dict(state="supervising", kill_switch=True, protection="protected")
            with (
                patch.object(cypherpunkctl, "runtime_dir", return_value=rt),
                patch.object(cypherpunkctl, "read_status", return_value=good),
                patch.object(cypherpunkctl, "read_json_private", return_value=dict(pid=123, identity="start")),
                patch.object(cypherpunkctl, "identity_of", return_value="start"),
            ):
                self.assertTrue(sf.status(dict(state=rt, now=lambda: now))["_fresh"])
                self.assertFalse(sf.status(dict(state=rt, now=lambda: now + 6))["_fresh"])
                with patch.object(cypherpunkctl, "identity_of", return_value="reused-pid"):
                    self.assertFalse(sf.status(dict(state=rt, now=lambda: now))["_fresh"])


if __name__ == "__main__":
    unittest.main()

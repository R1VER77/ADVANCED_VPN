"""Tests for tools/setup_flow.py: the checklist engine and today's checks, on simulated state."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

import hwkey
import setup_flow as sf


def step(id, depends=(), state="complete", fp=None, say="ok"):
    return sf.Step(id, id, depends, lambda ctx: sf.Result(state, say, dict(id=id), fp))


class Engine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_step_waits_for_its_dependencies(self):
        out = sf.run([step("a", state="blocked"), step("b", ("a",))], {}, self.dir)
        self.assertEqual([r.state for _, r in out], ["blocked", "pending"])
        rec = json.loads((self.dir / sf.CHECKPOINT).read_text())
        self.assertEqual((rec["complete"], rec["total"], rec["current"]), (0, 2, "a"))

    def test_only_a_check_completes_a_step_and_progress_is_counted(self):
        out = sf.run([step("a"), step("b", ("a",)), step("c", ("b",), state="waiting_for_user")], {}, self.dir)
        self.assertEqual([r.state for _, r in out], ["complete", "complete", "waiting_for_user"])
        rec = sf.load(self.dir)
        self.assertEqual((rec["complete"], rec["current"]), (2, "c"))

    def test_a_check_that_crashes_is_a_failure_never_a_pass(self):
        def boom(ctx):
            raise RuntimeError("no udevadm")

        out = sf.run([sf.Step("a", "a", (), boom), step("b", ("a",))], {}, self.dir)
        self.assertEqual([r.state for _, r in out], ["failed", "pending"])

    def test_resuming_checks_everything_again(self):
        sf.run([step("a"), step("b", ("a",))], {}, self.dir)
        # The world changed while setup was paused: a no longer holds.
        out = sf.run([step("a", state="waiting_for_hardware"), step("b", ("a",))], {}, self.dir)
        self.assertEqual([r.state for _, r in out], ["waiting_for_hardware", "pending"])

    def test_a_changed_input_marks_the_steps_after_it(self):
        sf.run([step("a", fp="key-1"), step("b", ("a",)), step("c", ("b",))], {}, self.dir)
        sf.run([step("a", fp="key-2"), step("b", ("a",)), step("c", ("b",))], {}, self.dir)
        rec = sf.load(self.dir)["steps"]
        self.assertEqual([rec[k]["inputs_changed"] for k in "abc"], [True, True, True])
        sf.run([step("a", fp="key-2"), step("b", ("a",)), step("c", ("b",))], {}, self.dir)
        rec = sf.load(self.dir)["steps"]
        self.assertEqual([rec[k]["inputs_changed"] for k in "abc"], [False, False, False])

    def test_the_checkpoint_is_private_and_holds_no_secret(self):
        ctx = dict(
            diagnose=lambda: [hwkey.Finding("key_ready", "ok", "ready", "hidraw2", dict(vendor="20A0", product="42B2"))]
        )
        sf.run([sf.Step("key", "key", (), sf.check_key)], ctx, self.dir)
        f = self.dir / sf.CHECKPOINT
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("pin", f.read_text().lower().replace("pin_retries", ""))

    def test_unknown_states_are_refused(self):
        with self.assertRaises(ValueError):
            sf.Result("done", "x")


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_key_step_follows_the_diagnosis(self):
        cases = [
            ([hwkey.Finding("key_ready", "ok", "ready", "hidraw2", dict(vendor="20A0", product="42B2"))], "complete"),
            ([hwkey.Finding("no_key", "blocker", "plug it in")], "waiting_for_hardware"),
            ([hwkey.Finding("fido2_disabled", "blocker", "off", repair="yubikey_enable_fido2")], "blocked"),
            ([hwkey.Finding("pin_retries_low", "warning", "2 left"),
              hwkey.Finding("key_ready", "ok", "ready", "hidraw2", dict(vendor="20A0", product="42B2"))], "complete"),
        ]  # fmt: skip
        for findings, state in cases:
            with self.subTest(state=state, first=findings[0].code):
                r = sf.check_key(dict(diagnose=lambda f=findings: f))
                self.assertEqual(r.state, state)
                if state == "blocked":
                    self.assertEqual(r.findings[0]["repair"], "yubikey_enable_fido2")

    def test_another_key_changes_the_key_fingerprint(self):
        def ready(product):
            return dict(
                diagnose=lambda: [
                    hwkey.Finding("key_ready", "ok", "r", "hidraw2", dict(vendor="20A0", product=product))
                ]
            )

        self.assertNotEqual(sf.check_key(ready("42B1")).fingerprint, sf.check_key(ready("42B2")).fingerprint)

    def test_the_vault_step(self):
        self.assertEqual(sf.check_vault(dict(vault=self.dir)).state, "waiting_for_user")
        from fido2 import cbor

        raw = bytes(16) + b"\x00\x01a" + cbor.encode({1: 1, 3: -8, -1: 6, -2: b"x" * 32})
        record = dict(
            schema=1,
            rp="cypherpunk-vpn.local",
            credential=base64.b64encode(raw).decode(),
            salt=base64.b64encode(b"s" * 32).decode(),
            counter=0,
        )
        path = self.dir / "credential.json"
        path.write_text(json.dumps(record))
        path.chmod(0o600)
        r = sf.check_vault(dict(vault=self.dir))
        self.assertEqual(r.state, "complete")
        self.assertFalse(r.evidence["possession_verified"])
        for counter in (None, -1, True, "0", 2**32):
            with self.subTest(counter=counter):
                invalid = dict(record, counter=counter)
                path.write_text(json.dumps(invalid))
                self.assertEqual(sf.check_vault(dict(vault=self.dir)).state, "blocked")
        missing = dict(record)
        del missing["counter"]
        path.write_text(json.dumps(missing))
        self.assertEqual(sf.check_vault(dict(vault=self.dir)).state, "blocked")
        record["credential"] = "abc"
        path.write_text(json.dumps(record))
        self.assertEqual(sf.check_vault(dict(vault=self.dir)).state, "blocked")

    def test_no_profile_waits_for_the_device_file(self):
        self.assertEqual(sf.check_profile(dict(state=self.dir)).state, "waiting_for_user")

    def test_guard_and_protection_follow_fresh_verified_status(self):
        def ctx(s):
            return dict(status=lambda: s, now=lambda: 100)

        good = dict(
            state="supervising",
            kill_switch=True,
            _fresh=True,
            protection="protected",
            evidence=dict(cloak_confirmed_at=99, carrier_handshake_at=99, path_probe_at=99),
        )
        self.assertEqual(sf.check_guard(ctx(good)).state, "complete")
        self.assertEqual(sf.check_guard(ctx(dict(good, state="blocked"))).state, "complete")
        self.assertEqual(sf.check_protected(ctx(good)).state, "complete")
        for change in (
            {"_fresh": False},
            {"kill_switch": False},
            {"state": "blocked"},
            {"evidence": {}},
            {"evidence": dict(cloak_confirmed_at=1, carrier_handshake_at=99, path_probe_at=99)},
            {"evidence": dict(cloak_confirmed_at=101, carrier_handshake_at=99, path_probe_at=99)},
            {"evidence": dict(cloak_confirmed_at=float("nan"), carrier_handshake_at=99, path_probe_at=99)},
        ):
            with self.subTest(change=change):
                self.assertNotEqual(sf.check_protected(ctx(dict(good, **change))).state, "complete")
        self.assertNotEqual(sf.check_guard(ctx(dict(good, _fresh=False))).state, "complete")

    def test_the_client_checklist_orders_its_dependencies(self):
        steps = sf.client_steps()
        ids = [s.id for s in steps]
        for s in steps:
            for d in s.depends:
                self.assertLess(ids.index(d), ids.index(s.id))
        self.assertEqual(ids[-1], "protected")


if __name__ == "__main__":
    unittest.main()

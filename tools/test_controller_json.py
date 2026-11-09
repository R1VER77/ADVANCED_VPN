"""The controller's machine interface (`--json`), which the Rust `avpn` CLI renders.

Every command must print exactly one JSON object on stdout, errors included, and
read-only queries must not create runtime state."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from avpnctl import runtime_dir
from managed_profile import lab_setup

CTL = Path(__file__).resolve().parent / "avpnctl.py"


def ctl(state, *args):
    """Run the controller with --json; return (exit code, parsed stdout, stderr)."""
    r = subprocess.run(
        [sys.executable, str(CTL), "--json", "--state", str(state), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    lines = r.stdout.strip().splitlines()
    assert len(lines) == 1, "stdout must be exactly one JSON line: %r" % r.stdout
    return r.returncode, json.loads(lines[0]), r.stderr


class ControllerJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        lab_setup(cls.root, "192.0.2.1:41194", "198.51.100.2:4444")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_hops_reports_the_enrolled_chain_in_order(self):
        rc, out, _ = ctl(self.root / "client", "hops")
        self.assertEqual(rc, 0)
        self.assertTrue(out["ok"])
        self.assertEqual(out["hops"], 2)
        self.assertEqual([h["hop"] for h in out["chain"]], ["relay", "exit"])
        self.assertEqual(out["chain"][0]["endpoint"], "192.0.2.1:41194")

    def test_info_is_non_secret_and_complete(self):
        rc, out, _ = ctl(self.root / "client", "info")
        self.assertEqual(rc, 0)
        info = out["info"]
        for key in ["role", "hops", "chain", "protection", "mode", "defense", "status"]:
            self.assertIn(key, info)
        self.assertEqual(info["status"], {"state": "not running"})
        text = json.dumps(out)
        for secret_marker in ["PRIVATE KEY", "psk", "-key.der"]:
            self.assertNotIn(secret_marker, text)

    def test_read_only_queries_create_no_runtime_state(self):
        state = self.root / "client"
        rt = runtime_dir(state, create=False)
        existed = os.path.lexists(rt)
        for action in ["hops", "info", "status"]:
            rc, out, _ = ctl(state, action)
            self.assertEqual((rc, out["ok"]), (0, True), action)
        self.assertEqual(os.path.lexists(rt), existed)

    def test_unenrolled_state_is_reported_not_crashed(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out, _ = ctl(Path(d), "info")
            self.assertEqual(rc, 0)
            self.assertFalse(out["info"]["enrolled"])
            rc, out, _ = ctl(Path(d), "hops")
            self.assertEqual((rc, out["chain"]), (0, []))

    def test_errors_are_one_json_object_with_human_text_on_stderr(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "profile.json").write_text("{not json")
            os.chmod(Path(d) / "profile.json", 0o600)
            rc, out, err = ctl(Path(d), "hops")
            self.assertEqual(rc, 1)
            self.assertEqual(out["ok"], False)
            self.assertIn("error", out)
            self.assertIn("Managed operation stopped", err)

    def test_refusals_carry_the_controllers_reason(self):
        # Refused for any user: without root by the root guard, as root by validation.
        with tempfile.TemporaryDirectory() as d:
            rc, out, err = ctl(Path(d), "preferences", "--upstream-gateway", "16.0.0.1")
            self.assertEqual(rc, 1)
            self.assertIn(out["error"], ("RuntimeError", "ValueError"))
            reason = "root supervisor" if os.geteuid() else "goes with --upstream-interface"
            self.assertIn(reason, out["message"])
            self.assertIn(reason, err)

    def test_doctor_reports_when_no_resolver_socket_exists(self):
        import avpnctl

        saved = avpnctl.RESOLVER_DIRS, avpnctl.SYSTEM_BUS_SOCKETS
        avpnctl.RESOLVER_DIRS, avpnctl.SYSTEM_BUS_SOCKETS = ("/nonexistent-avpn-a",), ("/nonexistent-avpn-b",)
        try:
            checks = avpnctl.doctor(self.root / "client")
        finally:
            avpnctl.RESOLVER_DIRS, avpnctl.SYSTEM_BUS_SOCKETS = saved
        detail = next(c["detail"] for c in checks if c["check"] == "resolver isolation")
        self.assertEqual(detail, "hidden from protected apps: none present")

    def test_doctor_reports_missing_tools_instead_of_crashing(self):
        import avpnctl

        def missing(name):
            raise FileNotFoundError("trusted executable not found: " + name)

        with mock.patch.object(avpnctl, "trusted_exe", missing):
            checks = avpnctl.doctor(self.root / "client", check_egress=True)
        by_name = {c["check"]: c for c in checks}
        self.assertFalse(by_name["trusted nft"]["ok"])
        self.assertEqual(by_name["advanced-vpn.service installed"]["detail"], "systemctl not found")
        self.assertEqual(by_name["address the first hop sees (outside the tunnel)"]["detail"], "curl not found")

    def test_doctor_returns_structured_checks(self):
        rc, out, _ = ctl(self.root / "client", "doctor")
        self.assertEqual(rc, 0)
        self.assertIn("healthy", out)
        names = [c["check"] for c in out["checks"]]
        self.assertIn("post-quantum crypto library", names)
        self.assertIn("enrolled in a chain", names)
        self.assertTrue(all(set(c) == {"check", "ok", "detail"} for c in out["checks"]))


if __name__ == "__main__":
    unittest.main()

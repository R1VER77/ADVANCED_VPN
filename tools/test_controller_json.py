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

    def test_a_current_chain_is_padded(self):
        rc, out, _ = ctl(self.root / "client", "info")
        self.assertIs(out["info"]["padded"], True)
        rc, out, _ = ctl(self.root / "client", "doctor")
        row = next(c for c in out["checks"] if c["check"] == "constant-cell padding")
        self.assertTrue(row["ok"])

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


class PrePaddingChainTests(unittest.TestCase):
    """A device enrolled before constant-cell padding existed, then upgraded."""

    @classmethod
    def setUpClass(cls):
        import managed_profile

        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        # Sign the chain the old way (no `cells`) and enroll it as the old code did.
        with (
            mock.patch.object(managed_profile, "CELLS", False),
            mock.patch.object(managed_profile, "require_padding", lambda p: p),
        ):
            lab_setup(cls.root, "192.0.2.1:41194", "198.51.100.2:4444")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_old_profile_really_lacks_padding(self):
        profile = json.loads((self.root / "client" / "profile.json").read_text())
        self.assertNotIn("cells", profile["core"])

    def test_kill_switch_reset_and_info_still_load_it(self):
        import avpnctl

        # reset and guard go through load_profile: they must never lock the user out.
        self.assertEqual(avpnctl.load_profile(self.root / "client")["role"], "client")
        rc, out, _ = ctl(self.root / "client", "info")
        self.assertEqual(rc, 0)
        self.assertIs(out["info"]["padded"], False)

    def test_doctor_says_to_re_sign(self):
        rc, out, _ = ctl(self.root / "client", "doctor")
        row = next(c for c in out["checks"] if c["check"] == "constant-cell padding")
        self.assertFalse(row["ok"])
        self.assertIn("avpn cloud chain --apply", row["detail"])

    def test_connect_refuses_before_changing_the_host(self):
        import avpnctl
        from managed_profile import PADDING_REQUIRED

        touched = mock.Mock(side_effect=AssertionError("host touched before the padding check"))
        with (
            mock.patch.object(avpnctl, "root_guard", lambda lab: None),
            mock.patch.object(avpnctl, "service_identity", touched),
            mock.patch.object(avpnctl, "ensure_network", touched),
        ):
            with self.assertRaises(RuntimeError) as e:
                avpnctl.supervise(self.root / "client", self.root / "bin", lab=True)
        self.assertEqual(str(e.exception), PADDING_REQUIRED)
        touched.assert_not_called()

    def test_enrolling_an_unpadded_bundle_is_refused(self):
        from managed_profile import PADDING_REQUIRED, enroll

        ops = self.root / "operator"
        with self.assertRaises(ValueError) as e:
            enroll(ops / "client.avpn", ops / "operator.pub", self.root / "client", replace=True)
        self.assertEqual(str(e.exception), PADDING_REQUIRED)


class PreCloakChainTests(unittest.TestCase):
    """A device enrolled before the HTTP/3 camouflage existed, then upgraded."""

    @classmethod
    def setUpClass(cls):
        import managed_profile

        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        # Sign the chain the old way (WireGuard straight to the first hop) and enroll it.
        with (
            mock.patch.object(managed_profile, "CLOAK", False),
            mock.patch.object(managed_profile, "require_current", lambda p: p),
        ):
            lab_setup(cls.root, "192.0.2.1:41194", "198.51.100.2:4444")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_old_profile_really_lacks_the_cloak(self):
        profile = json.loads((self.root / "client" / "profile.json").read_text())
        self.assertNotIn("cloak", profile)
        self.assertEqual(profile["carrier"]["endpoint"], "192.0.2.1:41194")

    def test_kill_switch_reset_and_info_still_load_it(self):
        import avpnctl

        self.assertEqual(avpnctl.load_profile(self.root / "client")["role"], "client")
        rc, _, _ = ctl(self.root / "client", "info")
        self.assertEqual(rc, 0)

    def test_doctor_says_to_re_sign_for_the_camouflage(self):
        rc, out, _ = ctl(self.root / "client", "doctor")
        row = next(c for c in out["checks"] if c["check"] == "HTTP/3 camouflage")
        self.assertFalse(row["ok"])
        self.assertIn("avpn cloud chain --apply", row["detail"])

    def test_connect_refuses_before_changing_the_host(self):
        import avpnctl
        from managed_profile import CLOAK_REQUIRED

        touched = mock.Mock(side_effect=AssertionError("host touched before the cloak check"))
        with (
            mock.patch.object(avpnctl, "root_guard", lambda lab: None),
            mock.patch.object(avpnctl, "service_identity", touched),
            mock.patch.object(avpnctl, "ensure_network", touched),
        ):
            with self.assertRaises(RuntimeError) as e:
                avpnctl.supervise(self.root / "client", self.root / "bin", lab=True)
        self.assertEqual(str(e.exception), CLOAK_REQUIRED)
        touched.assert_not_called()

    def test_enrolling_a_bundle_without_the_cloak_is_refused(self):
        from managed_profile import CLOAK_REQUIRED, enroll

        ops = self.root / "operator"
        with self.assertRaises(ValueError) as e:
            enroll(ops / "client.avpn", ops / "operator.pub", self.root / "client", replace=True)
        self.assertEqual(str(e.exception), CLOAK_REQUIRED)


class ServerRetentionGateTests(unittest.TestCase):
    """A server whose host would keep logs on disk must not carry traffic."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        lab_setup(cls.root, "192.0.2.1:41194", "198.51.100.2:4444")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    class Reached(Exception):
        """Raised by the first step after the gate: the server would have started."""

    def start(self, role, failing, shared=False, lab=False):
        import avpnctl
        import retention

        marker = self.root / ("shared-%s" % shared)
        if shared:
            marker.write_text("")
        reached = mock.Mock(side_effect=self.Reached)
        with (
            mock.patch.object(avpnctl, "root_guard", lambda lab: None),
            mock.patch.object(avpnctl, "service_identity", reached),
            mock.patch.object(retention, "failures", lambda: failing),
            mock.patch.object(retention, "SHARED_MARKER", marker),
        ):
            try:
                avpnctl.supervise(self.root / role, self.root / "bin", lab=lab)
            except self.Reached:
                return "started"
            except RuntimeError as e:
                return str(e)
        return "returned"

    def test_a_server_that_would_keep_logs_refuses_before_touching_the_host(self):
        out = self.start("relay", [("/var/log in RAM", False, "root disk"), ("no swap", False, "/swapfile")])
        self.assertIn("would keep logs on disk (/var/log in RAM; no swap)", out)

    def test_a_clean_server_starts(self):
        self.assertEqual(self.start("exit", []), "started")

    def test_a_shared_host_is_let_through_and_lab_and_clients_are_exempt(self):
        failing = [("no disk logger running", False, "rsyslog.service")]
        self.assertEqual(self.start("exit", failing, shared=True), "started")
        self.assertEqual(self.start("relay", failing, lab=True), "started")
        self.assertEqual(self.start("client", failing), "started")

    def test_doctor_shows_the_checks_on_servers_only(self):
        import avpnctl
        import retention

        rows = [("no swap", False, "/swapfile"), ("/var/log in RAM", True, "tmpfs")]
        missing = self.root / "no-such-marker"
        with (
            mock.patch.object(retention, "checks", lambda: rows),
            mock.patch.object(retention, "SHARED_MARKER", missing),
        ):
            server = {c["check"]: c for c in avpnctl.doctor(self.root / "relay")}
            client = {c["check"] for c in avpnctl.doctor(self.root / "client")}
        self.assertFalse(server["no swap"]["ok"])
        self.assertTrue(server["/var/log in RAM"]["ok"])
        self.assertNotIn("no swap", client)
        marker = self.root / "shared-doctor"
        marker.write_text("")
        with mock.patch.object(retention, "SHARED_MARKER", marker):
            server = {c["check"]: c for c in avpnctl.doctor(self.root / "relay")}
        self.assertFalse(server["no retained data"]["ok"])
        self.assertIn("shared host", server["no retained data"]["detail"])


if __name__ == "__main__":
    unittest.main()

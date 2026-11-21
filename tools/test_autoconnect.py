#!/usr/bin/env python3
"""Tests for auto-connect on untrusted networks (tools/autoconnect.py):
the opt-in gate, the trust matrix, fail-closed behavior on malformed
policies and events, the never-disconnect rule, and the NetworkManager
dispatcher translation — with the action injected, never executed."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import autoconnect as ac  # noqa: E402


def policy_on(ssids=(), wired=False, path=None):
    doc = {"schema": 1, "enabled": True, "trusted": {"ssids": list(ssids), "wired": wired}}
    if path is not None:
        path.write_text(json.dumps(doc))
    return doc


class PolicyLoadingTests(unittest.TestCase):
    def test_missing_policy_is_off(self):
        self.assertIsNone(ac.load_policy(Path("/nonexistent/autoconnect.json")))

    def test_disabled_policy_is_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "autoconnect.json"
            p.write_text(json.dumps({"schema": 1, "enabled": False}))
            self.assertIsNone(ac.load_policy(p))

    def test_enabled_policy_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "autoconnect.json"
            policy_on(ssids=["home-net"], path=p)
            doc = ac.load_policy(p)
            self.assertTrue(doc["enabled"])
            self.assertEqual(doc["trusted"]["ssids"], ["home-net"])

    def test_malformed_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "autoconnect.json"
            p.write_text("{not json")
            with self.assertRaises(ac.PolicyError):
                ac.load_policy(p)

    def test_bad_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "autoconnect.json"
            p.write_text(json.dumps({"schema": 99, "enabled": True}))
            with self.assertRaises(ac.PolicyError):
                ac.load_policy(p)

    def test_bad_ssid_list_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "autoconnect.json"
            p.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "enabled": True,
                        "trusted": {"ssids": ["", "x" * 33], "wired": False},
                    }
                )
            )
            with self.assertRaises(ac.PolicyError):
                ac.load_policy(p)


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy_on(ssids=["home-net", "office-5g"], wired=False)

    def test_unlisted_wifi_is_untrusted(self):
        decision = ac.classify({"action": "up", "medium": "wifi", "ssid": "Starbucks-Guest"}, self.policy)
        self.assertEqual(decision, ac.CONNECT)

    def test_allowlisted_wifi_is_trusted(self):
        decision = ac.classify({"action": "up", "medium": "wifi", "ssid": "home-net"}, self.policy)
        self.assertEqual(decision, ac.NO_OP)

    def test_wired_untrusted_by_default(self):
        decision = ac.classify({"action": "up", "medium": "wired"}, self.policy)
        self.assertEqual(decision, ac.CONNECT)

    def test_wired_trusted_when_opted_in(self):
        policy = policy_on(wired=True)
        self.assertEqual(ac.classify({"action": "up", "medium": "wired"}, policy), ac.NO_OP)

    def test_down_events_never_act(self):
        """The never-disconnect rule: only 'up'/'connectivity-change'
        can trigger; a trusted network going down is never an action."""
        for action in ("down", "removed", "lost", "deactivating"):
            self.assertEqual(ac.classify({"action": action, "medium": "wifi", "ssid": "x"}, self.policy), ac.NO_OP)

    def test_disabled_policy_never_acts(self):
        self.assertEqual(ac.classify({"action": "up", "medium": "wifi", "ssid": "any"}, None), ac.NO_OP)

    def test_unknown_medium_fail_closed(self):
        self.assertEqual(ac.classify({"action": "up", "medium": "wimax"}, self.policy), ac.NO_OP)

    def test_empty_ssid_is_untrusted(self):
        """A wifi event with no SSID (captive portals often report
        this) is untrusted: fail-closed on missing data."""
        self.assertEqual(ac.classify({"action": "up", "medium": "wifi", "ssid": ""}, self.policy), ac.CONNECT)

    def test_connectivity_change_triggers(self):
        self.assertEqual(
            ac.classify({"action": "connectivity-change", "medium": "wifi", "ssid": "hotel"}, self.policy), ac.CONNECT
        )


class HandlerTests(unittest.TestCase):
    def test_action_is_exactly_avpn_connect(self):
        record = ac.handle({"action": "up", "medium": "wifi", "ssid": "x"}, policy_on())
        self.assertEqual(record["action"], ["/opt/advanced-vpn/bin/avpn", "connect"])

    def test_run_injection_records_exit_code(self):
        ran = []

        def fake_run(cmd):
            ran.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        record = ac.handle({"action": "up", "medium": "wifi", "ssid": "x"}, policy_on(), run=fake_run)
        self.assertEqual(ran, [["/opt/advanced-vpn/bin/avpn", "connect"]])
        self.assertEqual(record["rc"], 0)

    def test_trusted_event_runs_nothing(self):
        ran = []

        def fake_run(cmd):
            ran.append(cmd)
            raise AssertionError("must not run")

        record = ac.handle({"action": "up", "medium": "wifi", "ssid": "home"}, policy_on(ssids=["home"]), run=fake_run)
        self.assertEqual(record["decision"], ac.NO_OP)
        self.assertEqual(ran, [])

    def test_policy_error_never_acts(self):
        class Boom(ac.PolicyError):
            pass

        def raising_classify(event, policy):
            raise Boom("bad")

        original = ac.classify
        ac.classify = raising_classify
        try:
            ran = []

            def fake_run(cmd):
                ran.append(cmd)
                return subprocess.CompletedProcess(cmd, 0)

            record = ac.handle({"action": "up", "medium": "wifi"}, policy_on(), run=fake_run)
        finally:
            ac.classify = original
        self.assertEqual(record["decision"], ac.NO_OP)
        self.assertEqual(ran, [])


class DispatcherTranslationTests(unittest.TestCase):
    def test_wifi_event_from_nm_env(self):
        event = ac.event_from_env(
            ["/etc/NetworkManager/dispatcher.d/avpn-autoconnect", "wlan0", "up"],
            {"CONNECTION_ID": "Starbucks-Guest", "DEVICE_TYPE": "wifi"},
        )
        self.assertEqual(event["medium"], "wifi")
        self.assertEqual(event["ssid"], "Starbucks-Guest")
        self.assertEqual(event["action"], "up")

    def test_ethernet_event_from_nm_env(self):
        event = ac.event_from_env(
            ["/etc/NetworkManager/dispatcher.d/avpn-autoconnect", "enp3s0", "up"],
            {"DEVICE_TYPE": "ethernet"},
        )
        self.assertEqual(event["medium"], "wired")
        self.assertIsNone(event.get("ssid") or None)

    def test_no_action_argument_is_none(self):
        self.assertIsNone(ac.event_from_env(["script", "wlan0"], {}))

    def test_end_to_end_with_env_and_policy(self):
        """The dispatcher path: env -> event -> decision, with the
        action injected (nothing executes)."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "autoconnect.json"
            policy_on(ssids=["home"], path=p)
            policy = ac.load_policy(p)
            event = ac.event_from_env(
                ["script", "wlan0", "up"],
                {"CONNECTION_ID": "airport-free-wifi", "DEVICE_TYPE": "wifi"},
            )
            record = ac.handle(event, policy)
            self.assertEqual(record["decision"], ac.CONNECT)


if __name__ == "__main__":
    unittest.main(verbosity=2)

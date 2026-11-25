"""Exercise saved-chain verification and activation with isolated signed bundles."""

import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from cryptography.exceptions import InvalidSignature

import cypherpunkctl
from keyguard import atomic, read_private
from managed_profile import SoftwareOperator, canonical, create, lab_setup, write_signature
import saved_chains


class SavedChainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "client"
        self.signer = SoftwareOperator(self.root / "operator-keys")
        self.first = lab_setup(self.root, "192.0.2.10:443", "198.51.100.10:443", operator=self.signer) / "client.cpvpn"
        self.second = self.build("second", self.signer, "198.51.100.20:443")
        self.pin = mock.patch.object(cypherpunkctl, "service_active", return_value=False)
        self.active = self.pin.start()
        self.addCleanup(self.pin.stop)
        exclusion = mock.patch.object(
            cypherpunkctl, "supervisor_locks", side_effect=lambda state: contextlib.nullcontext()
        )
        self.lock = exclusion.start()
        self.addCleanup(exclusion.stop)

    def build(self, name, signer, exit_):
        requests = {role: read_private(self.root / role / "request.json") for role in ("client", "relay", "exit")}
        out = self.root / name
        create(out, requests, "192.0.2.20:443", exit_, signer)
        return out / "client.cpvpn"

    def route(self):
        return cypherpunkctl.load_profile(self.state)["network"]["exit_endpoint"]

    def test_switch_both_ways_preserves_device_and_preferences(self):
        self.assertFalse(saved_chains.list_chains(self.state)["active_saved"])
        saved_chains.import_bundle(self.state, "first", self.first)
        saved_chains.import_bundle(self.state, "second", self.second)
        prefs = b'{"mode":"applications","daily_limit_mib":7}'
        atomic(self.state / "preferences.json", prefs)
        device = read_private(self.state / "request.json")
        saved_chains.set_label(self.state, "198.51.100.20:443", "DE", "Frankfurt")
        saved_chains.select_chain(self.state, "second")
        self.lock.assert_called_with(self.state)
        listed = saved_chains.list_chains(self.state)
        self.assertEqual(listed["current"][-1]["city"], "Frankfurt")
        self.assertEqual(self.route(), "198.51.100.20:443")
        self.assertEqual(read_private(self.state / "preferences.json"), prefs)
        self.assertEqual(read_private(self.state / "request.json"), device)
        saved_chains.select_chain(self.state, "first")
        self.assertEqual(self.route(), "198.51.100.10:443")

    def test_running_service_and_failed_preparation_keep_active_chain(self):
        saved_chains.import_bundle(self.state, "second", self.second)
        with self.assertRaisesRegex(ValueError, "original bundle"):
            saved_chains.select_chain(self.state, "second")
        self.active.return_value = True
        with self.assertRaisesRegex(RuntimeError, "Disconnect"):
            saved_chains.select_chain(self.state, "second", True)
        self.active.return_value = False
        with mock.patch.object(saved_chains, "enroll", side_effect=RuntimeError("hardware unlock failed")):
            with self.assertRaisesRegex(RuntimeError, "hardware"):
                saved_chains.select_chain(self.state, "second", True)
        self.assertEqual(self.route(), "198.51.100.10:443")
        self.assertFalse((self.root / ".client-chain-stage").exists())
        self.assertTrue(saved_chains.list_chains(self.state)["saved"][0]["available"])

    def test_interrupted_staging_never_replaces_active_profile(self):
        saved_chains.import_bundle(self.state, "second", self.second)
        stage = self.root / ".client-chain-stage"
        stage.mkdir(mode=0o700)
        (stage / "partial").write_text("incomplete")
        with mock.patch.object(saved_chains, "_exchange", side_effect=OSError("exchange failed")):
            with self.assertRaisesRegex(OSError, "exchange failed"):
                saved_chains.select_chain(self.state, "second", True)
        self.assertEqual(self.route(), "198.51.100.10:443")
        self.assertFalse(stage.exists())

    def test_wrong_operator_wrong_device_tamper_and_signed_expiry(self):
        foreign = self.build("foreign", SoftwareOperator(self.root / "foreign-keys"), "198.51.100.30:443")
        with self.assertRaises(InvalidSignature):
            saved_chains.import_bundle(self.state, "foreign", foreign)
        other = self.root / "other-device"
        saved_chains.private_dir(other, create=True)
        other_bundle = lab_setup(other, "192.0.2.30:443", "198.51.100.30:443", operator=self.signer)
        with self.assertRaisesRegex(ValueError, "another device"):
            saved_chains.import_bundle(self.state, "other", other_bundle / "client.cpvpn")
        tampered, expired = self.root / "tampered.cpvpn", self.root / "expired.cpvpn"
        with zipfile.ZipFile(self.second) as original:
            with zipfile.ZipFile(tampered, "x") as altered:
                for name in original.namelist():
                    data = original.read(name)
                    altered.writestr(name, data + b" " if name == "profile.json" else data)
            with zipfile.ZipFile(expired, "x") as altered:
                value = json.loads(original.read("set.json"))
                value["expires"] = "2000-01-01T00:00:00Z"
                signed = canonical(value)
                for name in original.namelist():
                    if not name.startswith("set."):
                        altered.writestr(name, original.read(name))
                altered.writestr("set.json", signed)
                write_signature(altered, *self.signer.sign(signed))
        with self.assertRaisesRegex(ValueError, "integrity"):
            saved_chains.import_bundle(self.state, "tampered", tampered)
        with self.assertRaisesRegex(ValueError, "expired"):
            saved_chains.import_bundle(self.state, "expired", expired)

    def test_exact_endpoint_conflicts_and_standby_label(self):
        profile = cypherpunkctl.load_profile(self.state)
        records = [{"provider": "oci", "region": "me-dubai-1", "public_ip": "192.0.2.10", "port": 443}]
        entry, exit_ = saved_chains.describe_hops(profile, {}, records)
        self.assertEqual(
            (entry["city"], entry["country"], entry["location_source"]),
            ("Dubai", "United Arab Emirates", "inventory-derived"),
        )
        self.assertIsNone(exit_["country"])
        records.append({"provider": "fly", "region": "fra", "public_ip": "192.0.2.10", "port": 443})
        self.assertIsNone(saved_chains.describe_hops(profile, {}, records)[0]["country"])
        profile["core"]["inner"]["peer_members"] = ["standby is possible"]
        hops = saved_chains.describe_hops(profile, {"192.0.2.10:443": ("SE", "Stockholm")}, records)
        self.assertEqual(hops[0]["country"], "Sweden")
        self.assertTrue(hops[-1]["primary"])

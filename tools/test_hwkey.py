"""Tests for tools/hwkey.py against simulated devices: a fake /sys tree, fake udev answers
and a fake CTAP probe. Each case is one situation setup must recognise; the same fixture
can generate the scenarios a setup assistant is trained and evaluated on."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import hwkey as h

FIDO_DESCRIPTOR = b"\x06\xd0\xf1\x09\x01\xa1\x01"
MOUSE_DESCRIPTOR = b"\x05\x01\x09\x02\xa1\x01"
READY = dict(ctap2=True, versions=["FIDO_2_0"], hmac_secret=True, pin_set=True, pin_retries=8, firmware=1)


class Sim:
    """A simulated machine: hidraw and USB devices in a temporary /sys tree."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sys = Path(self.tmp.name)
        self.udev, self.access, self.probes = {}, {}, {}
        self.management = {}

    def hid(self, node, vendor, product, name, descriptor=FIDO_DESCRIPTOR, tagged=True, access=True, probe=None):
        d = self.sys / "class/hidraw" / node / "device"
        d.mkdir(parents=True)
        (d / "uevent").write_text(f"HID_ID=0003:0000{vendor}:0000{product}\nHID_NAME={name}\n")
        (d / "report_descriptor").write_bytes(descriptor)
        self.udev[node] = (
            {} if tagged is None else ({"ID_FIDO_TOKEN": "1", "TAGS": ":uaccess:"} if tagged else {"ID_INPUT": "1"})
        )
        self.access["/dev/" + node] = access
        self.probes[node] = probe if probe is not None else READY

    def usb(self, port, vendor, product, name):
        d = self.sys / "bus/usb/devices" / port
        d.mkdir(parents=True)
        (d / "idVendor").write_text(vendor.lower() + "\n")
        (d / "idProduct").write_text(product.lower() + "\n")
        (d / "product").write_text(name + "\n")

    def probe(self, node):
        p = self.probes[node]
        if isinstance(p, Exception):
            raise p
        return p

    def diagnose(self):
        devices = h.hid_devices(self.sys, Path("/dev"), udev=lambda n: self.udev[n], access=lambda p: self.access[p])
        return h.diagnose(devices, h.usb_devices(self.sys), probe=self.probe, management=lambda: self.management)

    def codes(self):
        return [f.code for f in self.diagnose()]


class Diagnose(unittest.TestCase):
    def setUp(self):
        self.s = Sim()

    def tearDown(self):
        self.s.tmp.cleanup()

    def test_a_ready_nitrokey(self):
        self.s.hid("hidraw0", "046D", "C077", "Mouse", MOUSE_DESCRIPTOR, tagged=False, access=False)
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3")
        [f] = self.s.diagnose()
        self.assertEqual((f.code, f.severity, f.device), ("key_ready", "ok", "hidraw2"))
        self.assertIn("Nitrokey 3", f.message)

    def test_no_key_at_all(self):
        self.s.hid("hidraw0", "046D", "C077", "Mouse", MOUSE_DESCRIPTOR, tagged=False)
        self.assertEqual(self.s.codes(), ["no_key"])

    def test_existing_desktop_access_tag_requires_session_or_acl_diagnosis(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", access=False, tagged=True)
        [f] = self.s.diagnose()
        self.assertEqual((f.code, f.repair), ("desktop_access_denied", None))

    def test_denied_without_the_tag_offers_the_udev_rule(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", access=False, tagged=None)  # old udev: no fido_id
        [f] = self.s.diagnose()
        self.assertEqual((f.code, f.repair), ("permission_denied", "install_udev_rule"))

    def test_the_descriptor_finds_a_key_when_udev_says_nothing(self):
        self.s.hid("hidraw5", "20A0", "42B1", "Nitrokey 3", tagged=None)
        self.assertEqual(self.s.codes(), ["key_ready"])

    def test_a_yubikey_with_fido2_switched_off(self):
        self.s.usb("1-2", "1050", "0407", "YubiKey OTP+FIDO+CCID")  # no FIDO hidraw for it
        self.s.management = dict(fido2="Disabled", serial="12345678", firmware="5.2.7", locked=False)
        [f] = self.s.diagnose()
        self.assertEqual((f.code, f.repair), ("fido2_disabled", "yubikey_enable_fido2"))
        self.assertIn("OTP slots", f.message)

    def test_a_yubikey_with_fido2_on_is_not_reported_disabled(self):
        self.s.usb("1-2", "1050", "0407", "YubiKey OTP+FIDO+CCID")
        self.s.hid("hidraw3", "1050", "0407", "YubiKey")
        self.assertEqual(self.s.codes(), ["key_ready"])

    def test_capability_problems_block_in_order(self):
        cases = [
            (dict(ctap2=False), "no_ctap2"),
            (dict(READY, hmac_secret=False), "no_hmac_secret"),
            (dict(READY, pin_set=False, pin_retries=None), "pin_not_set"),
            (dict(READY, pin_retries=0), "pin_blocked"),
            (OSError("device busy"), "probe_failed"),
        ]
        for probe, code in cases:
            with self.subTest(code=code):
                s = Sim()
                s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", probe=probe)
                [f] = s.diagnose()
                self.assertEqual((f.code, f.severity), (code, "blocker"))
                s.tmp.cleanup()

    def test_a_blocked_pin_never_offers_a_reset_as_a_repair(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", probe=dict(READY, pin_retries=0))
        [f] = self.s.diagnose()
        self.assertIsNone(f.repair)
        self.assertIn("deletes every credential", f.message)

    def test_few_pin_retries_warn_but_the_key_is_still_ready(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", probe=dict(READY, pin_retries=2))
        self.assertEqual(self.s.codes(), ["pin_retries_low", "key_ready"])

    def test_two_ready_keys_ask_which_one(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3")
        self.s.hid("hidraw3", "1050", "0407", "YubiKey")
        self.assertEqual(self.s.codes(), ["several_keys", "key_ready", "key_ready"])


class AdditionalDiagnostics(unittest.TestCase):
    def setUp(self):
        self.s = Sim()

    def tearDown(self):
        self.s.tmp.cleanup()

    def test_on_device_verification_is_accepted_without_a_host_pin(self):
        self.s.hid("hidraw3", "1209", "53C1", "Trezor", probe=dict(READY, pin_set=False, uv=True, pin_retries=None))
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "key_ready")
        self.assertEqual(finding.detail["verification"], "on_device")

    def test_ranking_prefers_open_firmware_then_a_pin_entered_on_the_key(self):
        on_key = dict(READY, pin_set=False, uv=True, pin_retries=None)
        cases = [
            ("1209", "53C1", "Trezor", on_key, "cypherpunk_preferred", 1, "entered on the key"),
            ("20A0", "42B2", "Nitrokey 3", READY, "cypherpunk_preferred", 2, "typed on this computer"),
            ("0483", "A2CA", "Solo", READY, "cypherpunk_preferred", 2, "typed on this computer"),
            ("1209", "BEEE", "Solo 2", READY, "cypherpunk_preferred", 2, "typed on this computer"),
            ("20A0", "42D4", "CanoKey", READY, "cypherpunk_preferred", 2, "typed on this computer"),
            ("1207", "8887", "TKey", READY, "cypherpunk_preferred", 2, "typed on this computer"),
            ("2C97", "5000", "Ledger", on_key, "closed_source", 3, "entered on the key"),
            ("1050", "0407", "YubiKey", READY, "closed_source", 4, "typed on this computer"),
            ("0483", "5740", "Other ST device", READY, "unranked", 5, "typed on this computer"),
        ]
        for vendor, product, name, probe, tier, place, pin in cases:
            with self.subTest(name):
                s = Sim()
                try:
                    s.hid("hidraw2", vendor, product, name, probe=probe)
                    [f] = s.diagnose()
                finally:
                    s.tmp.cleanup()
                self.assertEqual(f.code, "key_ready")
                self.assertEqual((f.detail["tier"], f.detail["rank"]), (tier, place))
                self.assertIn(pin, f.message)
                # Every key is flagged: the PIN/hmac-secret channel on USB is P-256 for all of them.
                self.assertEqual(f.detail["usb_channel"], "p256_ecdh_ctap_pin_uv_1_2")
                self.assertIn("not post-quantum", f.message)

    def test_every_key_the_documented_ranking_names_is_ranked_by_setup(self):
        """The ranking table and hwkey.FIRMWARE name the same families, and each one is
        reachable from a USB id, so no documented key is reported as unranked."""
        doc = (Path(__file__).resolve().parents[1] / "docs/DEVICE_COMPATIBILITY_VALIDATION.md").read_text()
        table = doc[doc.index("## Ranking") :]
        named = set()
        for row in re.findall(r"^\| [1-4] \|[^|]*\| ([^|]*) \|", table, re.M):
            named |= {name.strip().removesuffix(" 5") for name in row.split(",")}
        self.assertEqual(named, set(h.FIRMWARE))
        reachable = set(h.KNOWN_KEYS.values()) | set(h.RANKED_ONLY.values())
        self.assertLessEqual(set(h.FIRMWARE), reachable)

    def test_fido_classification_does_not_imply_desktop_access_tag(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", access=False)
        self.s.udev["hidraw2"].pop("TAGS")
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "permission_denied")

    def test_old_uaccess_tag_does_not_hide_removed_access_in_current_event(self):
        self.s.hid("hidraw2", "20A0", "42B2", "Nitrokey 3", access=False)
        self.s.udev["hidraw2"]["CURRENT_TAGS"] = ":seat:security-device:"
        [finding] = self.s.diagnose()
        self.assertEqual((finding.code, finding.repair), ("permission_denied", "install_udev_rule"))
        self.s.udev["hidraw2"]["CURRENT_TAGS"] = ""
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "permission_denied")

    def test_missing_hid_never_proves_disabled_fido2(self):
        self.s.usb("1-2", "1050", "0407", "YubiKey")
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "fido2_unknown")
        self.assertIsNone(finding.repair)

    def test_locked_and_unsupported_devices_get_no_enable_repair(self):
        self.s.usb("1-2", "1050", "0407", "YubiKey")
        for state, locked, code in [
            ("Disabled", True, "configuration_locked"),
            ("Not available", False, "fido2_unavailable"),
        ]:
            self.s.management = dict(fido2=state, serial="12345678", locked=locked)
            [finding] = self.s.diagnose()
            self.assertEqual(finding.code, code)
            self.assertIsNone(finding.repair)

    def test_multiple_usb_keys_do_not_select_a_target_by_guessing(self):
        self.s.usb("1-2", "1050", "0407", "YubiKey A")
        self.s.usb("1-3", "1050", "0407", "YubiKey B")
        self.s.management = dict(fido2="Disabled", serial="12345678")
        self.assertFalse(any(f.repair for f in self.s.diagnose()))

    def test_all_four_families_offer_a_rule_only_when_access_is_missing(self):
        families = [
            ("20A0", "42B2", "Nitrokey"),
            ("1050", "0407", "YubiKey"),
            ("1209", "53C1", "Trezor"),
            ("2C97", "5011", "Ledger"),
        ]
        for vendor, product, name in families:
            for access, tagged, expected in [
                (True, True, "key_ready"),
                (False, False, "permission_denied"),
                (False, True, "desktop_access_denied"),
            ]:
                with self.subTest(name=name, access=access, tagged=tagged):
                    s = Sim()
                    try:
                        s.hid(
                            "hidraw3",
                            vendor,
                            product,
                            name,
                            access=access,
                            probe=dict(READY, uv=True, pin_set=False, pin_retries=None),
                        )
                        if not tagged:
                            s.udev["hidraw3"]["TAGS"] = ""
                        [finding] = s.diagnose()
                        self.assertEqual(finding.code, expected)
                        self.assertEqual(
                            finding.repair, "install_udev_rule" if expected == "permission_denied" else None
                        )
                    finally:
                        s.tmp.cleanup()

    def test_locked_ledger_prompts_for_security_key_app_without_wallet_repair(self):
        self.s.hid("hidraw3", "2C97", "5011", "Ledger", probe=dict(ctap2=False))
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "no_ctap2")
        self.assertIn("Security Key app", finding.message)
        self.assertIsNone(finding.repair)

    def test_connected_ledger_without_fido_is_not_reported_unplugged(self):
        self.s.usb("1-2", "2C97", "5011", "Ledger")
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "key_interface_unknown")
        self.assertIn("Security Key app", finding.message)
        self.assertIsNone(finding.repair)

    def test_unknown_model_cannot_gain_a_vendor_rule_by_claiming_a_known_name(self):
        self.s.hid("hidraw3", "FFFF", "0001", "Ledger", access=False, tagged=None)
        [finding] = self.s.diagnose()
        self.assertEqual(finding.code, "permission_denied")
        self.assertIsNone(finding.repair)


class Repairs(unittest.TestCase):
    def test_wallet_rules_never_grant_wallet_transport_or_world_access(self):
        rules = h.UDEV_RULE.splitlines()
        for vendor in ("1209", "2c97"):
            [rule] = [line for line in rules if f'idVendor}}=="{vendor}"' in line]
            self.assertIn('SUBSYSTEM=="hidraw"', rule)
            self.assertIn('ENV{ID_FIDO_TOKEN}=="1"', rule)
            self.assertIn('TAG+="uaccess"', rule)
        self.assertNotIn("MODE=", h.UDEV_RULE)
        self.assertNotIn("GROUP=", h.UDEV_RULE)
        self.assertNotIn('SUBSYSTEM=="usb"', h.UDEV_RULE)

    def test_only_the_two_known_repairs_exist_and_none_is_destructive(self):
        for rid in ("install_udev_rule", "yubikey_enable_fido2"):
            r = h.plan(rid)
            self.assertFalse(r.destructive)
            self.assertTrue(r.undo)
        with self.assertRaises(ValueError):
            h.plan("fido_reset")

    def test_the_yubikey_repair_touches_only_fido2_over_usb(self):
        self.assertEqual(
            h.plan("yubikey_enable_fido2").commands, [["ykman", "config", "usb", "--enable", "FIDO2", "--force"]]
        )

    def test_nothing_runs_without_confirmation(self):
        ran = []
        with self.assertRaises(PermissionError):
            h.apply(h.plan("yubikey_enable_fido2", "12345678"), confirmed=False, run=lambda *a, **k: ran.append(a))
        self.assertEqual(ran, [])

    def test_root_steps_go_through_sudo_the_rule_is_written_and_a_failure_stops_the_rest(self):
        ran = []

        def run(argv, input=None, text=None, env=None, stdout=None):
            import sys

            self.assertIs(stdout, sys.stderr)
            ran.append((argv, input))
            return subprocess.CompletedProcess(argv, 1 if argv[1] == "udevadm" else 0)

        codes = h.apply(h.plan("install_udev_rule"), confirmed=True, run=run)
        self.assertEqual(codes, [0, 1])  # the reload failed: trigger is not attempted
        self.assertEqual(ran[0][0][:2], ["/usr/bin/sudo", "install"])
        self.assertIn('ATTRS{idVendor}=="20a0"', ran[0][1])
        self.assertEqual(len(ran), 2)


class BoundedProbe(unittest.TestCase):
    def test_device_timeout_and_worker_errors_are_diagnostics(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("probe", 10)

        with self.assertRaises(TimeoutError):
            h.ctap_probe("hidraw2", run=timeout)
        with self.assertRaises(OSError):
            h.ctap_probe("hidraw2", run=lambda *a, **k: subprocess.CompletedProcess(a, 1, "", ""))
        with self.assertRaises(OSError):
            h.ctap_probe("hidraw2", run=lambda *a, **k: subprocess.CompletedProcess(a, 0, "[]", ""))

    def test_worker_has_an_exact_node_deadline_and_clean_environment(self):
        seen = []

        def run(argv, **kwargs):
            seen.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, '{"ctap2":true}', "")

        self.assertTrue(h.ctap_probe("hidraw2", run=run)["ctap2"])
        self.assertEqual(seen[0][0][-2:], ["--probe", "hidraw2"])
        self.assertEqual(seen[0][1]["timeout"], 10)
        self.assertNotIn("PYTHONPATH", seen[0][1]["env"])
        for node in ("../hidraw2", "hidraw2;id", "--reset"):
            with self.assertRaises(ValueError):
                h.ctap_probe(node, run=run)
        self.assertEqual(len(seen), 1)


class RepairOutput(unittest.TestCase):
    def test_vendor_stdout_cannot_corrupt_controller_json(self):
        import contextlib
        import io
        import json
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / "vendor-tool"
            helper.write_text('#!/usr/bin/python3\nprint("vendor progress")\n')
            helper.chmod(0o700)
            output = io.StringIO()
            with tempfile.TemporaryFile(mode="w+") as diagnostic:
                with patch("sysexec.trusted_exe", return_value=str(helper)):
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostic):
                        codes = h.apply(h.plan("yubikey_enable_fido2", "12345678"), confirmed=True)
                        print(json.dumps(dict(ok=codes == [0])))
                diagnostic.seek(0)
                self.assertIn("vendor progress", diagnostic.read())
            self.assertEqual(json.loads(output.getvalue()), dict(ok=True))


class DeviceSummary(unittest.TestCase):
    def sysfs(self, devices):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, root)
        for i, (vendor, product, bcd) in enumerate(devices):
            d = root / "bus/usb/devices" / ("1-%d" % i)
            d.mkdir(parents=True)
            (d / "idVendor").write_text(vendor.lower() + "\n")
            (d / "idProduct").write_text(product.lower() + "\n")
            (d / "bcdDevice").write_text(bcd + "\n")
        return root

    def ready(self, firmware=0):
        detail = dict(vendor="20A0", product="42B2", firmware=firmware, tier="cypherpunk_preferred",
                      verification="pin", pin_retries=8)  # fmt: skip
        return [h.Finding("key_ready", "ok", "ready", "hidraw2", detail)]

    def test_nitrokey_firmware_comes_from_its_usb_release_when_fido2_gives_none(self):
        sysfs = self.sysfs([("20A0", "42B2", "0109"), ("1D6B", "0002", "0612")])
        s = h.device_summary(self.ready(), sysfs)
        self.assertEqual((s["name"], s["firmware"], s["firmware_source"]), ("Nitrokey 3", "1.9", "usb"))
        self.assertTrue(s["open_firmware"])
        self.assertEqual(s["pin_retries"], 8)

    def test_a_fido2_firmware_version_wins_and_two_same_keys_are_not_guessed(self):
        sysfs = self.sysfs([("20A0", "42B2", "0109"), ("20A0", "42B2", "0108")])
        self.assertEqual(h.device_summary(self.ready(), sysfs)["firmware"], None)
        self.assertEqual(h.device_summary(self.ready(firmware=7), sysfs)["firmware"], "7")
        self.assertIsNone(h.device_summary([], sysfs))


if __name__ == "__main__":
    unittest.main()

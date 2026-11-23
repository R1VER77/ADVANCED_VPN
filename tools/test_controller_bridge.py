"""Attacker/replay/staleness/cancellation counterexamples for the controller boundary."""

import contextlib
import json
import threading
import time
import unittest

import controller_bridge as bridge


class Adapter:
    def __init__(self):
        self.version = "one"
        self.hardware = "same-device"
        self.calls = []
        self.mutex = threading.RLock()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.wait = False

    @contextlib.contextmanager
    def locked(self):
        with self.mutex:
            yield

    def generation(self):
        return self.version

    def prepare(self, caller, request):
        return dict(summary="Exact reviewed action", effects=[request["action"]], checked_inputs=self.hardware)

    def execute(self, caller, request, cancel, progress):
        self.calls.append((caller, request))
        self.entered.set()
        if self.wait:
            progress("waiting_for_hardware", "Touch the selected hardware device.")
            deadline = time.monotonic() + 2
            while not self.release.wait(0.01):
                if cancel.is_set():
                    raise InterruptedError
                if time.monotonic() > deadline:
                    raise TimeoutError("test deadline")


class CallerPlans(unittest.TestCase):
    def setUp(self):
        self.adapter = Adapter()
        self.tick = 100
        self.broker = bridge.Broker(self.adapter, clock=lambda: self.tick, wall=lambda: 1000)
        self.caller = bridge.Caller("a" * 32, ":1.42", 1000)
        self.other = bridge.Caller("a" * 32, ":1.43", 1000)

    def preview(self):
        return self.broker.preview(self.caller, '{"action":"disconnect"}')

    def finished(self, operation):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            result = self.broker.operation(self.caller, operation["id"])
            if result["state"] in ("complete", "failed", "cancelled"):
                return result
            time.sleep(0.01)
        self.fail("operation did not finish")

    def test_one_use_binds_live_bus_identity_not_only_uid(self):
        plan = self.preview()
        for other in (self.other, bridge.Caller("b" * 32, self.caller.name, self.caller.uid)):
            with self.assertRaises(bridge.Refused):
                self.broker.apply(other, plan["id"])
        result = self.finished(self.broker.apply(self.caller, plan["id"]))
        self.assertEqual(result["state"], "complete")
        with self.assertRaises(bridge.Refused):
            self.broker.apply(self.caller, plan["id"])
        self.assertEqual(len(self.adapter.calls), 1)

    def test_changed_configuration_or_device_consumes_and_refuses_plan(self):
        for changed in ("version", "hardware"):
            with self.subTest(changed=changed):
                plan = self.preview()
                setattr(self.adapter, changed, "changed-" + changed)
                with self.assertRaisesRegex(bridge.Refused, "inputs_changed"):
                    self.broker.apply(self.caller, plan["id"])
                with self.assertRaises(bridge.Refused):
                    self.broker.apply(self.caller, plan["id"])
        self.assertEqual(self.adapter.calls, [])

    def test_expiry_uses_monotonic_time(self):
        plan = self.preview()
        self.tick += bridge.PLAN_TTL
        with self.assertRaises(bridge.Refused):
            self.broker.apply(self.caller, plan["id"])
        self.assertFalse(self.adapter.calls)

    def test_native_review_is_owned_inert_expiring_and_cannot_mutate_stored_effects(self):
        plan = self.preview()
        for caller in (self.other, bridge.Caller("b" * 32, self.caller.name, self.caller.uid)):
            with self.assertRaises(bridge.Refused):
                self.broker.plan(caller, plan["id"])
        reviewed = self.broker.plan(self.caller, plan["id"])
        self.assertEqual(reviewed, plan)
        reviewed["effects"].append("untrusted edit")
        self.assertEqual(self.broker.plan(self.caller, plan["id"]), plan)
        self.assertFalse(self.adapter.calls)
        self.tick += bridge.PLAN_TTL
        with self.assertRaises(bridge.Refused):
            self.broker.plan(self.caller, plan["id"])

    def test_strict_action_schema_refuses_commands_paths_credentials_and_duplicates(self):
        attacks = [
            dict(action="shell", command="id"),
            dict(action="disconnect", pin="PRIVATE"),
            dict(action="import_bundle", path="/etc/shadow"),
            dict(action="connect", scope="anything"),
            dict(action="repair", repair="yubikey_enable_fido2", selector="--reset"),
            dict(action="repair", repair="install_udev_rule", selector="/dev/../etc/shadow"),
            dict(action="key_software", mode="remove"),
            dict(action="key_software", mode="install", packages=["openssh-server"]),
            dict(action="key_software"),
        ]
        for request in attacks:
            with self.subTest(request=request), self.assertRaises(bridge.Refused):
                self.broker.preview(self.caller, json.dumps(request))
        with self.assertRaises(bridge.Refused):
            self.broker.preview(self.caller, '{"action":"disconnect","action":"unlock"}')
        self.assertFalse(self.broker.plans)

    def test_limits_prevent_unbounded_plan_storage(self):
        for _ in range(bridge.MAX_PER_CALLER):
            self.preview()
        with self.assertRaisesRegex(bridge.Refused, "too_many"):
            self.preview()
        self.tick += bridge.PLAN_TTL + 1
        self.preview()
        self.assertEqual(len(self.broker.plans), 1)

    def test_cancellation_is_owned_and_remains_responsive_during_hardware_prompt(self):
        self.adapter.wait = True
        operation = self.broker.apply(self.caller, self.preview()["id"])
        self.assertTrue(self.adapter.entered.wait(1))
        with self.assertRaises(bridge.Refused):
            self.broker.cancel(self.other, operation["id"])
        self.broker.cancel(self.caller, operation["id"])
        self.assertEqual(self.finished(operation)["state"], "cancelled")
        self.assertEqual(self.adapter.calls[0][1], dict(action="disconnect"))

    def test_preview_cannot_queue_behind_a_hardware_prompt_and_block_cancel(self):
        self.adapter.wait = True
        operation = self.broker.apply(self.caller, self.preview()["id"])
        self.assertTrue(self.adapter.entered.wait(1))
        with self.assertRaisesRegex(bridge.Refused, "operation_is_running"):
            self.preview()
        self.broker.cancel(self.caller, operation["id"])
        self.assertEqual(self.finished(operation)["state"], "cancelled")


class KeyProbeCache(unittest.TestCase):
    def test_key_findings_reprobes_only_when_visible_device_or_state_changes(self):
        from pathlib import Path
        import tempfile
        from unittest import mock
        import controller_backend

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sysfs, dev = root / "sys", root / "dev"
            hid = sysfs / "class/hidraw/hidraw0/device"
            usb = sysfs / "bus/usb/devices/1-1"
            hid.mkdir(parents=True)
            usb.mkdir(parents=True)
            dev.mkdir(parents=True)
            (hid / "uevent").write_text("HID_NAME=Nitrokey\n")
            node = dev / "hidraw0"
            node.write_text("node")
            for name, val in (("idVendor", "20a0"), ("idProduct", "42b2"), ("busnum", "1"), ("devnum", "4")):
                (usb / name).write_text(val + "\n")
            udev_tags = {"hidraw0": {"TAGS": ":uaccess:"}}

            adapter = controller_backend.Adapter()
            caller = bridge.Caller("a" * 32, ":1.42", 1000)
            calls = []
            gen = ["g1"]

            def fake_diag(c):
                calls.append(c.uid)
                return ["ready-%d" % len(calls)]

            orig_fp = adapter.key_fingerprint
            fp = lambda: orig_fp(sysfs=sysfs, dev=dev, udev=lambda n: udev_tags.get(n, {}))  # noqa: E731
            with (
                mock.patch.object(adapter, "diagnostics", side_effect=fake_diag),
                mock.patch.object(adapter, "key_fingerprint", side_effect=fp),
                mock.patch.object(adapter, "generation", side_effect=lambda: gen[0]),
            ):
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "running"),)), ["ready-1"])
                # Unchanged poll does not talk to the key again.
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "running"),)), ["ready-1"])
                self.assertEqual(len(calls), 1)
                # Operation state change re-probes.
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "complete"),)), ["ready-2"])
                self.assertEqual(len(calls), 2)
                # Controller state generation change re-probes.
                gen[0] = "g2"
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "complete"),)), ["ready-3"])
                # udev property change re-probes.
                udev_tags["hidraw0"] = {"TAGS": ""}
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "complete"),)), ["ready-4"])
                # Device node permission/ctime change re-probes.
                node.chmod(0o660)
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "complete"),)), ["ready-5"])
                # USB device number change (re-plug) re-probes.
                (usb / "devnum").write_text("5\n")
                self.assertEqual(adapter.key_findings(caller, epoch=(("op1", "complete"),)), ["ready-6"])
                self.assertEqual(len(calls), 6)

            # A failed probe is never cached.
            with (
                mock.patch.object(adapter, "diagnostics", side_effect=[bridge.Refused("hardware_probe_failed"), ["ok"]]),
                mock.patch.object(adapter, "key_fingerprint", return_value="same"),
                mock.patch.object(adapter, "generation", return_value="same"),
            ):
                adapter.probe_cache = None
                with self.assertRaises(bridge.Refused):
                    adapter.key_findings(caller)
                self.assertEqual(adapter.key_findings(caller), ["ok"])


if __name__ == "__main__":
    unittest.main()

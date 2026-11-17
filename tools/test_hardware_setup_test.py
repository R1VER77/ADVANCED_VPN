"""Ensure physical-test tooling cannot pass with ambiguity, software-only reuse or damage."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import hardware_setup_test as smoke
import hwkey
import keyguard
import setup_flow


class HardwareTest(unittest.TestCase):
    def test_wrong_or_multiple_devices_never_pass_as_the_expected_key(self):
        key = hwkey.Finding("key_ready", "ok", "Ready", "hidraw2", dict(vendor=hwkey.NITROKEY))
        self.assertTrue(smoke.assess([key], "nitrokey")["ready"])
        self.assertFalse(smoke.assess([key], "ledger")["ready"])
        self.assertFalse(smoke.assess([key, key], "nitrokey")["ready"])
        denied = hwkey.Finding("permission_denied", "blocker", "Cannot open", "hidraw3")
        self.assertFalse(smoke.assess([key, denied], "nitrokey")["ready"])

    def fake_key(self, different_secret=False):
        calls = []
        secret = bytes(range(32))
        meta = dict(salt=keyguard.b64(bytes(32)), credential=keyguard.b64(b"test public record"))

        def enroll(vault):
            vault.mkdir(mode=0o700)
            (vault / "credential.json").write_text("test record")
            calls.append("enroll")

        def assertion(vault, message):
            calls.append("fresh assertion")
            return (bytes(reversed(secret)) if different_secret else secret), meta, dict(message=message)

        def verify(public, message, evidence):
            self.assertEqual(message, evidence["message"])
            calls.append("verify")

        return SimpleNamespace(
            enroll=enroll,
            hardware_secret=lambda vault: (secret, meta),
            hardware_assertion=assertion,
            credential_public=lambda vault: "test public key",
            verify_assertion=verify,
            seal_bytes=keyguard.seal_bytes,
            open_bytes=keyguard.open_bytes,
            unb64=keyguard.unb64,
            b64=keyguard.b64,
        ), calls

    def test_success_requires_a_fresh_assertion_and_removes_only_its_temporary_vault(self):
        api, calls = self.fake_key()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            existing = parent / "existing-vault"
            existing.mkdir()
            with patch("setup_flow.check_vault", return_value=setup_flow.Result("complete", "Valid")):
                report = smoke.roundtrip(parent, api)
            self.assertTrue(all(report.values()))
            self.assertEqual(calls, ["enroll", "fresh assertion", "verify"])
            self.assertEqual(list(parent.iterdir()), [existing])

    def test_wrong_hardware_secret_fails_and_still_removes_its_temporary_vault(self):
        from cryptography.exceptions import InvalidTag

        api, _ = self.fake_key(different_secret=True)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with patch("setup_flow.check_vault", return_value=setup_flow.Result("complete", "Valid")):
                with self.assertRaises(InvalidTag):
                    smoke.roundtrip(parent, api)
            self.assertEqual(list(parent.iterdir()), [])

    def test_read_only_results_never_contain_vendor_serials(self):
        key = hwkey.Finding("fido2_disabled", "blocker", "Enable FIDO2", detail=dict(serial="12345678"))
        self.assertNotIn("12345678", str(smoke.assess([key])))

    def test_broken_crypto_accepting_corrupted_data_can_never_pass(self):
        api, _ = self.fake_key()
        real_seal = api.seal_bytes
        saved = {}

        def seal(secret, meta, role, binding, payload):
            saved["payload"] = payload
            return real_seal(secret, meta, role, binding, payload)

        api.seal_bytes = seal
        api.open_bytes = lambda *args: saved["payload"]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with patch("setup_flow.check_vault", return_value=setup_flow.Result("complete", "Valid")):
                with self.assertRaisesRegex(RuntimeError, "corrupted envelope was accepted"):
                    smoke.roundtrip(parent, api)
            self.assertEqual(list(parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

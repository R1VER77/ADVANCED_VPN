"""Only validated public enrollment fields may cross the desktop boundary."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import controller_request
import managed_profile


class PublicEnrollmentRequest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "device"
        # Isolated software keys are a parser fixture, never a production device.
        self.request = managed_profile.request("client", self.state, "none")

    def write(self, request):
        (self.state / "request.json").write_bytes(managed_profile.canonical(request))

    def test_valid_projection_verifies_and_reads_only_the_public_record(self):
        read = controller_request.read_private
        with mock.patch.object(controller_request, "read_private", wraps=read) as reader:
            result = controller_request.public_request(self.state)
        self.assertEqual(reader.call_args.args, (self.state / "request.json",))
        self.assertEqual(result["sha256"], hashlib.sha256(result["text"].encode()).hexdigest())
        parsed, _ = managed_profile.load_request(result["text"], "client")
        self.assertEqual(parsed["certificates"], self.request["certificates"])

    def test_unknown_future_private_fields_are_not_exported(self):
        self.request["private_key"] = "PRIVATE_SENTINEL_MUST_NEVER_REACH_GUI"
        self.write(self.request)
        result = controller_request.public_request(self.state)
        self.assertNotIn("PRIVATE_SENTINEL", result["text"])
        self.assertNotIn("private_key", json.loads(result["text"]))

    def test_malformed_crypto_and_wrong_role_are_refused(self):
        for update in (dict(role="exit"), dict(schema=True), dict(certificates={}), dict(kem_public="AAAA")):
            with self.subTest(update=update):
                self.write(dict(self.request, **update))
                with self.assertRaises((ValueError, KeyError)):
                    controller_request.public_request(self.state)

    def test_missing_record_exports_nothing_and_symlink_is_refused(self):
        path = self.state / "request.json"
        path.rename(self.state / "original")
        self.assertIsNone(controller_request.public_request(self.state))
        path.symlink_to("original")
        with self.assertRaises((ValueError, OSError)):
            controller_request.public_request(self.state)

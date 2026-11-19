"""The operator's optional third signature half: an ML-DSA-44 FIDO2 credential on a separate
key (schema-3 operator). Assertions are built here exactly as a key builds them, signed by a
real ML-DSA-44 key, so every refusal is checked against genuine signatures."""

import base64
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from fido2 import cbor
from fido2.cose import EdDSA, MLDSA44

import keyguard
from managed_profile import (
    SoftwareOperator,
    canonical,
    read_operator,
    signature_members,
    verify_archive_signature,
    verify_operator,
    write_signature,
)


def cose(key_class, public):
    return keyguard.b64(cbor.encode(dict(key_class.from_cryptography_key(public))))


def assertion(private, message, rp=keyguard.RP, flags=0x05):
    """A WebAuthn assertion over SHA-256(message): user present and verified by default."""
    auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + (7).to_bytes(4, "big")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(message).digest()).rstrip(b"=").decode()
    client = json.dumps(dict(type="webauthn.get", challenge=challenge, origin="https://" + keyguard.RP)).encode()
    signature = private.sign(auth + hashlib.sha256(client).digest())
    return dict(
        authenticator_data=keyguard.b64(auth), client_data=keyguard.b64(client), signature=keyguard.b64(signature)
    )


class ThirdHalf(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.operator = SoftwareOperator(Path(self.tmp.name) / "op")
        self.pq_key = mldsa.MLDSA44PrivateKey.generate()
        self.public = dict(self.operator.public(), schema=3, hardware_mldsa44=cose(MLDSA44, self.pq_key.public_key()))
        self.message = canonical(dict(bundles={"client": "00" * 32}))
        classical, pq, _ = self.operator.sign(self.message)
        self.halves = (classical, pq, assertion(self.pq_key, self.message))

    def tearDown(self):
        self.tmp.cleanup()

    def test_all_three_halves_verify(self):
        verify_operator(self.public, self.message, *self.halves)

    def test_a_missing_third_half_is_refused(self):
        with self.assertRaisesRegex(ValueError, "ML-DSA-44 signature missing"):
            verify_operator(self.public, self.message, *self.halves[:2])

    def test_a_tampered_third_half_is_refused(self):
        bad = dict(self.halves[2])
        raw = bytearray(keyguard.unb64(bad["signature"]))
        raw[-1] ^= 1
        bad["signature"] = keyguard.b64(bytes(raw))
        with self.assertRaises(InvalidSignature):
            verify_operator(self.public, self.message, *self.halves[:2], bad)

    def test_a_third_half_for_another_message_is_refused(self):
        other = assertion(self.pq_key, self.message + b" ")
        with self.assertRaisesRegex(ValueError, "another message"):
            verify_operator(self.public, self.message, *self.halves[:2], other)

    def test_a_third_half_without_user_verification_is_refused(self):
        unverified = assertion(self.pq_key, self.message, flags=0x01)
        with self.assertRaisesRegex(ValueError, "PIN and touch required"):
            verify_operator(self.public, self.message, *self.halves[:2], unverified)

    def test_a_third_half_by_another_ml_dsa_key_is_refused(self):
        other = assertion(mldsa.MLDSA44PrivateKey.generate(), self.message)
        with self.assertRaises(InvalidSignature):
            verify_operator(self.public, self.message, *self.halves[:2], other)

    def test_a_two_half_operator_refuses_a_third_half(self):
        with self.assertRaisesRegex(ValueError, "unexpected third"):
            verify_operator(self.operator.public(), self.message, *self.halves)

    def test_the_third_key_must_be_ml_dsa_44(self):
        ed = ed25519.Ed25519PrivateKey.generate()
        public = dict(self.public, hardware_mldsa44=cose(EdDSA, ed.public_key()))
        with self.assertRaisesRegex(ValueError, "wrong operator ML-DSA-44 key"):
            verify_operator(public, self.message, *self.halves[:2], assertion(ed, self.message))

    def test_operator_files_name_exactly_their_schema_keys(self):
        path = Path(self.tmp.name) / "operator.pub"
        for operator, ok in (
            (self.public, True),
            (dict(self.public, schema=2), False),
            ({k: v for k, v in self.public.items() if k != "hardware_mldsa44"}, False),
            (self.operator.public(), True),
        ):
            path.write_bytes(canonical(operator))
            path.chmod(0o644)
            if ok:
                self.assertEqual(read_operator(path)[1]["schema"], operator["schema"])
            else:
                with self.assertRaises(ValueError):
                    read_operator(path)

    def test_archives_carry_and_check_the_third_half(self):
        self.assertEqual(signature_members(self.public), {"set.classical.json", "set.mldsa65.sig", "set.mldsa44.json"})
        self.assertEqual(signature_members(self.operator.public()), {"set.classical.json", "set.mldsa65.sig"})
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            write_signature(z, *self.halves)
        with zipfile.ZipFile(buffer) as z:
            self.assertEqual(set(z.namelist()), signature_members(self.public))
            verify_archive_signature(z, self.public, self.message)
            with self.assertRaises(ValueError):
                verify_archive_signature(z, self.public, self.message + b"x")


if __name__ == "__main__":
    unittest.main()

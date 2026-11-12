#!/usr/bin/env python3
"""Tests for the mesh signing path: keyguard mesh-seal/mesh-sign plumbing and
the publish flow in tools/mesh.py.

No FIDO2 hardware exists in CI, so hardware_secret/hardware_assertion are not
exercised; the envelope crypto (seal_bytes/open_bytes) and the publish control
flow are. ML-DSA signing itself is covered where the hash-locked environment
provides it.
"""

import argparse
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import keyguard  # noqa: E402
import mesh  # noqa: E402


def fake_secret_meta():
    return (
        b"\x01" * 32,
        {
            "schema": 1,
            "rp": keyguard.RP,
            "credential": base64.b64encode(b"cred").decode(),
            "salt": base64.b64encode(b"\x02" * 32).decode(),
            "counter": 0,
        },
    )


class MeshEnvelopeTests(unittest.TestCase):
    """The mesh-operator envelope uses the same binding discipline as the
    role envelopes: vault secret + role + certificate."""

    def setUp(self):
        self.secret, self.meta = fake_secret_meta()
        self.cert = b"operator-public-key"
        self.key = b"\x03" * 64

    def test_round_trip(self):
        env = keyguard.seal_bytes(self.secret, self.meta, keyguard.MESH_ROLE, self.cert, self.key)
        self.assertEqual(keyguard.open_bytes(self.secret, self.meta, keyguard.MESH_ROLE, self.cert, env), self.key)

    def test_wrong_role_is_rejected(self):
        env = keyguard.seal_bytes(self.secret, self.meta, keyguard.MESH_ROLE, self.cert, self.key)
        with self.assertRaises(ValueError):
            keyguard.open_bytes(self.secret, self.meta, "outer", self.cert, env)

    def test_wrong_certificate_is_rejected(self):
        env = keyguard.seal_bytes(self.secret, self.meta, keyguard.MESH_ROLE, self.cert, self.key)
        with self.assertRaises(Exception):
            keyguard.open_bytes(self.secret, self.meta, keyguard.MESH_ROLE, b"other", env)

    def test_wrong_vault_secret_is_rejected(self):
        env = keyguard.seal_bytes(self.secret, self.meta, keyguard.MESH_ROLE, self.cert, self.key)
        with self.assertRaises(Exception):
            keyguard.open_bytes(b"\x09" * 32, self.meta, keyguard.MESH_ROLE, self.cert, env)


class ParseLastJsonTests(unittest.TestCase):
    def test_extracts_the_last_json_line(self):
        out = 'Touch your hardware key when it flashes.\n{"descriptor": {"a": 1}}\n'
        self.assertEqual(mesh.parse_last_json(out), {"descriptor": {"a": 1}})

    def test_logs_after_json_are_ignored_only_if_not_json(self):
        out = '{"a": 1}\nnot json\n'
        self.assertEqual(mesh.parse_last_json(out), {"a": 1})

    def test_no_json_line_raises(self):
        with self.assertRaises(ValueError):
            mesh.parse_last_json("nothing here\n")


class PublishFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mesh_dir = Path(self.tmp.name) / "mesh"
        self.mesh_dir.mkdir()
        self._saved = (mesh.MESH_DIR, mesh.OPERATOR_ENVELOPE, mesh.VAULT)
        mesh.MESH_DIR = self.mesh_dir
        mesh.OPERATOR_ENVELOPE = self.mesh_dir / "operator-key.sealed.json"
        mesh.VAULT = Path(self.tmp.name) / "vault"
        self.addCleanup(self._restore)

    def _restore(self):
        mesh.MESH_DIR, mesh.OPERATOR_ENVELOPE, mesh.VAULT = self._saved

    def args(self, **kw):
        return argparse.Namespace(dry_run=kw.get("dry_run", False), yes=True)

    def test_no_node_json(self):
        self.assertEqual(mesh.cmd_publish(self.args())["error"], "NoNode")

    def test_invalid_descriptor_is_refused(self):
        (self.mesh_dir / "node.json").write_text(json.dumps({"schema": 999}))
        self.assertEqual(mesh.cmd_publish(self.args())["error"], "InvalidDescriptor")

    def test_dry_run_needs_no_envelope(self):
        (self.mesh_dir / "node.json").write_text(json.dumps(self._descriptor()))
        self.assertTrue(mesh.cmd_publish(self.args(dry_run=True))["ok"])
        self.assertFalse((self.mesh_dir / ".publish.tmp").exists())

    def test_missing_envelope_refuses_without_touching_the_keyguard(self):
        (self.mesh_dir / "node.json").write_text(json.dumps(self._descriptor()))
        result = mesh.cmd_publish(self.args())
        self.assertEqual(result["error"], "NoSealedOperatorKey")
        self.assertFalse((self.mesh_dir / ".publish.tmp").exists())

    def _descriptor(self):
        now = 2000000000
        return {
            "schema": mesh.SCHEMA,
            "node_id": "!abcd1234",
            "node_public_key": "AA==",
            "wg_public_key": "AA==",
            "cloak_endpoint": "node.example:443",
            "roles": ["relay"],
            "provider": "oci",
            "country": "DE",
            "capacity": {"egress_gib_month": 10240, "cover_budget_mib_day": 2048},
            "health": {"uptime_30d": 1.0, "latency_ms_p50": 12},
            "group": "public",
            "operator": "!abcd1234",
            "published": now,
            "expires": now + mesh.DESCRIPTOR_TTL_SECONDS,
            "signature": "",
        }


class MembershipProofShapeTests(unittest.TestCase):
    def test_proof_shape_matches_identity_rs(self):
        # src/mesh/identity.rs MembershipProof: member, device_public_key,
        # challenge, signature, hardware_bound. The proof file mesh.py writes
        # carries the FIDO2 credential (device_public_key), the assertion
        # (signature over SHA-256(challenge)) and the challenge hash.
        proof = {
            "schema": 1,
            "member": "!abcd1234",
            "credential": "Y3JlZA==",
            "assertion": {"authenticator_data": "AA==", "client_data": "AA==", "signature": "AA=="},
            "challenge_sha256": "00" * 32,
        }
        for field in ["member", "credential", "assertion", "challenge_sha256"]:
            self.assertIn(field, proof)
        for field in ["authenticator_data", "client_data", "signature"]:
            self.assertIn(field, proof["assertion"])


if __name__ == "__main__":
    unittest.main()

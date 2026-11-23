"""Key consistency for oblivious routes (tools/mesh.py, RFC 9458 section 7), with real
ML-DSA-65 descriptor signatures: nothing here stubs verify_descriptor, which is how its
broken import went unnoticed until 20 November 2026."""

import base64
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey  # noqa: E402

import mesh  # noqa: E402

KEY_A = base64.b64encode(b"A" * 1216).decode()
KEY_B = base64.b64encode(b"B" * 1216).decode()


def operator():
    """(private key, member id) of a mesh operator."""
    key = MLDSA65PrivateKey.generate()
    return key, mesh.member_id(key.public_key().public_bytes_raw())


def descriptor(key, gateway=None, **changes):
    """A descriptor signed by `key`, optionally naming a gateway key (key_id 1)."""
    raw = key.public_key().public_bytes_raw()
    now = int(time.time())
    d = dict(
        schema=mesh.SCHEMA,
        node_id=mesh.member_id(raw),
        node_public_key=base64.b64encode(raw).decode(),
        roles=["relay"],
        country="DE",
        group="public",
        operator=mesh.member_id(raw),
        published=now,
        expires=now + 3600,
    )
    if gateway is not None:
        d[mesh.GATEWAY_FIELD] = dict(key_id=1, public=gateway)
    d.update(changes)
    return mesh.sign_descriptor(d, key)


def route(gateway_operator, public=KEY_A):
    return dict(
        relay="http://relay.example",
        gateway_public=public,
        key_id=1,
        relay_operator="!aaaaaaaa",
        gateway_operator=gateway_operator,
    )


class Signatures(unittest.TestCase):
    def test_real_descriptor_signatures_verify_and_tampering_is_refused(self):
        key, _ = operator()
        d = descriptor(key, KEY_A)
        self.assertTrue(mesh.verify_descriptor(d))
        self.assertFalse(mesh.verify_descriptor(dict(d, country="FR")))
        self.assertFalse(mesh.verify_descriptor(dict(d, **{mesh.GATEWAY_FIELD: dict(key_id=1, public=KEY_B)})))
        other, _ = operator()
        forged = descriptor(other, KEY_B, node_id=d["node_id"])  # claims the gateway's id
        self.assertFalse(mesh.verify_descriptor(forged))


class OperatorIdentity(unittest.TestCase):
    """The mesh identity is the operator key `cypherpunk init --vault` made: no separate plaintext
    key, and a descriptor signed by `keyguard mesh-sign` with it verifies (no stubs)."""

    def test_cypherpunk_init_operator_key_signs_a_verifiable_descriptor(self):
        import contextlib
        import io

        import keyguard
        import managed_profile as mp
        from session_auth_vectors import SoftKey

        from fido2.cose import ES256
        from fido2.webauthn import Aaguid, AttestedCredentialData

        soft = SoftKey("es256")
        secret = bytes(range(32))
        record = AttestedCredentialData.create(
            Aaguid(bytes(16)), b"\x01" * 32, ES256.from_cryptography_key(soft.key.public_key())
        )
        meta = dict(
            schema=1, rp=keyguard.RP, salt=keyguard.b64(bytes(32)), credential=keyguard.b64(bytes(record)), counter=0
        )
        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch.object(
                keyguard,
                "hardware_assertion",
                lambda v, message=None, salt2=None: (secret, meta, soft.assert_(message or b"")),
            ),
        ):
            vault = Path(d) / "vault"
            vault.mkdir(mode=0o700)
            (vault / "credential.json").write_text(json.dumps(meta))
            mp.HardwareOperator(vault).sign(b"first signature creates and seals the ML-DSA-65 key")
            pub = vault / "operator-mldsa65.pub"
            raw = mesh.load_operator_key(pub)
            self.assertEqual(len(raw), mesh.MLDSA65_PUBLIC)
            # The bundles' operator.pub (JSON) names the same identity.
            with mock.patch.object(keyguard, "credential_public", lambda v: "cHVi"):
                public = mp.HardwareOperator(vault).public()
            op_file = Path(d) / "operator.pub"
            op_file.write_text(json.dumps(public))
            op_file.chmod(0o600)
            self.assertEqual(mesh.load_operator_key(op_file), raw)
            now = int(time.time())
            unsigned = dict(
                schema=mesh.SCHEMA, node_id=mesh.member_id(raw), node_public_key=base64.b64encode(raw).decode(),
                roles=["relay"], country="DE", group="public", operator=mesh.member_id(raw),
                published=now, expires=now + 3600, signature="",
            )  # fmt: skip
            path = Path(d) / "descriptor.json"
            path.write_text(json.dumps(unsigned))
            path.chmod(0o600)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                keyguard.mesh_sign(vault, vault / "operator-mldsa65.sealed.json", pub, path, "operator-mldsa65")
            signed = json.loads(out.getvalue().strip().splitlines()[-1])["descriptor"]
            self.assertTrue(mesh.verify_descriptor(signed))
            with self.assertRaisesRegex(ValueError, "role"):
                keyguard.mesh_sign(vault, vault / "operator-mldsa65.sealed.json", pub, path, "something-else")

    def test_a_file_that_is_not_an_operator_key_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.pub"
            for content in (b"x" * 10, json.dumps(dict(schema=1)).encode()):
                p.write_bytes(content)
                p.chmod(0o600)
                with self.assertRaises(SystemExit):
                    mesh.load_operator_key(p)


class Publishing(unittest.TestCase):
    def test_a_beacon_signs_its_gateway_key_into_its_descriptor(self):
        from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

        import ohttp

        m, x = mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "gw.key"
            path.write_bytes(ohttp.private_bytes(m, x))
            key, _ = operator()
            unsigned = {k: v for k, v in descriptor(key).items() if k != "signature"}
            signed = mesh.sign_descriptor(mesh.attach_gateway(unsigned, path), key)
        self.assertTrue(mesh.verify_descriptor(signed))
        self.assertEqual(base64.b64decode(signed[mesh.GATEWAY_FIELD]["public"]), ohttp.public_bytes(m, x))
        self.assertEqual(signed[mesh.GATEWAY_FIELD]["key_id"], 1)


class Consistency(unittest.TestCase):
    def setUp(self):
        self.gw_key, self.gw = operator()
        self.published = descriptor(self.gw_key, KEY_A)

    def test_a_key_shown_by_two_other_beacons_is_verified(self):
        witnesses = mesh.check_gateway_key(route(self.gw), [("!b1", [self.published]), ("!b2", [self.published])])
        self.assertEqual(witnesses, ["!b1", "!b2"])

    def test_the_gateway_cannot_vouch_for_itself_and_one_witness_is_not_enough(self):
        with self.assertRaisesRegex(mesh.GatewayKeyRefused, "only 1 other"):
            mesh.check_gateway_key(route(self.gw), [(self.gw, [self.published]), ("!b1", [self.published])])

    def test_a_key_given_only_to_this_member_is_refused(self):
        # The gateway gave this member KEY_B; everyone else sees KEY_A.
        with self.assertRaisesRegex(mesh.GatewayKeyRefused, "not the one its operator published"):
            mesh.check_gateway_key(route(self.gw, KEY_B), [("!b1", [self.published]), ("!b2", [self.published])])

    def test_two_signed_keys_are_equivocation(self):
        other = descriptor(self.gw_key, KEY_B)
        with self.assertRaisesRegex(mesh.GatewayKeyRefused, "equivocation"):
            mesh.check_gateway_key(route(self.gw), [("!b1", [self.published]), ("!b2", [other])])

    def test_a_claim_not_signed_by_the_gateway_operator_counts_for_nothing(self):
        stranger, _ = operator()
        planted = descriptor(stranger, KEY_B, node_id=self.gw)  # fails verification: ignored
        witnesses = mesh.check_gateway_key(
            route(self.gw), [("!b1", [self.published, planted]), ("!b2", [self.published])]
        )
        self.assertEqual(witnesses, ["!b1", "!b2"])


class Fetching(unittest.TestCase):
    """fetch_from_beacons records only verified routes; an unverified route only fetches."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        patch = mock.patch.object(mesh, "MESH_DIR", self.dir)
        patch.start()
        self.addCleanup(patch.stop)
        self.gw_key, self.gw = operator()

    def fetch(self, routes, answers):
        (self.dir / "beacons.json").write_text(json.dumps(routes))
        calls = []

        def call(entry, method, path, body=b""):
            calls.append((method, path))
            source = entry["gateway_operator"] if isinstance(entry, dict) else entry
            return 200, dict(descriptors=answers[source])

        with mock.patch.object(mesh, "beacon_call", call):
            mesh.fetch_from_beacons()
        self.assertEqual({c for c in calls}, {("GET", "/descriptors")})
        path = mesh.gateway_checks_path()
        return json.loads(path.read_text()) if path.exists() else {}

    def test_a_consistent_route_is_recorded_and_then_usable(self):
        published = descriptor(self.gw_key, KEY_A)
        b1, b2 = "https://b1.example:8787", "https://b2.example:8787"
        checks = self.fetch([route(self.gw), b1, b2], {self.gw: [published], b1: [published], b2: [published]})
        self.assertEqual(checks[self.gw]["witnesses"], sorted([b1, b2]))
        self.assertTrue(mesh.gateway_verified(route(self.gw)))
        self.assertFalse(mesh.gateway_verified(route(self.gw, KEY_B)))  # not that key
        self.assertFalse(mesh.gateway_verified(route(self.gw), now=time.time() + mesh.DESCRIPTOR_TTL_SECONDS + 1))

    def test_an_inconsistent_route_is_not_recorded_and_can_only_fetch(self):
        published = descriptor(self.gw_key, KEY_A)
        b1, b2 = "https://b1.example:8787", "https://b2.example:8787"
        checks = self.fetch([route(self.gw, KEY_B), b1, b2], {self.gw: [published], b1: [published], b2: [published]})
        self.assertNotIn(self.gw, checks)
        with self.assertRaisesRegex(mesh.GatewayKeyRefused, "not verified"):
            mesh.beacon_call(route(self.gw, KEY_B), "POST", "/gossip", b"{}")


if __name__ == "__main__":
    unittest.main()

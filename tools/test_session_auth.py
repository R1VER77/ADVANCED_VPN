"""Hardware session authorization (docs/HARDWARE_BOUND_SESSIONS.md): the shared vectors,
the COSE key conversion, and leaves built by managed_profile.refresh_leaves."""

import base64
import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402
from fido2 import cbor  # noqa: E402
from fido2.cose import ES256, EdDSA, RS256  # noqa: E402

import session_auth as sa  # noqa: E402
from session_auth_vectors import SoftKey  # noqa: E402

VECTORS = json.loads((Path(__file__).resolve().parent / "testdata" / "session_auth.json").read_text())


def cose(key_class, public):
    return base64.b64encode(cbor.encode(dict(key_class.from_cryptography_key(public)))).decode()


class Vectors(unittest.TestCase):
    def test_the_reference_verifier_agrees_with_every_vector(self):
        self.assertGreaterEqual(len(VECTORS["vectors"]), 17)
        self.assertEqual(VECTORS["oid"], sa.OID)
        for v in VECTORS["vectors"]:
            with self.subTest(v["name"]):
                try:
                    sa.verify_leaf(v["device"], bytes.fromhex(v["leaf"]), VECTORS["now"])
                    got = None
                except ValueError as e:
                    got = str(e)
                self.assertEqual(got, v["error"])

    def test_both_device_algorithms_are_accepted_and_every_check_refuses_something(self):
        names = {v["name"]: v["error"] for v in VECTORS["vectors"]}
        self.assertIsNone(names["accepted_es256"])
        self.assertIsNone(names["accepted_eddsa"])
        self.assertEqual(
            {e for e in names.values() if e},
            {
                "no hardware session authorization",
                "wrong relying party",
                "touch and PIN required",
                "wrong client data",
                "assertion is for another statement",
                "not signed by the enrolled key",
                "the authorization does not name this key",
                "session authorization expired or not yet valid",
                "the leaf outlives its authorization",
                "a session lasts at most 12 hours",
                "malformed session authorization",
            },
        )


class DeviceKeys(unittest.TestCase):
    def test_es256_and_eddsa_credentials_convert_to_what_rust_verifies(self):
        p = ec.generate_private_key(ec.SECP256R1()).public_key()
        d = sa.device_key(cose(ES256, p))
        self.assertEqual(d["alg"], "es256")
        self.assertEqual(
            bytes.fromhex(d["public_hex"]),
            p.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint),
        )
        e = ed25519.Ed25519PrivateKey.generate().public_key()
        d = sa.device_key(cose(EdDSA, e))
        self.assertEqual(d, dict(alg="eddsa", public_hex=e.public_bytes_raw().hex()))

    def test_a_credential_that_cannot_authorize_sessions_is_named_not_exempted(self):
        r = rsa.generate_private_key(65537, 2048).public_key()
        with self.assertRaisesRegex(ValueError, "cannot authorize sessions"):
            sa.device_key(cose(RS256, r))

    def test_statements_name_every_layer_and_last_at_most_12_hours(self):
        layers = {"inner": "ab" * 32}
        sa.authorization(layers, 0, sa.MAX_SECONDS)
        for bad in [({}, 0, 10), ({"inner": "ab"}, 0, 10), (layers, 0, sa.MAX_SECONDS + 1), (layers, 10, 10)]:
            with self.assertRaises(ValueError):
                sa.authorization(*bad)


class RefreshedLeaves(unittest.TestCase):
    """managed_profile.refresh_leaves with a session: what a client presents to each hop."""

    def test_each_refreshed_leaf_carries_an_authorization_its_hop_accepts(self):
        import managed_profile as mp
        from cryptography.hazmat.primitives.asymmetric import mldsa

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config, keys = {}, {}
            for lane in ("outer", "inner"):
                k = mldsa.MLDSA65PrivateKey.generate()
                (root / (lane + "-cert.der")).write_bytes(
                    mp.device_certificate("client-%s.advanced-vpn.internal" % lane, k)
                )
                (root / (lane + "-cert.der")).chmod(0o600)
                keys[lane] = k.private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
                config[lane] = dict(pin_kind="spki", key=str(root / (lane + "-key.der")))
            now = int(dt.datetime.now(dt.timezone.utc).timestamp())
            nb, na = now - 300, now - 300 + sa.MAX_SECONDS
            statement = sa.authorization(mp.session_layers(config, root), nb, na)
            soft = SoftKey("es256")
            mp.refresh_leaves(config, root, keys, session=(statement, soft.assert_(statement), nb, na))
            other = SoftKey("es256")
            for lane in ("outer", "inner"):
                leaf = (root / (lane + "-active-cert.der")).read_bytes()
                s = sa.verify_leaf(soft.device(), leaf, now)
                self.assertEqual(set(s["layers"]), {"outer", "inner"})
                with self.assertRaisesRegex(ValueError, "not signed by the enrolled key"):
                    sa.verify_leaf(other.device(), leaf, now)
                cert = x509.load_der_x509_certificate(leaf)
                self.assertEqual(int(cert.not_valid_after_utc.timestamp()), na)
            # Without a session the leaf is the plain 12-hour rotation, which a hop that
            # pins a device key refuses.
            mp.refresh_leaves(config, root, keys)
            with self.assertRaisesRegex(ValueError, "no hardware session authorization"):
                sa.verify_leaf(soft.device(), (root / "inner-active-cert.der").read_bytes(), now)


class Enrollment(unittest.TestCase):
    """The real request -> create -> enroll flow with a software stand-in for the key."""

    def enroll(self, protect, credential_class=ES256):
        import time
        from unittest import mock

        import keyguard
        import managed_profile as mp

        soft = SoftKey("es256")
        public = (
            soft.key.public_key() if credential_class is ES256 else rsa.generate_private_key(65537, 2048).public_key()
        )
        secret = bytes(range(32))
        meta = dict(salt=keyguard.b64(bytes(32)), credential=keyguard.b64(b"record"), counter=0)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "vault").mkdir()
        with (
            mock.patch.object(keyguard, "hardware_secret", lambda v: (secret, meta)),
            mock.patch.object(
                keyguard,
                "hardware_assertion",
                lambda v, message=None, salt2=None: (secret, meta, soft.assert_(message)),
            ),
            mock.patch.object(keyguard, "credential_public", lambda v: cose(credential_class, public)),
        ):
            mp.lab_setup(
                root, "198.51.100.1:443", "203.0.113.2:4433", protect={"client": protect}, vault=root / "vault"
            )
            profiles = {r: json.loads((root / r / "profile.json").read_text()) for r in ("client", "relay", "exit")}
            leaves = None
            if protect == "nitrokey":
                secret2, meta2, session = mp.authorize_session(profiles["client"]["core"], root / "client")
                keys = mp.load_keys(root / "client", ["outer", "inner"], secret2, meta2)
                (root / "rt").mkdir()
                mp.refresh_leaves(
                    profiles["client"]["core"], root / "client", keys, out_dir=root / "rt", session=session
                )
                leaves = {l: (root / "rt" / (l + "-active-cert.der")).read_bytes() for l in ("outer", "inner")}
        return profiles, leaves, soft, time.time()

    def test_every_hop_pins_a_hardware_clients_key_and_accepts_only_its_authorized_leaves(self):
        profiles, leaves, soft, now = self.enroll("nitrokey")
        relay, exit_ = profiles["relay"]["core"]["outer"], profiles["exit"]["core"]["inner"]
        self.assertEqual(relay["peer_device"], soft.device())
        self.assertEqual(exit_["peer_device"], soft.device())
        self.assertNotIn("peer_device", profiles["client"]["core"]["outer"])  # a client checks no device
        sa.verify_leaf(relay["peer_device"], leaves["outer"], now)
        sa.verify_leaf(exit_["peer_device"], leaves["inner"], now)
        with self.assertRaisesRegex(ValueError, "expired"):
            sa.verify_leaf(exit_["peer_device"], leaves["inner"], now + sa.MAX_SECONDS)

    def test_a_software_protected_client_is_enrolled_as_before(self):
        profiles, _, _, _ = self.enroll("none")
        self.assertNotIn("peer_device", profiles["relay"]["core"]["outer"])
        self.assertNotIn("peer_device", profiles["exit"]["core"]["inner"])

    def test_a_key_whose_credential_cannot_authorize_sessions_is_refused_at_enrollment(self):
        with self.assertRaisesRegex(ValueError, "cannot authorize sessions"):
            self.enroll("nitrokey", credential_class=RS256)


if __name__ == "__main__":
    unittest.main()

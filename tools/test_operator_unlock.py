"""Operator-unlocked servers (managed_profile `operator` protection, keyguard.lock_bytes):
a server without a TPM keeps its keys encrypted under a data key that only the operator's
Nitrokey can unwrap, and holds that data key in RAM only after the operator's unlock.
Real cryptography throughout: nothing here stubs the sealing, the KEM or the binding."""

import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402

import keyguard  # noqa: E402
import managed_profile as mp  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        unlock_dir = self.root / "run-unlock"
        patch = mock.patch.object(mp, "UNLOCK_DIR", unlock_dir)
        patch.start()
        self.addCleanup(patch.stop)
        self.operator = mp.SoftwareOperator(self.root / "operator-keys")
        self.unlock_public = self.operator.create_unlock_key()

    def server(self, name="exit", role="exit"):
        state = self.root / name
        req = mp.request(role, state, "operator", unlock_public=self.unlock_public)
        return state, req


class AtRest(Base):
    def test_no_private_key_is_on_disk_in_the_clear_and_the_data_key_is_only_wrapped(self):
        state, req = self.server()
        files = sorted(f.name for f in state.iterdir())
        self.assertFalse(set(files) & set(mp.PLAINTEXT.values()), files)
        locked = [f for f in files if f.endswith("-key.locked.json")]
        self.assertEqual(
            sorted(locked), sorted(n + "-key.locked.json" for n in ("inner", "wireguard", "kem", "cloak", "i2p"))
        )
        protection = json.loads((state / "protection.json").read_text())
        self.assertEqual(protection["mode"], "operator")
        self.assertEqual(protection["unlock"], req["unlock"])
        # The data key itself appears nowhere: not in a file, not in RAM's unlock dir.
        self.assertFalse(mp.UNLOCK_DIR.exists())

    def test_a_locked_server_refuses_to_load_its_keys(self):
        state, _ = self.server()
        self.assertTrue(mp.server_locked(state))
        with self.assertRaisesRegex(mp.Locked, "avpn cloud unlock"):
            mp.load_keys(state, ["inner"])

    def test_a_client_cannot_be_operator_protected_and_the_unlock_key_is_required(self):
        with self.assertRaisesRegex(ValueError, "for servers"):
            mp.request("client", self.root / "c", "operator", unlock_public=self.unlock_public)
        with self.assertRaisesRegex(ValueError, "unlock key is required"):
            mp.request("exit", self.root / "e", "operator")
        with self.assertRaisesRegex(ValueError, "not an operator unlock key"):
            mp.request("exit", self.root / "e2", "operator", unlock_public=b"x" * 32)


class Unlock(Base):
    def unwrap(self, req, name="exit"):
        return self.operator.unwrap(mp.unlock_items({name: req}))[name]

    def test_the_operator_unwraps_and_the_server_then_opens_the_keys_it_published(self):
        state, req = self.server()
        data_key = self.unwrap(req)
        names = mp.server_unlock(state, data_key)
        self.assertIn("inner", names)
        self.assertFalse(mp.server_locked(state))
        self.assertEqual(oct(mp.UNLOCK_DIR.stat().st_mode & 0o777), "0o700")
        keys = mp.load_keys(state, ["inner", "wireguard", "kem"])
        # The opened keys are the ones the request published.
        inner = serialization.load_der_private_key(keys["inner"], password=None)
        cert = x509.load_der_x509_certificate(base64.b64decode(req["certificates"]["inner"]))
        raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
        self.assertEqual(inner.public_key().public_bytes(*raw), cert.public_key().public_bytes(*raw))
        wg = x25519.X25519PrivateKey.from_private_bytes(keys["wireguard"]).public_key().public_bytes(*raw)
        self.assertEqual(wg.hex(), req["wireguard_public_hex"])
        sealed = keyguard.kem_seal(base64.b64decode(req["kem_public"]), b"psk", b"ctx")
        self.assertEqual(keyguard.kem_open(keys["kem"], sealed, b"ctx"), b"psk")

    def test_a_wrong_data_key_is_refused_and_nothing_is_held(self):
        state, _ = self.server()
        for bad in (bytes(32), b"short"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                mp.server_unlock(state, bad)
        self.assertTrue(mp.server_locked(state))

    def test_a_data_key_wrapped_for_another_server_does_not_unwrap(self):
        # A compromised server presents another server's wrapped data key as its own: the
        # operator binds the unwrap to its own copy of this server's certificates.
        _, req_a = self.server("exit-a")
        _, req_b = self.server("exit-b")
        replay = {"exit-a": (req_b["unlock"], req_a["role"], req_a["certificates"])}
        with self.assertRaisesRegex(ValueError, "does not open"):
            self.operator.unwrap(replay)
        # Its own record, with its own certificates, unwraps.
        self.assertEqual(len(self.unwrap(req_a, "exit-a")), keyguard.DATA_KEY)

    def test_a_server_locked_to_another_operator_is_named(self):
        _, req = self.server()
        other = mp.SoftwareOperator(self.root / "other-operator")
        other.create_unlock_key()
        with self.assertRaisesRegex(ValueError, "another operator's unlock key"):
            other.unwrap(mp.unlock_items({"exit": req}))

    def test_swapped_key_files_do_not_open(self):
        state, req = self.server()
        mp.server_unlock(state, self.unwrap(req))
        kem, wg = state / "kem-key.locked.json", state / "wireguard-key.locked.json"
        a, b = kem.read_bytes(), wg.read_bytes()
        kem.write_bytes(b)
        wg.write_bytes(a)
        with self.assertRaises(ValueError):
            mp.load_keys(state, ["kem"])

    def test_a_key_file_rolled_back_to_another_key_of_the_same_name_does_not_open(self):
        # Same data key, same name, but not the key the server published: e.g. an older
        # key file put back. The envelope is bound to the published public value.
        state, req = self.server()
        data_key = self.unwrap(req)
        mp.server_unlock(state, data_key)
        old_public = b"kem:" + bytes(keyguard.KEM_PUBLIC)
        rolled_back = keyguard.lock_bytes(data_key, "kem", old_public, b"\x00" * 96)
        (state / "kem-key.locked.json").write_bytes(mp.canonical(rolled_back))
        with self.assertRaises(ValueError):
            mp.load_keys(state, ["kem"])

    def test_the_request_validator_accepts_the_record_and_refuses_a_malformed_one(self):
        _, req = self.server()
        raw = mp.canonical(req)
        mp.load_request(raw, "exit")
        for bad in (dict(req["unlock"], schema=2), dict(req["unlock"], operator_unlock_sha256="zz")):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "unlock"):
                mp.load_request(mp.canonical(dict(req, unlock=bad)), "exit")


class ServerUnlockCommand(Base):
    """`avpnctl server-unlock` as the chain runs it over SSH: the data key on stdin, as hex.
    (Root is required on a real server; the check is bypassed here, the rest is real.)"""

    def run_ctl(self, state, stdin, *args):
        import contextlib
        import io

        import avpnctl

        out = io.StringIO()
        argv = ["avpnctl", "--json", "--state", str(state), "server-unlock", *args]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(sys, "stdin", io.StringIO(stdin)),
            mock.patch.object(avpnctl, "root_guard", lambda lab: None),
            mock.patch.object(avpnctl, "harden_process", lambda: None),
            contextlib.redirect_stdout(out),
        ):
            avpnctl.main()
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def test_the_command_accepts_the_right_key_and_refuses_others(self):
        state, req = self.server()
        data_key = self.operator.unwrap(mp.unlock_items({"exit": req}))["exit"]
        for bad in ("zz", bytes(32).hex(), ""):
            with self.subTest(bad=bad), self.assertRaises((SystemExit, ValueError)):
                self.run_ctl(state, bad + "\n")
        self.assertTrue(mp.server_locked(state))
        r = self.run_ctl(state, data_key.hex() + "\n")
        self.assertTrue(r["ok"])
        self.assertIn("inner", r["unlocked"])
        self.assertFalse(mp.server_locked(state))


class LabChain(unittest.TestCase):
    """The real request -> init -> enroll flow with an exit locked to the operator: the
    signing unwraps its data key, enroll re-stores the carrier and link keys under it, and
    after a reboot (RAM cleared) the exit is locked until the operator unwraps it again."""

    def test_an_operator_locked_exit_enrolls_and_is_locked_again_after_a_reboot(self):
        import shutil

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with mock.patch.object(mp, "UNLOCK_DIR", root / "run-unlock"):
                mp.lab_setup(root, "198.51.100.1:443", "203.0.113.2:4444", protect=dict(exit="operator"))
                exit_state = root / "exit"
                profile = json.loads((exit_state / "profile.json").read_text())
                mp.profile_validate(profile)
                self.assertFalse(list(exit_state.glob("*-key.der")) + list(exit_state.glob("*-key.bin")))
                names = ["inner", "wireguard", "kem", "link"]
                before = mp.load_keys(exit_state, names)
                # enroll opened the paced-link keys with the KEM key and stored them, locked.
                self.assertTrue((exit_state / "link-key.locked.json").exists())
                self.assertTrue(before["link"] and len(before["link"]) % 32 == 0)
                shutil.rmtree(mp.UNLOCK_DIR)  # a reboot clears /run
                with self.assertRaises(mp.Locked):
                    mp.load_keys(exit_state, names)
                operator = mp.SoftwareOperator(root / "operator-keys")
                req = json.loads((exit_state / "request.json").read_text())
                mp.server_unlock(exit_state, operator.unwrap(mp.unlock_items({"exit": req}))["exit"])
                self.assertEqual(mp.load_keys(exit_state, names), before)


class HardwareOperatorTouches(unittest.TestCase):
    """The hardware operator: the unlock key's private half is sealed in the vault, and one
    PIN + touch both signs the chain and unwraps the servers' data keys."""

    def setUp(self):
        from fido2.cose import ES256
        from fido2.webauthn import Aaguid, AttestedCredentialData

        from session_auth_vectors import SoftKey

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        patch = mock.patch.object(mp, "UNLOCK_DIR", self.root / "run-unlock")
        patch.start()
        self.addCleanup(patch.stop)
        soft = SoftKey("es256")
        record = AttestedCredentialData.create(
            Aaguid(bytes(16)), b"\x01" * 32, ES256.from_cryptography_key(soft.key.public_key())
        )
        self.meta = dict(
            schema=1, rp=keyguard.RP, salt=keyguard.b64(bytes(32)), credential=keyguard.b64(bytes(record)), counter=0
        )
        self.secret = bytes(range(32))
        self.vault = self.root / "vault"
        self.vault.mkdir(mode=0o700)
        (self.vault / "credential.json").write_text(json.dumps(self.meta))
        self.touches = 0

        def assertion(v, message=None, salt2=None):
            self.touches += 1
            return self.secret, self.meta, soft.assert_(message or b"")

        patch = mock.patch.object(keyguard, "hardware_assertion", assertion)
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_unlock_key_is_sealed_and_one_touch_signs_and_unwraps(self):
        op = mp.HardwareOperator(self.vault)
        public = op.create_unlock_key()
        self.assertEqual(self.touches, 1)
        self.assertEqual(op.create_unlock_key(), public)  # once only
        self.assertEqual(self.touches, 1)
        # On disk: the public half and a sealed envelope, nothing that is the private key.
        sealed = json.loads((self.vault / "operator-unlock.sealed.json").read_text())
        private = keyguard.open_bytes(self.secret, self.meta, mp.UNLOCK_ROLE, public, sealed)
        for f in self.vault.iterdir():
            self.assertNotIn(private, f.read_bytes(), f.name)
        with self.assertRaises(Exception):  # another hardware secret does not open it
            keyguard.open_bytes(bytes(32), self.meta, mp.UNLOCK_ROLE, public, sealed)

        state = self.root / "exit"
        req = mp.request("exit", state, "operator", unlock_public=public)
        op.pending_unwrap = mp.unlock_items({"exit": req})
        before = self.touches
        op.sign(b"the chain")
        self.assertEqual(self.touches - before, 1)  # the signing touch also unwrapped
        mp.server_unlock(state, op.unwrapped["exit"])
        self.assertIn("inner", mp.load_keys(state, ["inner"]))


if __name__ == "__main__":
    unittest.main()

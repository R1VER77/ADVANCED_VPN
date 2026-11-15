"""Device setup at installation: vault rules, no half-made state, commands on root's PATH."""

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import avpnctl
import install
from managed_profile import request


class DeviceSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_refused_vault_leaves_no_device_state(self):
        vault = self.d / "vault"
        vault.mkdir(mode=0o700)  # no FIDO2 credential inside
        state = self.d / "enrolled"
        with self.assertRaises((OSError, ValueError)):
            request("client", state, "nitrokey", vault)
        self.assertFalse(state.exists(), "a failed unlock must not leave half-made keys behind")

    def test_existing_device_keys_are_never_overwritten(self):
        state = self.d / "enrolled"
        state.mkdir()
        with self.assertRaisesRegex(ValueError, "already has keys"):
            request("client", state, "none")

    def test_a_midway_failure_leaves_no_half_written_device(self):
        # Bug 9b: a failure after the keys were generated (a sealing error, a full
        # disk) used to leave a half-made directory that the next setup "kept" or
        # refused as existing keys. The device must appear all at once or not at all.
        state = self.d / "enrolled"
        with mock.patch("managed_profile.store_keys", side_effect=OSError("no space left on device")):
            with self.assertRaises(OSError):
                request("client", state, "none")
        self.assertFalse(state.exists(), "a failed request must not leave a device directory")
        self.assertEqual(list(self.d.iterdir()), [], "and no half-made sibling either")
        # A retry after the failure succeeds instead of being refused.
        req = request("client", state, "none")
        self.assertEqual(req["role"], "client")
        self.assertTrue((state / "request.json").exists())

    def test_hardware_sealed_keys_still_open_after_the_atomic_rename(self):
        # The device is built in a hidden sibling and renamed into place: the sealed key
        # envelopes must bind to their key material, never to the directory they were
        # written in, or every key would be unopenable after the rename.
        import base64

        from managed_profile import LANES, load_keys

        secret = os.urandom(32)
        meta = dict(salt=base64.b64encode(os.urandom(32)).decode(), credential=base64.b64encode(b"cred-id").decode())
        vault = self.d / "vault"
        vault.mkdir(mode=0o700)
        state = self.d / "enrolled"
        with mock.patch("keyguard.hardware_secret", return_value=(secret, meta)):
            request("relay", state, "nitrokey", vault)
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), ["enrolled", "vault"], "no leftover sibling")
        names = [*LANES["relay"], "wireguard", "kem", "cloak", "i2p"]
        keys = load_keys(state, names, secret, meta)
        self.assertEqual(sorted(keys), sorted(names))
        self.assertTrue(all(keys.values()))
        # And the wrong hardware secret opens nothing.
        with self.assertRaises(Exception):
            load_keys(state, ["kem"], os.urandom(32), meta)

    def test_vault_must_be_private_and_owned_by_the_caller(self):
        vault = self.d / "vault"
        vault.mkdir(mode=0o700)
        self.assertEqual(avpnctl.device_vault(vault), vault)
        vault.chmod(0o750)
        with self.assertRaisesRegex(ValueError, "private directory owned by this user"):
            avpnctl.device_vault(vault)
        vault.chmod(0o700)
        # Root reading a vault in someone's home (owned by that user) is refused up front.
        with mock.patch.object(avpnctl.os, "geteuid", lambda: os.getuid() + 1):
            with self.assertRaisesRegex(ValueError, "omit --vault to use /etc/advanced-vpn/vault"):
                avpnctl.device_vault(vault)

    def test_default_vault_only_for_root(self):
        if os.geteuid() == 0:
            self.skipTest("as root the default vault is used by design; this checks a non-root caller")
        with self.assertRaisesRegex(ValueError, "--vault is required"):
            avpnctl.device_vault(None)

    def test_missing_vault_is_created_on_first_use(self):
        vault = self.d / "new" / "vault"
        created = []

        def fake_enroll(path):
            path.mkdir(mode=0o700)
            created.append(path)

        with mock.patch("keyguard.enroll", fake_enroll):
            self.assertEqual(avpnctl.device_vault(vault), vault)
        self.assertEqual(created, [vault])
        self.assertEqual(stat.S_IMODE(vault.parent.stat().st_mode), 0o700)

    def test_public_request_is_handed_to_the_sudo_user(self):
        f = self.d / "client.req"
        f.write_text("{}")
        f.chmod(0o600)
        with mock.patch.dict(os.environ, SUDO_UID=str(os.getuid()), SUDO_GID=str(os.getgid())):
            avpnctl.hand_to_invoker(f)
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)

    def test_commands_are_linked_onto_roots_path_without_clobbering(self):
        target, bin_dir = self.d / "opt", self.d / "usr-local-bin"
        self.assertTrue(install.link_commands(target, bin_dir))
        self.assertEqual(os.readlink(bin_dir / "avpn"), str(target / "bin/avpn"))
        self.assertEqual(os.readlink(bin_dir / "avpnctl"), str(target / "bin/avpnctl"))
        self.assertTrue(install.link_commands(target, bin_dir), "re-running is a no-op")
        (bin_dir / "avpn").unlink()
        (bin_dir / "avpn").write_text("someone else's avpn")
        self.assertFalse(install.link_commands(target, bin_dir))
        self.assertEqual((bin_dir / "avpn").read_text(), "someone else's avpn")


if __name__ == "__main__":
    unittest.main()

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

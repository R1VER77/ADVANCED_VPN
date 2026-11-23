"""Plaintext key custody (--protect none) is refused unless explicitly acknowledged."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CYPHERPUNKCTL = Path(__file__).resolve().parent / "cypherpunkctl.py"


def request(state, *extra):
    return subprocess.run(
        [sys.executable, CYPHERPUNKCTL, "--state", state / "s", "request", "--role", "client", "--protect", "none",
         "--out", state / "r.json", *extra],
        capture_output=True, text=True, timeout=120,
    )  # fmt: skip


class KeyCustodyTests(unittest.TestCase):
    def test_plaintext_keys_need_the_explicit_flag(self):
        with tempfile.TemporaryDirectory() as d:
            r = request(Path(d))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("refusing --protect none", r.stderr)
            self.assertFalse((Path(d) / "s").exists(), "no key may be written before the refusal")

    def test_the_flag_allows_a_test_device(self):
        with tempfile.TemporaryDirectory() as d:
            r = request(Path(d), "--insecure-plaintext-keys")
            self.assertEqual(r.returncode, 0, r.stderr[-300:])
            self.assertTrue((Path(d) / "r.json").stat().st_size > 0)


if __name__ == "__main__":
    unittest.main()


class EligibleKeyTests(unittest.TestCase):
    """Which FIDO2 keys may hold a vault (checked on real keys on 14 Nov 2026: a Nitrokey 3
    and a YubiKey 5C NFC verify with a host PIN, a Trezor Safe 3 on its own screen)."""

    @staticmethod
    def info(extensions, **options):
        from types import SimpleNamespace

        return SimpleNamespace(extensions=extensions, options=options)

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import keyguard

        self.eligible = keyguard.eligible

    def test_a_key_with_a_host_pin_is_eligible(self):
        self.assertTrue(self.eligible(self.info(["credProtect", "hmac-secret"], clientPin=True, rk=True, up=True)))

    def test_a_key_that_verifies_on_its_own_screen_is_eligible(self):
        # A Trezor reports uv: true and no clientPin: its PIN never reaches the computer.
        self.assertTrue(self.eligible(self.info(["hmac-secret"], uv=True, rk=True, up=True)))

    def test_a_key_without_any_user_verification_is_refused(self):
        self.assertFalse(self.eligible(self.info(["hmac-secret"], clientPin=False, rk=True, up=True)))
        self.assertFalse(self.eligible(self.info(["hmac-secret"], rk=True, up=True)))

    def test_a_key_without_hmac_secret_is_refused(self):
        self.assertFalse(self.eligible(self.info(["credProtect"], clientPin=True)))
        self.assertFalse(self.eligible(self.info(["credProtect"], uv=True)))

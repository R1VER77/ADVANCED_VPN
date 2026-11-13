"""Plaintext key custody (--protect none) is refused unless explicitly acknowledged."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

AVPNCTL = Path(__file__).resolve().parent / "avpnctl.py"


def request(state, *extra):
    return subprocess.run(
        [sys.executable, AVPNCTL, "--state", state / "s", "request", "--role", "client", "--protect", "none",
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

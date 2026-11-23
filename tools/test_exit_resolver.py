"""The exit's own recursive resolver (`cypherpunk init --dns-recursive`, tools/exit_resolver.py).
The resolver itself was checked live (20 Nov 2026, Debian 13, Unbound 1.26): 20 of 20
popular names resolved, dnssec-failed.org was refused, nic.cz validated, and nothing
answered off loopback; cypherpunk-vpn-dns in recursive mode in front of it kept its
blocklist and .invalid handling (docs/DEPLOYMENT.md)."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import exit_resolver  # noqa: E402
import managed_profile as mp  # noqa: E402


class Config(unittest.TestCase):
    def test_the_resolver_validates_minimises_and_listens_on_loopback_only(self):
        c = exit_resolver.config()
        for line in (
            "interface: 127.0.0.1",
            "port: 5335",
            "access-control: 0.0.0.0/0 refuse",
            "access-control: 127.0.0.0/8 allow",
            'trust-anchor-file: "/usr/share/dns/root.key"',
            "qname-minimisation: yes",
            "harden-dnssec-stripped: yes",
            "use-caps-for-id: yes",
            "hide-identity: yes",
            "hide-version: yes",
            "log-queries: no",
            "control-enable: no",
        ):
            self.assertIn(line, c)
        self.assertNotIn("harden-referral-path: yes", c)  # broke www.debian.org live
        with self.assertRaisesRegex(ValueError, "loopback"):
            exit_resolver.config("0.0.0.0:5335")


class Profiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def exit_profile(self, dns):
        mp.lab_setup(self.root, "198.51.100.1:443", "203.0.113.2:4433", dns=dns)
        return json.loads((self.root / "exit" / "profile.json").read_text())

    def test_a_recursive_exit_asks_its_own_resolver_and_runs_it(self):
        p = self.exit_profile(dict(recursive=True))
        self.assertEqual(p["dns"]["upstream"], "127.0.0.1:5335")
        self.assertTrue(p["dns"]["recursive"])
        mp.profile_validate(p)
        out = mp.runtime(p, self.root / "exit")
        self.assertEqual(out["resolver"], {"listen": "127.0.0.1:5335"})

    def test_a_forwarding_exit_is_unchanged(self):
        p = self.exit_profile(None)
        self.assertEqual(p["dns"]["upstream"], "1.1.1.1:853")
        self.assertNotIn("recursive", p["dns"])
        self.assertNotIn("resolver", mp.runtime(p, self.root / "exit"))

    def test_a_recursive_profile_pointing_anywhere_else_is_refused(self):
        p = self.exit_profile(dict(recursive=True))
        for bad in (dict(upstream="1.1.1.1:53"), dict(recursive="yes")):
            with self.subTest(bad), self.assertRaisesRegex(ValueError, "recursive|DNS"):
                mp.profile_validate(dict(p, dns=dict(p["dns"], **bad)))


if __name__ == "__main__":
    unittest.main()

"""Paced server links over TCP, for an IPv6-only exit whose provider carries no UDP there
(managed_profile link_transport; the Rust side is src/link.rs ingress_tcp/egress_tcp).
The real request -> init -> enroll flow; the data plane's own parser checks the result."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import managed_profile as mp  # noqa: E402

RELAY = "198.51.100.1:443"
EXIT6 = "[2001:db8:1::4]:4444"
BINARY = Path(__file__).resolve().parents[1] / "target" / "release" / "advanced-vpn"


class Profiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def chain(self, exit_address=EXIT6, transport="tcp", **kw):
        mp.lab_setup(self.root, RELAY, exit_address, link_transport=transport, **kw)
        return {r: json.loads((self.root / r / "profile.json").read_text()) for r in ("client", "relay", "exit")}

    def test_a_tcp_chain_names_the_ipv6_exit_and_listens_on_both_families(self):
        p = self.chain()
        self.assertEqual(p["relay"]["core"]["link_transport"], "tcp")
        self.assertEqual(p["relay"]["core"]["link_out"], [EXIT6])
        self.assertEqual(p["exit"]["core"]["link_transport"], "tcp")
        self.assertEqual(p["exit"]["core"]["listen"], "[::]:4444")
        self.assertNotIn("link_transport", p["client"]["core"])  # the carrier is the client's only link
        for role, profile in p.items():
            with self.subTest(role=role):
                mp.profile_validate(profile)

    def test_a_udp_chain_is_written_as_before(self):
        p = self.chain(exit_address="203.0.113.2:4444", transport="udp")
        for role in ("relay", "exit"):
            self.assertNotIn("link_transport", p[role]["core"])
        self.assertEqual(p["exit"]["core"]["listen"], "0.0.0.0:4444")

    def test_refusals(self):
        cases = [
            dict(exit_address=EXIT6, transport="udp"),  # IPv6 needs the TCP link
            dict(exit_address="203.0.113.2:4444", transport="sctp"),
            dict(exit_address="[::]:4444", transport="tcp"),  # unspecified
            dict(exit_address="[fe80::1]:4444", transport="tcp"),  # link-local
            dict(exit_address="[2001:db8::4]:0", transport="tcp"),  # port
        ]
        for i, case in enumerate(cases):
            with self.subTest(case=case), self.assertRaises(ValueError):
                mp.lab_setup(self.root / str(i), RELAY, case["exit_address"], link_transport=case["transport"])
        with self.assertRaises(ValueError):  # the first hop is dialled by the client: IPv4
            mp.lab_setup(self.root / "v6-first", "[2001:db8::1]:443", EXIT6, link_transport="tcp")
        with self.assertRaises(ValueError):  # a one-hop chain has no server link
            mp.lab_setup(self.root / "one", None, "203.0.113.2:443", hops=1, link_transport="tcp")

    def test_a_tampered_profile_is_refused(self):
        p = self.chain()
        relay = json.loads(json.dumps(p["relay"]))
        relay["core"]["link_transport"] = "udp"  # IPv6 next hop over UDP
        with self.assertRaises(ValueError):
            mp.profile_validate(relay)
        relay["core"]["link_transport"] = "quic"
        with self.assertRaises(ValueError):
            mp.profile_validate(relay)

    @unittest.skipUnless(BINARY.exists(), "needs the release data plane (cargo build --release)")
    def test_the_data_plane_accepts_the_generated_configs(self):
        # As the supervisor runs it: the layer key and the link keys as sealed memfds,
        # certificate paths under the device directory.
        import os

        from keyguard import memory_fd

        self.chain()
        for role in ("relay", "exit"):
            state = self.root / role
            cfg = mp.runtime(json.loads((state / "profile.json").read_text()), state)["core"]
            lane = mp.SERVER_LANE[role]
            for field in ("ca", "cert", "key"):
                cfg[lane][field] = str(state / cfg[lane][field])
            path = self.root / (role + "-core.json")
            path.write_text(json.dumps(cfg))
            path.chmod(0o600)
            keys = mp.load_keys(state, [lane, "link"])
            fds = {name: memory_fd(value) for name, value in keys.items()}
            try:
                argv = [str(BINARY), "--config", str(path), "--check"]
                for name, fd in fds.items():
                    argv += ["--key-fd", "%s=%d" % (name, fd)]
                r = subprocess.run(argv, capture_output=True, text=True, timeout=60, pass_fds=list(fds.values()))
            finally:
                for fd in fds.values():
                    os.close(fd)
            with self.subTest(role=role):
                self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
                self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["configuration_valid"], True)


if __name__ == "__main__":
    unittest.main()

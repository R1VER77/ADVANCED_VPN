"""The mix lane's configuration checks and request validation."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mix  # noqa: E402

CLIENT = """PKISignatureScheme = "Ed25519 Sphincs+"
WireKEMScheme = "xwing"
[Listen]
  [Listen.Tcp]
    Address = "kpclientd:32000"
    Network = "tcp"
[SphinxGeometry]
  PacketLength = 22458
  NIKEName = ""
  KEMName = "XWING"
[Logging]
  Disable = false
  File = "client.log"
  Level = "NOTICE"
[UpstreamProxy]
  Type = "none"
[Debug]
  DisableDecoyTraffic = false
[PinnedGateways]
  [[PinnedGateways.Gateways]]
    Name = "gateway1"
    WireKEMScheme = "xwing"
    PKISignatureScheme = "Ed25519 Sphincs+"
[VotingAuthority]
  [[VotingAuthority.Peers]]
    Identifier = "auth1"
"""


class ConfigTests(unittest.TestCase):
    def test_a_good_configuration_gets_our_fixed_addresses_and_no_log_file(self):
        client, thin = mix.check_config(CLIENT)
        self.assertIn('Address = "%s"' % mix.THIN, client)
        self.assertNotIn("kpclientd:32000", client)
        self.assertIn('File = ""', client)
        self.assertIn('Address = "%s"' % mix.THIN, thin)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "client.toml").write_text(CLIENT)
            target = mix.setup(d, Path(d) / "installed")
            self.assertEqual(sorted(p.name for p in target.iterdir()), sorted(mix.CONFIG_FILES))

    def test_unsafe_configurations_are_refused(self):
        for bad in [
            CLIENT.replace("DisableDecoyTraffic = false", "DisableDecoyTraffic = true"),
            CLIENT.replace('Type = "none"', 'Type = "socks5"'),
            CLIENT.replace("[PinnedGateways]", "[Other]"),
            CLIENT.replace("[VotingAuthority]", "[Other]"),
            # Classical Sphinx (an X25519 NIKE, or no KEM at all) is refused.
            CLIENT.replace('NIKEName = ""', 'NIKEName = "x25519"').replace('KEMName = "XWING"', 'KEMName = ""'),
            CLIENT.replace('KEMName = "XWING"', 'KEMName = "MLKEM768"'),
            # A classical directory signature anywhere (top level, or one gateway's).
            CLIENT.replace('PKISignatureScheme = "Ed25519 Sphincs+"\nWire', 'PKISignatureScheme = "Ed25519"\nWire'),
            CLIENT.replace('    PKISignatureScheme = "Ed25519 Sphincs+"', '    PKISignatureScheme = "ed25519"'),
            CLIENT.replace("PKISignatureScheme", "Other"),
            # A classical or missing link KEM.
            CLIENT.replace('    WireKEMScheme = "xwing"', '    WireKEMScheme = "x25519"'),
            CLIENT.replace("WireKEMScheme", "Other"),
            CLIENT.replace('[Listen.Tcp]\n    Address = "kpclientd:32000"', "[Listen.Unix]"),
        ]:
            with self.assertRaises(ValueError):
                mix.check_config(bad)

    def test_requests_are_absolute_urls_and_safe_methods(self):
        for url, method in [
            ("ftp://x/", "GET"),
            ("example.org/", "GET"),
            ("https://a b/", "GET"),
            ("https://x/", "POST"),
        ]:
            with self.assertRaises(ValueError):
                mix.request(url, method, timeout=0)

    def test_missing_programs_are_named(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict("os.environ", {"AVPN_KATZENPOST": d}):
            with self.assertRaisesRegex(RuntimeError, "kpclientd and http-proxy-client"):
                mix.binaries()


if __name__ == "__main__":
    unittest.main()

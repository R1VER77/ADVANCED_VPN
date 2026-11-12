"""The mix lane's configuration checks and request validation."""

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mix  # noqa: E402

CLIENT = """PKISignatureScheme = "Ed25519"
[Listen]
  [Listen.Tcp]
    Address = "kpclientd:32000"
    Network = "tcp"
[SphinxGeometry]
  PacketLength = 9082
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

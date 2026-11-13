"""The I2P front: destination keys, i2pd configuration, signed profiles and the kill switch."""

import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import i2p  # noqa: E402
import managed_profile as mp  # noqa: E402


class DestinationTests(unittest.TestCase):
    def test_keys_have_i2pds_layout_and_a_stable_b32(self):
        private, identity = i2p.destination_keys()
        self.assertEqual((len(private), len(identity)), (i2p.PRIVATE_LEN, i2p.IDENTITY_LEN))
        self.assertEqual(i2p.private_identity(private), identity)
        address = i2p.b32(identity)
        self.assertRegex(address, i2p.B32)
        self.assertEqual(address, i2p.b32(bytes(identity)))
        self.assertNotEqual(address, i2p.b32(i2p.destination_keys()[1]))
        # Key certificate: type 5, length 4, Ed25519 (7) signing, X25519 (4) encryption.
        self.assertEqual(identity[384:], bytes([5, 0, 4, 0, 7, 0, 4]))

    def test_other_key_types_and_lengths_are_refused(self):
        _, identity = i2p.destination_keys()
        for bad in [
            identity[:-1],
            identity + b"\0",
            identity[:387] + bytes([0, 1, 0, 4]),
            identity[:389] + bytes([0, 0]),
        ]:
            with self.assertRaises(ValueError):
                i2p.b32(bad)
        with self.assertRaises(ValueError):
            i2p.private_identity(b"\0" * 10)


class ConfigTests(unittest.TestCase):
    def test_a_production_router_offers_nothing_but_routing(self):
        conf = i2p.router_conf(None, host="198.51.100.7", port=12000)
        for section in ["http", "httpproxy", "socksproxy", "sam", "bob", "i2cp", "i2pcontrol", "addressbook", "upnp"]:
            self.assertIn("[%s]\nenabled = false" % section, conf)
        self.assertIn("notransit = true", conf)
        self.assertIn("loglevel = none", conf)
        self.assertIn("[reseed]\nverify = true", conf)
        self.assertIn("certsdir = " + i2p.CERTS_DIR, conf)
        self.assertIn("host = 198.51.100.7", conf)
        self.assertNotIn("netid", conf)
        self.assertNotIn("zipfile", conf)
        # The entry publishes its router; the client's is hidden and publishes nothing.
        self.assertIn("[trust]\nhidden = false", conf)
        client = i2p.router_conf(None)
        self.assertIn("[trust]\nhidden = true", client)
        self.assertNotIn("published = true", client)
        self.assertNotIn("host =", client)
        self.assertIn("[ssu2]\nenabled = false", client)
        self.assertIn("[ssu2]\nenabled = true", conf)

    def test_tunnels(self):
        client = i2p.tunnels_conf(dict(kind="i2p", destination="a" * 52 + ".b32.i2p", hops=2))
        self.assertIn("type = client", client)
        self.assertIn("port = 41197", client)
        self.assertIn("inbound.length = 2\noutbound.length = 2", client)
        self.assertIn("keys = transient", client)
        server = i2p.tunnels_conf(dict(kind="i2p", router_port=12000), "/run/x/i2p-a/front.dat", "/run/x/i2p-a")
        self.assertIn("type = server", server)
        self.assertIn("port = 8443", server)
        self.assertIn("inbound.length = 0\noutbound.length = 0", server)
        # i2pd prefixes the datadir to any keys path: it must be relative.
        self.assertIn("keys = front.dat\n", server)

    def test_front_sections(self):
        good = dict(kind="i2p", destination="b" * 52 + ".b32.i2p", hops=1)
        self.assertEqual(i2p.valid_front(good, "client"), good)
        for bad in [
            dict(good, hops=0),
            dict(good, hops=4),
            dict(good, destination="b" * 51 + ".b32.i2p"),
            dict(good, kind="tor"),
            dict(good, extra=1),
        ]:
            with self.assertRaises(ValueError):
                i2p.valid_front(bad, "client")
        i2p.valid_front(dict(kind="i2p", router_port=12000), "server")
        for port in [80, 40000, "12000"]:
            with self.assertRaises(ValueError):
                i2p.valid_front(dict(kind="i2p", router_port=port), "server")

    def test_front_firewall_drops_the_entry_both_ways(self):
        text = i2p.front_firewall("192.0.2.66")
        self.assertIn("ip daddr 192.0.2.66 drop", text)
        self.assertIn("ip saddr 192.0.2.66 drop", text)
        with self.assertRaises(ValueError):
            i2p.front_firewall("192.0.2.66; flush ruleset")


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "lab"
        cls.root.mkdir()
        mp.lab_setup(cls.root, "192.0.2.1:443", "198.51.100.2:4444", front="i2p", front_hops=1)
        cls.profiles = {r: json.loads((cls.root / r / "profile.json").read_text()) for r in ["client", "relay", "exit"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_client_reaches_the_entrys_own_destination(self):
        client, relay = self.profiles["client"], self.profiles["relay"]
        request = json.loads((self.root / "relay/request.json").read_text())
        self.assertEqual(client["front"]["destination"], i2p.b32(base64.b64decode(request["i2p_destination"])))
        self.assertEqual(client["front"]["hops"], 1)
        self.assertEqual(client["cloak"]["remote"], i2p.CLIENT_TUNNEL)
        self.assertEqual(client["cloak"]["front"], "i2p")
        self.assertEqual(relay["cloak"]["front"], "i2p")
        self.assertTrue(i2p.PORT_RANGE[0] <= relay["front"]["router_port"] <= i2p.PORT_RANGE[1])
        self.assertNotIn("front", self.profiles["exit"])
        # The entry's destination keys are its own, protected with its other keys.
        keys = mp.load_keys(self.root / "relay", ["i2p"])
        self.assertEqual(i2p.private_identity(keys["i2p"]), base64.b64decode(request["i2p_destination"]))

    def test_tampered_profiles_are_refused(self):
        client, relay, exit_ = self.profiles["client"], self.profiles["relay"], self.profiles["exit"]
        cases = []
        p = copy.deepcopy(client)
        p["cloak"]["remote"] = client["network"]["relay_endpoint"]  # straight to the entry
        cases.append(p)
        p = copy.deepcopy(client)
        del p["cloak"]["front"]
        cases.append(p)
        p = copy.deepcopy(client)
        del p["front"]
        cases.append(p)
        p = copy.deepcopy(client)
        p["carrier"]["rate"] = "fast"
        cases.append(p)
        p = copy.deepcopy(exit_)
        p["front"] = dict(relay["front"])
        cases.append(p)
        p = copy.deepcopy(relay)
        p["front"] = dict(client["front"])
        cases.append(p)
        for k, bad in enumerate(cases):
            with self.assertRaises(ValueError, msg="case %d" % k):
                mp.profile_validate(bad)
        mp.profile_validate(copy.deepcopy(client))
        mp.profile_validate(copy.deepcopy(relay))

    def test_init_refuses_fast_classes_and_old_entry_keys(self):
        reqs = {r: (self.root / r / "request.json").read_bytes() for r in ["client", "relay", "exit"]}
        signer = mp.SoftwareOperator(self.root / "operator-keys")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "rate classes"):
                mp.create(Path(d) / "a", reqs, "192.0.2.1:443", "198.51.100.2:4444", signer, rate="fast", front="i2p")
            old = json.loads(reqs["relay"])
            del old["i2p_destination"]
            with self.assertRaisesRegex(ValueError, "predate the I2P front"):
                mp.create(
                    Path(d) / "b",
                    dict(reqs, relay=json.dumps(old).encode()),
                    "192.0.2.1:443",
                    "198.51.100.2:4444",
                    signer,
                    front="i2p",
                )

    def test_runtime_and_identities(self):
        import avpnctl

        cfg = mp.runtime(self.profiles["relay"], self.root / "relay")
        self.assertIn("i2p", avpnctl.managed_identities(cfg))
        self.assertNotIn("front", avpnctl.BINARIES)
        cfg = mp.runtime(self.profiles["client"], self.root / "client")
        self.assertNotIn("i2p", avpnctl.managed_identities(cfg))
        self.assertEqual(cfg["front"]["hops"], 1)


class KillSwitchTests(unittest.TestCase):
    def rules(self, profile, service_uid, front_uid):
        import avpnctl

        with mock.patch.object(avpnctl, "replace_table") as table:
            avpnctl.whole_firewall(profile, service_uid, front_uid)
        return table.call_args[0][0]

    def test_only_the_i2p_router_leaves_and_never_to_the_entry_directly(self):
        profile = dict(network=dict(relay_endpoint="192.0.2.66:443"), front=dict(kind="i2p"))
        text = self.rules(profile, 1, 2)
        self.assertIn("meta skuid 2 meta l4proto {tcp, udp} accept", text)
        self.assertNotIn("192.0.2.66", text)
        self.assertNotIn("meta skuid 1 ip daddr 192.0.2.66", text)
        for uid in [None, 0, 1]:
            with self.assertRaises(RuntimeError):
                self.rules(profile, 1, uid)

    def test_without_a_front_the_carrier_reaches_only_the_entry(self):
        text = self.rules(dict(network=dict(relay_endpoint="192.0.2.66:443")), 1, None)
        self.assertIn("meta skuid 1 ip daddr 192.0.2.66 udp dport 443 accept", text)
        self.assertIn("meta skuid 1 ip daddr 192.0.2.66 tcp dport 443 accept", text)
        self.assertNotIn("l4proto", text)


class RouterVersionTests(unittest.TestCase):
    def fake(self, d, text):
        path = Path(d) / "i2pd"
        path.write_text("#!/bin/sh\necho '%s'\n" % text)
        path.chmod(0o755)
        return path

    def test_only_proven_i2pd_versions_run_the_front(self):
        import avpnctl

        with tempfile.TemporaryDirectory() as d:
            for text, ok in [
                ("i2pd version 2.56.0 (0.9.65)", True),
                ("i2pd version 2.58.1 (0.9.67)", True),
                ("i2pd version 2.49.0 (0.9.60)", False),
                ("something else", False),
            ]:
                with mock.patch.dict("os.environ", {"AVPN_I2PD": str(self.fake(d, text))}):
                    if ok:
                        self.assertEqual(avpnctl.front_binary(True).name, "i2pd")
                    else:
                        with self.assertRaisesRegex(RuntimeError, "2.56.0 or newer"):
                            avpnctl.front_binary(True)


class HardwareSealingTests(unittest.TestCase):
    def test_a_first_hop_can_seal_every_key_under_a_nitrokey(self):
        # Regression: the cloak key had no envelope binding, so a first hop with Nitrokey
        # protection could not create its keys at all.
        import keyguard

        meta = dict(credential=keyguard.b64(b"credential-id"), salt=keyguard.b64(b"s" * 32))
        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch.object(keyguard, "hardware_secret", return_value=(b"k" * 32, meta)),
        ):
            state = Path(d) / "relay"
            mp.request("relay", state, "nitrokey", Path(d) / "vault")
            keys = mp.load_keys(state, ["cloak", "i2p", "wireguard", "kem"], b"k" * 32, meta)
            self.assertEqual(len(keys["i2p"]), i2p.PRIVATE_LEN)
            with self.assertRaises(Exception):
                mp.load_keys(state, ["i2p"], b"x" * 32, meta)  # another vault's secret


if __name__ == "__main__":
    unittest.main()


class TableWatchTests(unittest.TestCase):
    """The kill-switch drift watchdog (avpnctl.TableWatch), against a fake nft."""

    def fake(self, tables):
        import avpnctl

        loaded = []

        def cmd(*args, check=True, input=None):
            name = args[-1]
            out = tables.get(name)
            return mock.Mock(returncode=0 if out is not None else 1, stdout=out or "")

        def nft(text, ns=None):
            loaded.append((text, ns))
            name = text.split("table inet ")[-1].split(" ")[0]
            tables[name] = text.split("\n", 1)[1] if text.startswith("delete") else text

        return mock.patch.multiple(avpnctl, cmd=cmd, nft=nft), loaded

    def test_deleted_and_altered_tables_are_restored_exactly(self):
        import avpnctl

        tables = {"advanced_vpn": "table inet advanced_vpn { policy drop }\n"}
        patch, loaded = self.fake(tables)
        with patch:
            watch = avpnctl.TableWatch([("advanced_vpn", None), ("advanced_vpn_front", None)])
            self.assertEqual(watch.check(), [])  # untouched, and an absent table is not watched
            del tables["advanced_vpn"]
            self.assertEqual(watch.check(), [("advanced_vpn", None)])
            self.assertEqual(tables["advanced_vpn"], "table inet advanced_vpn { policy drop }\n")
            tables["advanced_vpn"] = "table inet advanced_vpn { policy accept }\n"
            watch.check()
            self.assertTrue(loaded[-1][0].startswith("delete table inet advanced_vpn\n"))
            self.assertEqual(tables["advanced_vpn"], "table inet advanced_vpn { policy drop }\n")

    def test_a_restore_storm_fails_closed(self):
        import avpnctl

        tables = {"advanced_vpn": "table inet advanced_vpn { policy drop }\n"}
        patch, _ = self.fake(tables)
        with patch:
            watch = avpnctl.TableWatch([("advanced_vpn", None)], limit=3, window=60)
            for k in range(3):
                del tables["advanced_vpn"]
                watch.check(now=k)
            del tables["advanced_vpn"]
            with self.assertRaisesRegex(RuntimeError, "kill switch keeps being altered"):
                watch.check(now=10)

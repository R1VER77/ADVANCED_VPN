"""Oblivious control-plane requests: encapsulation, refusal and an end-to-end relay path."""

import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ohttp  # noqa: E402

MARKER = b"MARKER-7f3a"


class EncapsulationTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public = ohttp.keypair()
        self.gw = ohttp.Gateway(self.private, 7)

    def test_round_trip_and_the_relay_sees_no_plaintext(self):
        wire, reply = ohttp.encapsulate(self.public, 7, "POST", "/gossip", MARKER)
        self.assertNotIn(MARKER, wire)
        method, path, body, reply_key = self.gw.open(wire)
        self.assertEqual((method, path, body), ("POST", "/gossip", MARKER))
        sealed = self.gw.seal(reply_key, 200, b'{"ok":true}')
        self.assertNotIn(b'"ok"', sealed)
        self.assertEqual(ohttp.decapsulate(sealed, reply), (200, b'{"ok":true}'))

    def test_tampering_wrong_key_staleness_and_replay_are_refused(self):
        wire, reply = ohttp.encapsulate(self.public, 7, "GET", "/descriptors")
        for i in [0, 1, 7, 20, len(wire) - 1]:
            bad = bytearray(wire)
            bad[i] ^= 1
            with self.assertRaises(ohttp.Refused, msg="byte %d" % i):
                self.gw.open(bytes(bad))
        with self.assertRaises(ohttp.Refused):
            ohttp.Gateway(self.private, 8).open(wire)  # another key id
        other_private, _ = ohttp.keypair()
        with self.assertRaises(ohttp.Refused):
            ohttp.Gateway(other_private, 7).open(wire)  # another gateway's key
        with self.assertRaises(ohttp.Refused):
            self.gw.open(wire, now=time.time() + ohttp.FRESH_SECONDS + 5)  # stale
        self.gw.open(wire)
        with self.assertRaises(ohttp.Refused):
            self.gw.open(wire)  # replayed

    def test_a_restarted_gateway_refuses_replays_of_earlier_requests(self):
        wire, _ = ohttp.encapsulate(self.public, 7, "POST", "/v1/test", b"x")
        self.gw.open(wire)
        t = time.time()
        restarted = ohttp.Gateway(self.private, 7, started=t + 1)  # its cache is empty
        with self.assertRaises(ohttp.Refused):
            restarted.open(wire, now=t + 2)
        fresh, _ = ohttp.encapsulate(self.public, 7, "POST", "/v1/test", b"y")
        self.assertEqual(ohttp.Gateway(self.private, 7, started=t).open(fresh, now=t + 2)[2], b"y")

    def test_a_response_opens_only_with_its_own_reply_key(self):
        wire, reply = ohttp.encapsulate(self.public, 7, "GET", "/health")
        _, _, _, reply_key = self.gw.open(wire)
        sealed = bytearray(self.gw.seal(reply_key, 200, b"x"))
        _, other = ohttp.encapsulate(self.public, 7, "GET", "/health")
        with self.assertRaises(ohttp.Refused):
            ohttp.decapsulate(bytes(sealed), other)
        sealed[-1] ^= 1
        with self.assertRaises(ohttp.Refused):
            ohttp.decapsulate(bytes(sealed), reply)

    def test_gateway_keys_persist(self):
        from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

        m, x = mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        private, public = ohttp.load_private(ohttp.private_bytes(m, x))
        self.assertEqual(public, ohttp.public_bytes(m, x))
        wire, _ = ohttp.encapsulate(public, 1, "GET", "/health")
        ohttp.Gateway(private, 1).open(wire)


class RouteTests(unittest.TestCase):
    def test_same_operator_relay_and_gateway_is_refused(self):
        import base64

        import mesh

        _, public = ohttp.keypair()
        entry = dict(
            relay="https://relay.example:8788",
            gateway_public=base64.b64encode(public).decode(),
            key_id=1,
            relay_operator="!aaaaaaaa",
            gateway_operator="!aaaaaaaa",
        )
        with self.assertRaises(ValueError):
            mesh.beacon_entry(entry)
        entry["gateway_operator"] = "!bbbbbbbb"
        self.assertEqual(mesh.beacon_entry(entry)["relay"], "https://relay.example:8788")
        with self.assertRaises(ValueError):
            mesh.beacon_entry(dict(entry, relay="file:///etc/passwd"))

    def test_end_to_end_through_a_relay_and_a_beacon_gateway(self):
        import base64

        import mesh
        import mesh_beacon
        import ohttp_relay

        with tempfile.TemporaryDirectory() as d:
            beacon = mesh_beacon.serve(Path(d) / "state", "127.0.0.1", 0, [], Path(d) / "gw.key")
            threading.Thread(target=beacon.serve_forever, daemon=True).start()
            port = beacon.server_address[1]
            relay = ohttp_relay.serve("http://127.0.0.1:%d" % port, "127.0.0.1", 0)
            threading.Thread(target=relay.serve_forever, daemon=True).start()
            try:
                import urllib.request

                with urllib.request.urlopen("http://127.0.0.1:%d/ohttp-config" % port) as r:  # noqa: S310
                    cfg = json.loads(r.read())
                entry = mesh.beacon_entry(
                    dict(
                        relay="http://127.0.0.1:%d" % relay.server_address[1],
                        gateway_public=cfg["public"],
                        key_id=cfg["key_id"],
                        relay_operator="!aaaaaaaa",
                        gateway_operator="!bbbbbbbb",
                    )
                )
                status, doc = mesh.beacon_call(entry, "GET", "/health")
                self.assertEqual((status, doc["ok"]), (200, True))
                status, doc = mesh.beacon_call(entry, "GET", "/descriptors")
                self.assertEqual(status, 200)
                self.assertEqual(doc["descriptors"], [])
                # A forged request through the relay is refused by the gateway.
                req = urllib.request.Request("http://127.0.0.1:%d/relay" % relay.server_address[1], data=b"\x01" * 400)  # noqa: S310 (local test server)
                with self.assertRaises(urllib.error.HTTPError):
                    with urllib.request.urlopen(req) as r:  # noqa: S310 (local test server)
                        ohttp.decapsulate(r.read(), ohttp.keypair()[0])
                self.assertTrue(base64.b64decode(cfg["public"]))
            finally:
                for server in (beacon, relay):
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    unittest.main()

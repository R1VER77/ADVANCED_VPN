"""Oblivious control-plane requests: encapsulation, refusal and an end-to-end relay path."""

import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ohttp  # noqa: E402
import timesync  # noqa: E402

MARKER = b"MARKER-7f3a"


def setUpModule():
    # Tests read the local clock as the synchronized one (no network); TimeSync below
    # covers the synchronization itself.
    global _clock
    _clock = mock.patch.object(timesync, "now", time.time)
    _clock.start()


def tearDownModule():
    _clock.stop()


def running_gateway(private, key_id):
    """A gateway that has been up for a while, so this bucket's requests are after its start."""
    return ohttp.Gateway(private, key_id, started=time.time() - 2 * ohttp.BUCKET)


class EncapsulationTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public = ohttp.keypair()
        self.gw = running_gateway(self.private, 7)

    def test_round_trip_and_the_relay_sees_no_plaintext(self):
        wire, reply = ohttp.encapsulate(self.public, 7, "POST", "/gossip", MARKER)
        self.assertNotIn(MARKER, wire)
        method, path, body, reply_key = self.gw.open(wire)
        self.assertEqual((method, path, body), ("POST", "/gossip", MARKER))
        sealed = self.gw.seal(reply_key, 200, b'{"ok":true}')
        self.assertNotIn(b'"ok"', sealed)
        self.assertEqual(ohttp.decapsulate(sealed, reply), (200, b'{"ok":true}'))

    def test_two_requests_from_one_member_share_only_what_every_member_sends(self):
        """The code side of formal/ohttp/ohttp_unlinkability.pv: opened by the gateway, two
        identical requests from one member agree only on the gateway's header, the chosen
        method, path and body, and the clock reading (named in the model as not covered);
        the nonce and the reply key are fresh, and nothing else is in a request."""
        h = ohttp.header(7)
        inner = []
        for _ in range(2):
            wire, _reply = ohttp.encapsulate(self.public, 7, "GET", "/descriptors")
            self.assertEqual(wire[: len(h)], h)
            inner.append(json.loads(ohttp.SUITE.decrypt(wire[len(h) :], self.private, ohttp.REQUEST_INFO + h)))
        a, b = inner
        self.assertEqual(set(a), {"t", "nonce", "method", "path", "body", "reply"})
        self.assertNotEqual(a["nonce"], b["nonce"])
        self.assertNotEqual(a["reply"], b["reply"])
        self.assertLessEqual({k for k in a if a[k] == b[k]}, {"t", "method", "path", "body"})

    def test_tampering_wrong_key_staleness_and_replay_are_refused(self):
        wire, reply = ohttp.encapsulate(self.public, 7, "GET", "/descriptors")
        for i in [0, 1, 7, 20, len(wire) - 1]:
            bad = bytearray(wire)
            bad[i] ^= 1
            with self.assertRaises(ohttp.Refused, msg="byte %d" % i):
                self.gw.open(bytes(bad))
        with self.assertRaises(ohttp.Refused):
            running_gateway(self.private, 8).open(wire)  # another key id
        other_private, _ = ohttp.keypair()
        with self.assertRaises(ohttp.Refused):
            running_gateway(other_private, 7).open(wire)  # another gateway's key
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
        # A request in a bucket after the restart is accepted (one in the restart's own
        # bucket is not: the client retries in the next).
        later = t + ohttp.BUCKET + 5
        fresh, _ = ohttp.encapsulate(self.public, 7, "POST", "/v1/test", b"y", now=later)
        self.assertEqual(ohttp.Gateway(self.private, 7, started=t).open(fresh, now=later + 2)[2], b"y")

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
        running_gateway(private, 1).open(wire)


class TimeSync(unittest.TestCase):
    """The timestamp would link a member with a skewed clock; it comes from a synchronized
    clock, in whole buckets (tools/timesync.py, Tails' htpdate method)."""

    def pools(self, answers):
        return lambda host: answers[host]() if callable(answers[host]) else answers[host]

    def test_members_with_skewed_clocks_send_the_same_timestamp(self):
        true = 1_800_000_000 - 1_800_000_000 % ohttp.BUCKET + 5  # 5 s into a bucket
        private, public = ohttp.keypair()
        inner = []
        for skew in (+7, -11):
            local = true + skew
            # Every pool reports the true time, so each member's offset cancels its skew.
            offset = timesync.synchronize(pools=(("a",), ("b",), ("c",)), offset_of=lambda host, s=skew: -s - 0.4)
            for clock in (local, local + offset):
                wire, _ = ohttp.encapsulate(public, 1, "GET", "/health", now=clock)
                h = ohttp.header(1)
                inner.append(json.loads(ohttp.SUITE.decrypt(wire[len(h) :], private, ohttp.REQUEST_INFO + h))["t"])
        raw_fast, synced_fast, raw_slow, synced_slow = inner
        self.assertNotEqual(raw_fast, raw_slow)  # unsynchronized, the skew shows
        self.assertEqual(synced_fast, synced_slow)  # synchronized, it does not
        self.assertEqual(synced_fast % ohttp.BUCKET, 0)

    def test_the_gateway_refuses_a_timestamp_that_is_not_a_whole_bucket(self):
        private, public = ohttp.keypair()
        now = 1_800_000_007.0
        with mock.patch.object(ohttp, "BUCKET", 1):  # an old or careless client: exact seconds
            wire, _ = ohttp.encapsulate(public, 1, "GET", "/health", now=now)
        with self.assertRaisesRegex(ohttp.Refused, "whole bucket"):
            ohttp.Gateway(private, 1, started=now - 100).open(wire, now=now)

    def test_one_lying_pool_is_outvoted_and_disagreement_or_silence_refuses(self):
        three = (("a",), ("b",), ("c",))
        self.assertAlmostEqual(timesync.synchronize(three, self.pools(dict(a=2.0, b=3.0, c=3600.0))), 3.0)
        with self.assertRaises(timesync.ClockUnsynchronized):
            timesync.synchronize(three, self.pools(dict(a=0.0, b=900.0, c=-900.0)))

        def down():
            raise OSError("unreachable")

        with self.assertRaises(timesync.ClockUnsynchronized):
            timesync.synchronize((("a", "a2"), ("b",), ("c",)), self.pools(dict(a=down, a2=down, b=1.0, c=1.0)))
        # A pool's second server stands in for its first.
        self.assertEqual(
            timesync.synchronize((("a", "a2"), ("b",), ("c",)), self.pools(dict(a=down, a2=1.0, b=1.0, c=1.0))), 1.0
        )


class DateHeaders(unittest.TestCase):
    """What a time server's answer may be used for (found in a live survey: CDNs serve
    cached answers whose Date is stale, or rewritten, so Age cannot be trusted)."""

    def answer(self, age=None, error=False, date=True):
        import email.utils
        from email.message import Message

        headers = Message()
        if date:
            headers["Date"] = email.utils.formatdate(time.time(), usegmt=True)
        if age is not None:
            headers["Age"] = str(age)
        if error:
            import urllib.error

            return mock.patch(
                "urllib.request.urlopen", side_effect=urllib.error.HTTPError("u", 405, "x", headers, None)
            )
        response = mock.MagicMock(headers=headers)
        response.__enter__.return_value = response
        return mock.patch("urllib.request.urlopen", return_value=response)

    def test_a_fresh_answer_or_an_error_page_gives_the_offset(self):
        for kwargs in (dict(), dict(age=0), dict(error=True)):
            with self.answer(**kwargs):
                self.assertLess(abs(timesync.date_offset("example.org")), 2)

    def test_a_cached_answer_or_one_without_a_date_is_refused(self):
        for kwargs, reason in ((dict(age=4417), "cached"), (dict(date=False), "no Date")):
            with self.answer(**kwargs), self.assertRaisesRegex(ValueError, reason):
                timesync.date_offset("example.org")


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
            mesh_beacon.Handler.state.gateway.started -= 2 * ohttp.BUCKET  # as if it had been running
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
                # Unverified, the route may only fetch the directory (key consistency,
                # tools/test_gateway_consistency.py); once verified, anything.
                status, doc = mesh.beacon_call(entry, "GET", "/descriptors")
                self.assertEqual(status, 200)
                self.assertEqual(doc["descriptors"], [])
                with self.assertRaises(mesh.GatewayKeyRefused):
                    mesh.beacon_call(entry, "GET", "/health")
                with mock.patch.object(mesh, "gateway_verified", lambda e: True):
                    status, doc = mesh.beacon_call(entry, "GET", "/health")
                self.assertEqual((status, doc["ok"]), (200, True))
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

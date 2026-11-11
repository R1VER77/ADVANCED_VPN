#!/usr/bin/env python3
"""Tests for the mesh beacon (tools/mesh_beacon.py).

ML-DSA is not available in every build environment, so signature verification
is stubbed: these tests cover the beacon's own logic (validation, dedup, TTL
pruning, rate limits, bans, forwarding discipline), not the ML-DSA primitive,
which src/mesh and tools/mesh.py test separately.
"""

import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mesh  # noqa: E402
import mesh_beacon as mb  # noqa: E402


def make_descriptor(node: str, published: int | None = None, ttl: int = 3600) -> dict:
    now = int(time.time()) if published is None else published
    return {
        "schema": mesh.SCHEMA,
        "node_id": node,
        "node_public_key": "AA==",
        "wg_public_key": "AA==",
        "cloak_endpoint": "node.example:443",
        "roles": ["relay"],
        "provider": "oci",
        "country": "DE",
        "capacity": {"egress_gib_month": 10240, "cover_budget_mib_day": 2048},
        "health": {"uptime_30d": 1.0, "latency_ms_p50": 12},
        "group": "public",
        "operator": node,
        "published": now,
        "expires": now + ttl,
        "signature": "AA==",
    }


class BeaconCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Accept every signature; reject nothing at the crypto layer.
        self._verify = mesh.verify_descriptor
        mesh.verify_descriptor = lambda d: True
        self.addCleanup(setattr, mesh, "verify_descriptor", self._verify)
        self.state = mb.BeaconState(Path(self.tmp.name) / "state")
        self.server = mb.ThreadingHTTPServer(("127.0.0.1", 0), mb.Handler)
        mb.Handler.state = self.state
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def post(self, descriptor, hop=0):
        return self._post_raw(descriptor, hop)

    def _post_raw(self, descriptor, hop):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps({"descriptor": descriptor, "hop": hop})
        conn.request("POST", "/gossip", body, {"Content-Type": "application/json"})
        r = conn.getresponse()
        payload = json.loads(r.read())
        conn.close()
        return payload

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        r = conn.getresponse()
        payload = json.loads(r.read())
        conn.close()
        return payload


class IngestTests(BeaconCase):
    def test_valid_descriptor_is_stored_and_listed(self):
        d = make_descriptor("!aaaa1111")
        self.assertTrue(self.post(d)["ok"])
        got = self.get("/descriptors")
        self.assertEqual([x["node_id"] for x in got["descriptors"]], ["!aaaa1111"])

    def test_duplicate_is_not_replaced(self):
        d1 = make_descriptor("!bbbb2222", published=int(time.time()) - 10)
        d2 = make_descriptor("!bbbb2222", published=int(time.time()) - 20)
        self.assertTrue(self.post(d1)["ok"])
        self.assertFalse(self.post(d2)["ok"])  # older copy refused
        self.assertEqual(self.state.descriptors["!bbbb2222"]["published"], d1["published"])

    def test_expired_descriptor_is_rejected(self):
        d = make_descriptor("!cccc3333", published=int(time.time()) - 7200, ttl=3600)
        self.assertFalse(self.post(d)["ok"])

    def test_invalid_signature_is_rejected_and_counts_toward_a_ban(self):
        d = make_descriptor("!dddd4444")
        mesh.verify_descriptor = lambda x: False
        for _ in range(mb.MAX_BANS_BEFORE_PERSIST):
            self.assertFalse(self.post(d)["ok"])
        self.assertIn("!dddd4444", self.state.bans)
        mesh.verify_descriptor = lambda x: True
        self.assertFalse(self.post(d)["ok"])  # banned members stay refused

    def test_rate_limit_per_member(self):
        for i in range(mb.MAX_POSTS_PER_MEMBER_PER_HOUR):
            d = make_descriptor("!eeee5555", published=int(time.time()) + i)
            self.assertTrue(self.post(d)["ok"])
        d = make_descriptor("!eeee5555", published=int(time.time()) + 99)
        self.assertFalse(self.post(d)["ok"])

    def test_oversize_body_is_refused(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/gossip", "x" * (mb.MAX_BODY_BYTES + 1),
                     {"Content-Type": "application/json"})
        r = conn.getresponse()
        self.assertEqual(r.status, 413)
        r.read()
        conn.close()

    def test_ttl_pruning(self):
        d = make_descriptor("!ffff6666", published=int(time.time()) - 7200, ttl=3600)
        self.state.descriptors[d["node_id"]] = d  # inject as if stored earlier
        self.assertEqual(self.state.prune(), 1)
        self.assertEqual(self.state.descriptors, {})

    def test_state_survives_a_reload(self):
        self.assertTrue(self.post(make_descriptor("!aaaa7777"))["ok"])
        reloaded = mb.BeaconState(Path(self.tmp.name) / "state")
        self.assertIn("!aaaa7777", reloaded.descriptors)


class ForwardingTests(BeaconCase):
    def test_descriptor_is_forwarded_once_with_incremented_hop(self):
        received = []

        class Recorder(mb.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length"))
                received.append(json.loads(self.rfile.read(length)))
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        peer = mb.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        self.addCleanup(peer.shutdown)
        self.state.peers = [f"http://127.0.0.1:{peer.server_address[1]}"]

        d = make_descriptor("!ffff8888")
        self.assertTrue(self.post(d, hop=1)["ok"])
        deadline = time.time() + 5
        while not received and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["hop"], 2)
        self.assertEqual(received[0]["descriptor"]["node_id"], "!ffff8888")

        # The same (node_id, published) is never forwarded twice.
        self.state._maybe_forward(d, 1)
        time.sleep(0.3)
        self.assertEqual(len(received), 1)

    def test_hop_limit_stops_forwarding(self):
        self.state.peers = ["http://127.0.0.1:1"]  # would fail loudly if used
        d = make_descriptor("!gggg9999")
        self.assertTrue(self.post(d, hop=mb.GOSSIP_HOP_LIMIT)["ok"])
        self.assertNotIn((d["node_id"], d["published"]), self.state.forwarded)


class GossipSendTests(BeaconCase):
    def test_gossip_descriptor_posts_to_configured_beacons(self):
        mesh_dir = Path(self.tmp.name) / "meshdir"
        mesh_dir.mkdir()
        (mesh_dir / "beacons.json").write_text(json.dumps([f"http://127.0.0.1:{self.port}"]))
        old = mesh.MESH_DIR
        mesh.MESH_DIR = mesh_dir
        self.addCleanup(setattr, mesh, "MESH_DIR", old)
        d = make_descriptor("!zzzz9999")
        result = mesh.gossip_descriptor(d)
        self.assertEqual(result, {"sent": 1, "beacons": 1})
        self.assertIn("!zzzz9999", self.state.descriptors)

    def test_gossip_descriptor_without_beacons_is_a_noop(self):
        mesh_dir = Path(self.tmp.name) / "empty"
        mesh_dir.mkdir()
        old = mesh.MESH_DIR
        mesh.MESH_DIR = mesh_dir
        self.addCleanup(setattr, mesh, "MESH_DIR", old)
        self.assertEqual(mesh.gossip_descriptor(make_descriptor("!yyyy0000"))["sent"], 0)


class GetTests(BeaconCase):
    def test_get_limit_is_capped(self):
        for i in range(5):
            self.post(make_descriptor(f"!hhhh{i:04d}"))
        self.assertEqual(len(self.get("/descriptors?limit=3")["descriptors"]), 3)
        self.assertEqual(len(self.get("/descriptors?limit=9999")["descriptors"]), 5)

    def test_get_rate_limit_keeps_the_fixed_shape(self):
        for _ in range(mb.MAX_GETS_PER_IP_PER_MINUTE):
            self.get("/health")  # health does not spend the budget
            self.state.admit_get("127.0.0.1")
        # Budget now exhausted for this IP:
        self.assertFalse(self.state.admit_get("127.0.0.1"))

    def test_health_reports_descriptor_count(self):
        self.post(make_descriptor("!iiii0001"))
        self.assertEqual(self.get("/health")["descriptors"], 1)


if __name__ == "__main__":
    unittest.main()

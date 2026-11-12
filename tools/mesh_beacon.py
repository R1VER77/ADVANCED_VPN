#!/usr/bin/env python3
"""avpn-mesh-beacon: store-and-forward directory gossip for AVPN/Mesh.

Beacons are the mesh's always-on meeting points (the role MQTT plays for
Meshtastic): members POST signed node descriptors; the beacon validates,
deduplicates, rate-limits per member, prunes expired entries and forwards
fresh ones to its peer beacons with a hop counter (TTL 3). Clients GET the
current directory.

Anti-amplification discipline:
- a POST never triggers data-plane traffic and the response is a small
  fixed-size ack, whatever the request looked like;
- a descriptor is forwarded at most once per (node_id, published) pair, so a
  gossip loop cannot fan out;
- per-member POST and per-IP GET rate limits are token buckets with small
  capacities;
- request bodies are size-capped and responses never echo request data.

Runs as an unprivileged user. State is one directory with two JSON files:
directory.json (the descriptors it currently holds) and bans.json (members
that submitted too many invalid descriptors). Both are world-readable-nothing:
descriptors are public information, but the files stay 0600 like every other
mesh artifact.
"""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mesh  # noqa: E402  (descriptor validation + ML-DSA verification)
import ohttp  # noqa: E402  (oblivious requests: the gateway side)

GOSSIP_HOP_LIMIT = mesh.GOSSIP_HOP_LIMIT
MAX_BODY_BYTES = 65536
MAX_POSTS_PER_MEMBER_PER_HOUR = 6
MAX_GETS_PER_IP_PER_MINUTE = 60
MAX_BANS_BEFORE_PERSIST = 3  # invalid submissions before a member is banned
GET_DEFAULT_LIMIT = 100
GET_MAX_LIMIT = 500


def _atomic_write(path: Path, doc: dict):
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(doc, indent=1) + "\n")
    os.replace(tmp, path)


class BeaconState:
    """The beacon's mutable state, guarded by one lock."""

    def __init__(self, state_dir: Path, peers: list[str] | None = None):
        self.dir = Path(state_dir)
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.peers = [mesh.beacon_url(u) for u in peers or []]
        self.lock = threading.Lock()
        self.descriptors: dict[str, dict] = {}
        self.forwarded: set[tuple[str, int]] = set()
        self.post_budget: dict[str, list[float]] = {}
        self.get_budget: dict[str, list[float]] = {}
        self.invalid: dict[str, int] = {}
        self.bans: set[str] = set()
        self._load()

    def _load(self):
        dpath = self.dir / "directory.json"
        if dpath.exists():
            doc = json.loads(dpath.read_text())
            for d in doc.get("descriptors", []):
                self.descriptors[d["node_id"]] = d
        bpath = self.dir / "bans.json"
        if bpath.exists():
            self.bans = set(json.loads(bpath.read_text()).get("banned", []))
        self.prune()

    def prune(self, now: float | None = None):
        """Drop expired descriptors (TTL discipline, same as clients)."""
        now = time.time() if now is None else now
        dead = [k for k, d in self.descriptors.items() if d.get("expires", 0) <= now]
        for k in dead:
            del self.descriptors[k]
        return len(dead)

    def flush(self):
        """Persist the directory and ban list atomically."""
        doc = {"schema": mesh.SCHEMA, "descriptors": sorted(self.descriptors.values(), key=lambda d: d["node_id"])}
        _atomic_write(self.dir / "directory.json", doc)
        _atomic_write(self.dir / "bans.json", {"schema": 1, "banned": sorted(self.bans)})

    # ------------------------------------------------------------ decisions

    def admit_post(self, member: str, now: float | None = None) -> bool:
        """Per-member POST token bucket: MAX_POSTS_PER_MEMBER_PER_HOUR."""
        now = time.time() if now is None else now
        stamps = [t for t in self.post_budget.get(member, []) if now - t < 3600]
        if len(stamps) >= MAX_POSTS_PER_MEMBER_PER_HOUR:
            self.post_budget[member] = stamps
            return False
        stamps.append(now)
        self.post_budget[member] = stamps
        return True

    def admit_get(self, ip: str, now: float | None = None) -> bool:
        """Whether this address may make another GET this minute."""
        now = time.time() if now is None else now
        stamps = [t for t in self.get_budget.get(ip, []) if now - t < 60]
        if len(stamps) >= MAX_GETS_PER_IP_PER_MINUTE:
            self.get_budget[ip] = stamps
            return False
        stamps.append(now)
        self.get_budget[ip] = stamps
        return True

    def ingest(self, descriptor: dict, hop: int, now: float | None = None) -> str:
        """Validate and store one descriptor. Returns a short status string;
        the caller maps every non-"stored" status to the same small nack."""
        now = time.time() if now is None else now
        node = descriptor.get("node_id", "?")
        with self.lock:
            if node in self.bans:
                return "banned"
            if not self.admit_post(node, now):
                return "rate-limited"
            if mesh.validate(descriptor, now) or not mesh.verify_descriptor(descriptor):
                count = self.invalid.get(node, 0) + 1
                self.invalid[node] = count
                if count >= MAX_BANS_BEFORE_PERSIST:
                    self.bans.add(node)
                    self.flush()
                return "invalid"
            known = self.descriptors.get(node)
            if known and known.get("published", 0) >= descriptor.get("published", 0):
                return "duplicate"  # stored copy is at least as fresh
            self.descriptors[node] = descriptor
            self.flush()
        self._maybe_forward(descriptor, hop)
        return "stored"

    def _maybe_forward(self, descriptor: dict, hop: int):
        """Store-and-forward with TTL and duplicate suppression: each beacon
        forwards a given (node_id, published) at most once, ever."""
        if hop >= GOSSIP_HOP_LIMIT or not self.peers:
            return
        key = (descriptor["node_id"], descriptor.get("published", 0))
        with self.lock:
            if key in self.forwarded:
                return
            self.forwarded.add(key)
        body = json.dumps({"descriptor": descriptor, "hop": hop + 1}).encode()
        for url in self.peers:
            threading.Thread(target=self._forward_one, args=(url, body), daemon=True).start()

    @staticmethod
    def _forward_one(url: str, body: bytes):
        try:
            req = urllib.request.Request(  # noqa: S310 (peers checked by mesh.beacon_url)
                url.rstrip("/") + "/gossip", data=body, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5):  # noqa: S310 (peers checked by mesh.beacon_url)
                pass
        except OSError:
            return  # an unreachable peer is skipped, never fatal


class Handler(BaseHTTPRequestHandler):
    """HTTP front end; every response is small and fixed-shape."""

    state: BeaconState = None  # set by serve()
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        """Log nothing per request (beacons are quiet by default)."""

    def _reply(self, code: int, doc: dict):
        body = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY_BYTES:
            return None
        return self.rfile.read(length)

    def handle_request(self, method: str, path: str, body: bytes, peer: str):
        """One beacon request, direct or opened from an oblivious one: (status, document)."""
        if method == "POST" and path == "/gossip":
            try:
                doc = json.loads(body)
                descriptor, hop = doc["descriptor"], int(doc.get("hop", 0))
            except Exception:
                return 400, {"ok": False}
            status = self.state.ingest(descriptor, max(0, hop))
            # Anti-amplification: one small fixed-shape ack for every outcome.
            return 200, {"ok": status == "stored"}
        if method == "GET" and path.startswith("/health"):
            return 200, {"ok": True, "descriptors": len(self.state.descriptors)}
        if method == "GET" and path.startswith("/descriptors"):
            if not self.state.admit_get(peer):
                return 200, {"ok": False, "descriptors": []}  # fixed shape
            try:
                q = path.split("limit=", 1)[1].split("&", 1)[0]
                limit = min(GET_MAX_LIMIT, max(1, int(q)))
            except (IndexError, ValueError):
                limit = GET_DEFAULT_LIMIT
            with self.state.lock:
                self.state.prune()
                batch = sorted(self.state.descriptors.values(), key=lambda d: -d.get("published", 0))[:limit]
            return 200, {"schema": mesh.SCHEMA, "descriptors": batch}
        return 404, {"ok": False}

    def do_POST(self):
        """Accept one gossiped descriptor (POST /gossip), or an oblivious request (POST /ohttp)."""
        body = self._body()
        if body is None:
            return self._reply(413, {"ok": False})
        if self.path == "/ohttp":
            return self._oblivious(body)
        self._reply(*self.handle_request("POST", self.path, body, self.client_address[0]))

    def do_GET(self):
        """Serve health, the descriptor set, or this gateway's public key."""
        if self.path.startswith("/ohttp-config") and self.state.gateway:
            g = self.state.gateway
            return self._reply(
                200, {"key_id": g.key_id, "public": base64.b64encode(self.state.gateway_public).decode()}
            )
        self._reply(*self.handle_request("GET", self.path, b"", self.client_address[0]))

    def _oblivious(self, wire: bytes):
        """Gateway: open a sealed request (it arrives from a relay, never the member),
        answer it as a direct one, and seal the answer to the member's reply key."""
        g = self.state.gateway
        if g is None:
            return self._reply(404, {"ok": False})
        try:
            method, path, body, reply = g.open(wire)
        except ohttp.Refused:
            return self._reply(400, {"ok": False})
        status, doc = self.handle_request(method, path, body, self.client_address[0])
        sealed = g.seal(reply, status, json.dumps(doc).encode())
        self.send_response(200)
        self.send_header("Content-Type", "message/ohttp-res")
        self.send_header("Content-Length", str(len(sealed)))
        self.end_headers()
        self.wfile.write(sealed)


def serve(
    state_dir: Path, host: str, port: int, peers: list[str], gateway_key: Path | None = None
) -> ThreadingHTTPServer:
    """A beacon server bound to host:port with its state directory; with `gateway_key`
    (created 0600 on first use) it also answers oblivious requests at /ohttp."""
    state = BeaconState(state_dir, peers)
    state.gateway = state.gateway_public = None
    if gateway_key is not None:
        if gateway_key.exists():
            private, public = ohttp.load_private(gateway_key.read_bytes())
        else:
            from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

            m, x = mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate()
            fd = os.open(gateway_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(ohttp.private_bytes(m, x))
            private, public = ohttp.load_private(gateway_key.read_bytes())
        state.gateway, state.gateway_public = ohttp.Gateway(private, 1), public
    server = ThreadingHTTPServer((host, port), Handler)
    Handler.state = state
    return server


def main() -> int:
    """Command-line entry point."""
    p = argparse.ArgumentParser(prog="avpn-mesh-beacon", description=__doc__.splitlines()[0])
    p.add_argument("--dir", type=Path, default=Path("/var/lib/avpn-mesh-beacon"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--peers", default="", help="comma-separated beacon base URLs to forward fresh descriptors to")
    p.add_argument(
        "--gateway-key", type=Path, help="answer oblivious requests at /ohttp with this key (created if missing)"
    )
    a = p.parse_args()
    peers = [u.strip() for u in a.peers.split(",") if u.strip()]
    server = serve(a.dir, a.host, a.port, peers, a.gateway_key)
    print(f"avpn-mesh-beacon on {a.host}:{a.port}, {len(peers)} peers", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

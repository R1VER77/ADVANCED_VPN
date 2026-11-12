#!/usr/bin/env python3
"""Oblivious relay for the mesh control plane (see tools/ohttp.py).

A member sends a sealed request here; the relay forwards the body, and nothing else, to
its one configured gateway (a beacon's /ohttp) and returns the sealed answer. It sees
the member's address and ciphertext; it never sends the member's address on (no
forwarded-for header) and never logs. Run it on a node of a different operator than the
gateway's beacon, or the split buys nothing.

usage: python3 tools/ohttp_relay.py --gateway https://BEACON:8787 [--host H] [--port P]
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time
import urllib.request

MAX_BODY = (1 << 20) + 8192
PER_MINUTE = 120


class Relay(BaseHTTPRequestHandler):
    """POST /relay: forward an opaque sealed request to the gateway."""

    gateway = ""
    budget: dict = {}
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        """Log nothing: the relay is the one party that sees members' addresses."""

    def _reply(self, code, body=b"", kind="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Forward one sealed request; answer with the sealed response."""
        if self.path != "/relay":
            return self._reply(404)
        now, ip = time.time(), self.client_address[0]
        stamps = [t for t in Relay.budget.get(ip, []) if now - t < 60]
        if len(stamps) >= PER_MINUTE:
            return self._reply(429)
        Relay.budget[ip] = stamps + [now]
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            return self._reply(413)
        body = self.rfile.read(length)
        # Only the body travels on; no header names the member.
        req = urllib.request.Request(  # noqa: S310 (fixed http(s) gateway from the command line)
            Relay.gateway + "/ohttp", data=body, headers={"Content-Type": "message/ohttp-req"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 (as above)
                answer = r.read(MAX_BODY)
        except OSError:
            return self._reply(502)
        self._reply(200, answer, "message/ohttp-res")


def serve(gateway, host, port):
    """A relay bound to host:port that forwards to `gateway`."""
    if not gateway.startswith(("https://", "http://")):
        raise ValueError("the gateway must be an http(s) URL")
    Relay.gateway = gateway.rstrip("/")
    return ThreadingHTTPServer((host, port), Relay)


def main():
    """Command-line entry point."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--gateway", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8788)
    a = p.parse_args()
    server = serve(a.gateway, a.host, a.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

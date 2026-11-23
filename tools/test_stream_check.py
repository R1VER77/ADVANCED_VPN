#!/usr/bin/env python3
"""Tests for `cypherpunk stream-check` (tools/stream_check.py).

Every classification is exercised against a real local HTTP server that
serves the services' actual marker copy (the Netflix proxy notice, the
iPlayer outside-UK gate, the Disney+/Max/YouTube TV geo notices, a 403
class refusal, and a clean content page) — real sockets, real fetches,
real parsing. No result is asserted without the wire having carried the
bytes that justify it. The live-internet test is skipped unless the
sandbox can reach the service (CI marks it opt-in for the same reason
the tool itself is honest: an unreachable probe is `unknown`, not a
pass).
"""

import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import stream_check as sc  # noqa: E402

NETFLIX_PROXY_NOTICE = (
    "<html><body><h1>Streaming error</h1>"
    "<p>You seem to be using an unblocker or proxy. Please turn off any of "
    "these services and try again.</p></body></html>"
)
IPLAYER_GEO_GATE = (
    "<html><body><p>It looks like you're outside the UK, so BBC iPlayer is "
    "not available in your area right now.</p></body></html>"
)
GEO_NOTICE = "<html><body><h1>Sorry about that</h1><p>This content is not available in your location.</p></body></html>"
CLEAN_CONTENT = {
    "netflix": (
        '<html><body><script>window.__data = {"currentCountry":"GB"};</script>'
        "<h1>Netflix</h1><p>Watch TV shows online</p></body></html>"
    ),
    "bbc-iplayer": "<html><body><h1>BBC iPlayer</h1><p>Most popular</p></body></html>",
    "disney-plus": "<html><body><h1>Disney+</h1><p>Start streaming</p></body></html>",
    "max": "<html><body><h1>Max</h1><p>Sign in</p></body></html>",
    "youtube-tv": "<html><body><h1>YouTube TV</h1><p>Live TV</p></body></html>",
    "dazn": "<html><body><h1>DAZN</h1><p>Home</p></body></html>",
}


class MockService(http.server.BaseHTTPRequestHandler):
    """Serves the response the exit's vantage point would receive.

    MOCK_STATE["scenario"] decides what every page returns:
      proxy-notice — the VPN-detection page (Netflix copy)
      geo-gate     — the geo notice (iPlayer copy)
      forbidden    — HTTP 403 with no marker copy
      clean        — the service's real content page"""

    def do_GET(self):  # noqa: N802 (http.server API)
        scenario = MOCK_STATE.get("scenario", "clean")
        service = MOCK_STATE.get("service", "netflix")
        if scenario == "proxy-notice":
            body, status = NETFLIX_PROXY_NOTICE.encode(), 200
        elif scenario == "geo-gate":
            body, status = IPLAYER_GEO_GATE.encode(), 200
        elif scenario == "forbidden":
            body, status = b"<html><body>Access denied</body></html>", 403
        else:
            body, status = CLEAN_CONTENT[service].encode(), 200
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


MOCK_STATE = {"scenario": "clean", "service": "netflix"}


class MockServer:
    def __init__(self, service, scenario="clean"):
        MOCK_STATE["service"] = service
        MOCK_STATE["scenario"] = scenario
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), MockService)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ClassificationTests(unittest.TestCase):
    """The classifier: marker precedence, status handling, region."""

    def test_blocked_marker_wins_over_eligible(self):
        pages = [("https://x/", 200, NETFLIX_PROXY_NOTICE)]
        verdict = sc.classify("netflix", pages)
        self.assertEqual(verdict["result"], "blocked")
        self.assertIn("you seem to be using an unblocker or proxy", verdict["markers_seen"])

    def test_403_without_markers_is_blocked(self):
        pages = [("https://x/", 403, "<html>Access denied</html>")]
        verdict = sc.classify("netflix", pages)
        self.assertEqual(verdict["result"], "blocked")
        self.assertIn("http-403", verdict["markers_seen"])

    def test_clean_page_is_eligible_with_region(self):
        pages = [("https://x/", 200, CLEAN_CONTENT["netflix"])]
        verdict = sc.classify("netflix", pages)
        self.assertEqual(verdict["result"], "eligible")
        self.assertEqual(verdict["region"], "GB")

    def test_iplayer_eligible_defaults_to_gb(self):
        pages = [("https://x/", 200, CLEAN_CONTENT["bbc-iplayer"])]
        verdict = sc.classify("bbc-iplayer", pages)
        self.assertEqual(verdict["result"], "eligible")
        self.assertEqual(verdict["region"], "GB")

    def test_unmatched_copy_is_unknown(self):
        pages = [("https://x/", 200, "<html><body>hello world</body></html>")]
        verdict = sc.classify("max", pages)
        self.assertEqual(verdict["result"], "unknown")

    def test_geo_gate_blocked_for_disney(self):
        pages = [("https://x/", 200, GEO_NOTICE)]
        verdict = sc.classify("disney-plus", pages)
        self.assertEqual(verdict["result"], "blocked")


class ProbeTests(unittest.TestCase):
    """The full probe over a real local HTTP server."""

    def test_netflix_blocked_over_the_wire(self):
        server = MockServer("netflix", scenario="proxy-notice")
        try:
            record = sc.run_probe("netflix", base_url=server.base)
            self.assertEqual(record["result"], "blocked")
            self.assertTrue(record["pages"] >= 1)
            self.assertEqual(record["schema"], 1)
        finally:
            server.close()

    def test_iplayer_geo_gate_over_the_wire(self):
        server = MockServer("bbc-iplayer", scenario="geo-gate")
        try:
            record = sc.run_probe("bbc-iplayer", base_url=server.base)
            self.assertEqual(record["result"], "blocked")
        finally:
            server.close()

    def test_403_class_refusal_over_the_wire(self):
        server = MockServer("max", scenario="forbidden")
        try:
            record = sc.run_probe("max", base_url=server.base)
            self.assertEqual(record["result"], "blocked")
            self.assertIn("http-403", record["markers_seen"])
        finally:
            server.close()

    def test_clean_service_eligible_over_the_wire(self):
        for service in ("disney-plus", "max", "youtube-tv", "dazn"):
            server = MockServer(service)
            try:
                record = sc.run_probe(service, base_url=server.base)
                self.assertEqual(record["result"], "eligible", service)
            finally:
                server.close()

    def test_unknown_service_rejected(self):
        with self.assertRaises(SystemExit):
            sc.run_probe("hulu")


class RecordTests(unittest.TestCase):
    """The evidence trail: dated history, descriptor merge."""

    def _record(self, result="eligible"):
        return {
            "schema": 1,
            "service": "netflix",
            "checked": "2026-11-21T12:00:00+00:00",
            "result": result,
            "region": "GB",
            "markers_seen": ["netflix"],
            "statuses": [200, 200],
            "pages": 2,
            "fetch_errors": [],
        }

    def test_history_is_kept_per_service_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            sc.save_record(self._record(), "exit-a", "cloak", evidence)
            sc.save_record(self._record("blocked"), "exit-a", "cloak", evidence)
            path = sc.record_path(evidence, "netflix", "exit-a")
            doc = json.loads(path.read_text())
            self.assertEqual(len(doc["history"]), 2)
            self.assertEqual(doc["history"][0]["result"], "eligible")
            self.assertEqual(doc["history"][1]["result"], "blocked")
            self.assertEqual(doc["history"][1]["transport_profile"], "cloak")

    def test_separate_exits_get_separate_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            sc.save_record(self._record(), "exit-a", "cloak", evidence)
            sc.save_record(self._record(), "exit-b", "cloak", evidence)
            self.assertTrue(sc.record_path(evidence, "netflix", "exit-a").exists())
            self.assertTrue(sc.record_path(evidence, "netflix", "exit-b").exists())

    def test_descriptor_merge_replaces_per_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            desc = Path(tmp) / "exit.json"
            desc.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "id": "exit-a",
                        "region": "uk",
                        "streaming": [
                            {"service": "netflix", "result": "eligible", "checked": "2026-11-01T00:00:00+00:00"},
                            {"service": "dazn", "result": "unknown", "checked": "2026-11-01T00:00:00+00:00"},
                        ],
                    }
                )
            )
            sc.descriptor_merge(desc, self._record("blocked"), "cloak")
            doc = json.loads(desc.read_text())
            services = {e["service"]: e for e in doc["streaming"]}
            self.assertEqual(services["netflix"]["result"], "blocked")
            self.assertEqual(services["netflix"]["transport_profile"], "cloak")
            self.assertEqual(services["netflix"]["checked"], "2026-11-21T12:00:00+00:00")
            self.assertEqual(services["dazn"]["result"], "unknown")

    def test_descriptor_merge_adds_first_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            desc = Path(tmp) / "exit.json"
            desc.write_text(json.dumps({"schema": 1, "id": "exit-a"}))
            streaming = sc.descriptor_merge(desc, self._record(), "i2p-front")
            self.assertEqual(len(streaming), 1)
            self.assertEqual(streaming[0]["transport_profile"], "i2p-front")


class CLITests(unittest.TestCase):
    def test_exit_codes_by_result(self):
        # MOCK_STATE is process-global, so the scenarios run in sequence.
        with tempfile.TemporaryDirectory() as tmp:
            blocked = MockServer("netflix", scenario="proxy-notice")
            try:
                rc_blocked = sc.main(
                    [
                        "netflix",
                        "--base-url",
                        blocked.base,
                        "--exit",
                        "cli-exit",
                        "--json",
                        "--evidence-dir",
                        tmp,
                    ]
                )
            finally:
                blocked.close()
            self.assertEqual(rc_blocked, 1)  # the proxy notice: blocked
            clean = MockServer("netflix", scenario="clean")
            try:
                rc_clean = sc.main(
                    [
                        "netflix",
                        "--base-url",
                        clean.base,
                        "--exit",
                        "cli-exit",
                        "--json",
                        "--evidence-dir",
                        tmp,
                    ]
                )
            finally:
                clean.close()
            self.assertEqual(rc_clean, 0)  # clean content: eligible

    def test_json_output_shape(self):
        import contextlib
        import io

        server = MockServer("dazn")
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = sc.main(
                    [
                        "dazn",
                        "--base-url",
                        server.base,
                        "--exit",
                        "cli-exit",
                        "--json",
                        "--evidence-dir",
                        tempfile.mkdtemp(),
                    ]
                )
            self.assertEqual(rc, 0)
            lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
            # The JSON record is the pretty-printed document; the final
            # "record: <path>" line follows it.
            json_text = "\n".join(ln for ln in lines if not ln.startswith("record:"))
            doc = json.loads(json_text)
            self.assertEqual(doc["service"], "dazn")
            self.assertEqual(doc["result"], "eligible")
        finally:
            server.close()


class LiveInternetTests(unittest.TestCase):
    """Opt-in live probe (network egress from this machine). Skipped in
    the sandbox unless CPVPN_STREAM_CHECK_LIVE=1: a live run from a data
    center address is evidence about THIS vantage point only."""

    def test_live_netflix_probe(self):
        if os.environ.get("CPVPN_STREAM_CHECK_LIVE") != "1":
            self.skipTest("live probe is opt-in (CPVPN_STREAM_CHECK_LIVE=1)")
        record = sc.run_probe("netflix")
        self.assertIn(record["result"], ("eligible", "blocked", "unknown"))
        self.assertTrue(record["pages"] >= 1)


if __name__ == "__main__":
    import os  # noqa: E402

    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Show which identifiers a controlled website observes across disposable browser profiles."""

from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
from threading import Thread


class Observer(BaseHTTPRequestHandler):
    """A loopback-only test destination with no third-party resources or logging."""

    def log_message(self, *_):
        """Suppress the HTTP server's request log."""

    def do_GET(self):  # noqa: N802 - HTTP handler method
        """Provision a cookie and collect a small browser-visible settings vector."""
        if self.path != "/":
            self.send_error(404)
            return
        cookies = SimpleCookie(self.headers.get("Cookie", ""))
        identity = cookies["lab"].value if "lab" in cookies else secrets.token_hex(16)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", f"lab={identity}; Max-Age=3600; Path=/; SameSite=Lax; HttpOnly")
        self.end_headers()
        page = f"""<pre id="result" data-id="{html.escape(identity, quote=True)}"></pre>
        <script>
          const element = document.querySelector('#result');
          element.textContent = JSON.stringify([element.dataset.id, navigator.userAgent,
            navigator.languages.join(','), navigator.platform, Intl.DateTimeFormat().resolvedOptions().timeZone]);
        </script>"""
        self.wfile.write(page.encode())


def visit(chrome, origin, profile):
    """Capture only the test document's output using a fresh Chrome process."""
    arguments = [
        chrome,
        "--headless",
        "--disable-background-networking",
        "--disable-component-update",
        "--no-first-run",
        f"--user-data-dir={profile}",
        "--dump-dom",
        origin,
    ]
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() == 0:
        if len(uid_map) != 3 or uid_map[1] == "0":
            raise RuntimeError("run the fixture unprivileged or in a private user namespace")
        arguments.insert(2, "--no-sandbox")
    result = subprocess.check_output(arguments, stderr=subprocess.DEVNULL, timeout=30, text=True)  # noqa: S603
    match = re.search(r'<pre id="result"[^>]*>(.*?)</pre>', result)
    if match is None:
        raise RuntimeError("browser did not run the test document")
    return json.loads(html.unescape(match[1]))


def main():
    """Write booleans only. Raw browser traits and cookies are discarded."""
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if chrome is None:
        raise RuntimeError("Chrome or Chromium is required by this fixture")
    with ThreadingHTTPServer(("127.0.0.1", 0), Observer) as server, tempfile.TemporaryDirectory() as directory:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}/"
            first = Path(directory) / "first"
            first_visit = visit(chrome, origin, first)
            next_visit = visit(chrome, origin, first)
            separate_visit = visit(chrome, origin, Path(directory) / "separate")
        finally:
            server.shutdown()
            thread.join()
    checks = dict(
        same_profile_cookie_matched=first_visit[0] == next_visit[0],
        separate_profile_cookie_differs=first_visit[0] != separate_visit[0],
        browser_settings_match_across_profiles=first_visit[1:] == separate_visit[1:],
    )
    print(json.dumps(checks))
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

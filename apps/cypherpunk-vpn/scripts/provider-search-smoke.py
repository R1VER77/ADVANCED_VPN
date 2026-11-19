#!/usr/bin/env python3
"""Browser UI with an explicit test transport and the real local search engine.

This is not native D-Bus/Polkit or live-provider qualification. It never installs
a controller, prompts for hardware or invokes an action. Serve only built assets
and the bounded fixture on loopback, and destroy the browser profile on exit.
"""

import argparse
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import search_providers  # noqa: E402


def main():
    """Exercise pagination, selection and narrow layout without write authority."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--geckodriver", type=Path, default=Path.home() / ".local/bin/geckodriver")
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    calls = []
    index = search_providers.shipped_index()

    class Fixture(SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Never record query text or server request logs.

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if self.path != "/__controller_fixture__" or not 0 < size <= 2048:
                    raise ValueError("invalid fixture request")
                request = json.loads(self.rfile.read(size))
                command, value = request["command"], request["args"]
                calls.append(command)
                if command == "get_snapshot":
                    result = dict(schema=1, observed_at=time.time(), scope="none", enrolled=False,
                                  state="not_enrolled", protection="unknown", chain=[], kill_switch="unknown")
                elif command == "get_setup":
                    result = dict(schema=1, branch="create", complete=0, total=0, current=None,
                                  finished=False, steps=[])
                elif command == "provider_search":
                    result = search_providers.search(index, value)
                else:
                    raise ValueError("this fixture has no write methods")
                payload = json.dumps(result).encode()
                self.send_response(200)
            except Exception:
                payload = b'{"error":"fixture_refused"}'
                self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Fixture, directory=ROOT / "apps/cypherpunk-vpn/dist"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    options = webdriver.FirefoxOptions()
    options.add_argument("-headless")
    options.set_preference("network.captive-portal-service.enabled", False)
    options.set_preference("network.prefetch-next", False)
    driver = None
    checks = []
    try:
        driver = webdriver.Firefox(options=options, service=Service(str(args.geckodriver)))
        wait = WebDriverWait(driver, 12)
        driver.set_window_size(960, 766)
        driver.get(f"http://127.0.0.1:{server.server_port}")
        driver.execute_script("""window.__TAURI_INTERNALS__ = {invoke: async (command, args={}) => {
          const r=await fetch('/__controller_fixture__', {method:'POST',
            headers:{'Content-Type':'application/json'}, body:JSON.stringify({command,args})});
          if(!r.ok) throw new Error('explicit_test_fixture_refused'); return await r.text();
        }}""")
        driver.find_element(By.CSS_SELECTOR, "button.refresh").click()
        button = wait.until(lambda d: next((b for b in d.find_elements(By.TAG_NAME, "button") if b.text == "Create my network"), None))
        button.click()
        wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, ".provider-search li")) == 50)
        checks.append("real index renders a bounded first page")
        first = driver.find_element(By.CSS_SELECTOR, ".provider-search li strong").text
        driver.find_element(By.XPATH, "//button[text()='Next results']").click()
        wait.until(lambda d: d.find_element(By.CSS_SELECTOR, ".provider-search li strong").text != first)
        checks.append("opaque cursor advances the actual provider index")
        field = driver.find_element(By.ID, "provider-query")
        field.send_keys("hetznercloud/hcloud")
        driver.find_element(By.CSS_SELECTOR, ".provider-search button[type=submit]").click()
        wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, ".provider-search li")) == 1)
        driver.find_element(By.CSS_SELECTOR, ".provider-search li button").click()
        text = driver.find_element(By.CSS_SELECTOR, ".provider-search").text
        assert "Guided setup under review" in text and "No server has been created" in text
        checks.append("candidate selection remains discovery-only")
        driver.save_screenshot(str(args.out / "provider-desktop.png"))
        driver.set_window_size(420, 640)
        viewport = driver.execute_script("return innerWidth")
        # Firefox can impose a 500px minimum outer window. Record the measured
        # CSS viewport instead of claiming the requested 420px was achieved.
        assert viewport <= 500
        assert driver.execute_script("return document.documentElement.scrollWidth <= innerWidth + 1")
        driver.execute_script("document.querySelector('.provider-search .selected').scrollIntoView({block:'end'})")
        driver.save_screenshot(str(args.out / "provider-narrow.png"))
        checks.append(f"narrow layout has no horizontal overflow at measured {viewport} CSS pixels")
        assert set(calls) == {"get_snapshot", "get_setup", "provider_search"}
        checks.append("fixture observed only three read methods and no action requests")
        result = dict(schema=1, status="passed", scope="browser_with_explicit_test_transport_and_actual_search_module",
                      native_bus_qualified=False, provisioning_qualified=False, checks=checks,
                      narrow_viewport_css_pixels=viewport,
                      index_sha256=index["index_sha256"], browser=driver.capabilities["browserVersion"],
                      script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        (args.out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
    finally:
        if driver is not None:
            driver.quit()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()

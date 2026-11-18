#!/usr/bin/env python3
"""Record how the map animates when the route changes while connected: for each route,
frames from the change through the rebuild to "Connected". Writes PNG frames to --out.
Needs the dev server on localhost:5173 (the app opens connected: ?start=connected).

usage: python scripts/routes.py --out frames/ [--dark]
"""

import argparse
import time
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import Select

ROUTES = {
    "1-singapore": ["sin"],
    "2-stockholm-frankfurt": ["sto", "fra"],
    "3-reykjavik-newyork-saopaulo": ["rek", "nyc", "sao"],
    "4-sydney-tokyo-losangeles-toronto": ["syd", "tyo", "lax", "tor"],
    "3-london-mumbai-johannesburg": ["lon", "bom", "jnb"],
}

p = argparse.ArgumentParser()
p.add_argument("--out", type=Path, required=True)
p.add_argument("--dark", action="store_true")
p.add_argument("--url", default="http://localhost:5173")
p.add_argument("--geckodriver", default=str(Path.home() / "vm/advanced-vpn/wf-real/tools/geckodriver"))
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=True)

o = webdriver.FirefoxOptions()
o.add_argument("-headless")
o.set_preference("ui.systemUsesDarkTheme", 1 if a.dark else 0)
d = webdriver.Firefox(options=o, service=Service(a.geckodriver))
d.set_window_size(960, 766)
d.get(a.url.rstrip("/") + "/?start=connected")
time.sleep(2)


def panel(open_it):
    is_open = bool(d.find_elements(By.CSS_SELECTOR, ".demo .body"))
    if is_open != open_it:
        d.find_element(By.CSS_SELECTOR, ".demo .head").click()
        time.sleep(0.2)


def set_route(ids):
    panel(True)
    for b in d.find_elements(By.CSS_SELECTOR, ".route .hops button"):
        if b.text.startswith(str(len(ids)) + " "):
            b.click()
    time.sleep(0.2)
    for i, sel in enumerate(d.find_elements(By.CSS_SELECTOR, ".hop select")):
        Select(sel).select_by_value(ids[i])
        time.sleep(0.05)
    panel(False)


frame = 0
for name, ids in ROUTES.items():
    set_route(ids)
    t0 = time.time()
    k = 0
    while time.time() - t0 < 5.2:  # through the rebuild to "Connected"
        d.save_screenshot(str(a.out / ("%04d-%s.png" % (frame, name))))
        frame += 1
        k += 1
        time.sleep(max(0.0, t0 + k * 0.15 - time.time()))  # one frame every 0.15 s
    title = d.find_element(By.TAG_NAME, "h1").text
    rows = [e.text for e in d.find_elements(By.CSS_SELECTOR, ".server .where")]
    print(name, "->", title, "|", " / ".join(r.replace("\n", " ") for r in rows))
d.quit()

#!/usr/bin/env python3
"""Drive the prototype in headless Firefox through every scenario of the brief and print
what a user would read at each step. Needs the dev server on localhost:5173.

usage: python scripts/walkthrough.py [--geckodriver PATH] [--shots DIR]
"""

import argparse
import json
import time
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service

p = argparse.ArgumentParser()
p.add_argument("--url", default="http://localhost:5173")
p.add_argument("--geckodriver", default=str(Path.home() / "vm/cypherpunk-vpn/wf-real/tools/geckodriver"))
p.add_argument("--shots", type=Path)
a = p.parse_args()

opts = webdriver.FirefoxOptions()
opts.add_argument("-headless")
d = webdriver.Firefox(options=opts, service=Service(a.geckodriver))
d.set_window_size(960, 766)  # an 800x600 page plus the window frame
d.get(a.url)
time.sleep(1)


def button(text):
    for b in d.find_elements(By.TAG_NAME, "button"):
        if text in b.text:
            return b
    raise LookupError(text)


def click(text, wait=0.9):
    button(text).click()
    time.sleep(wait)


def demo(text):
    if not d.find_elements(By.CSS_SELECTOR, ".demo .body"):
        d.find_element(By.CSS_SELECTOR, ".demo .head").click()
        time.sleep(0.3)
    click(text, 0.9)


def read():
    h1 = d.find_element(By.TAG_NAME, "h1").text
    notice = [e.text for e in d.find_elements(By.CSS_SELECTOR, ".notice strong")]
    line = [e.text for e in d.find_elements(By.CSS_SELECTOR, ".line, .body p")][:1]
    return {"title": h1, "notice": notice[0] if notice else None, "says": line[0] if line else None}


shot_n = [0]


def shot(name):
    if d.find_elements(By.CSS_SELECTOR, ".demo .body"):
        d.find_element(By.CSS_SELECTOR, ".demo .head").click()  # fold the demo panel
    time.sleep(1.0)  # let the map finish moving
    if a.shots:
        a.shots.mkdir(parents=True, exist_ok=True)
        shot_n[0] += 1
        d.save_screenshot(str(a.shots / ("%02d-%s.png" % (shot_n[0], name))))


log = {}
shot("first-use")
log["first use"] = read()
for f in ["laptop-corrupt.cpvpn", "laptop-other-operator.cpvpn", "laptop-expired.cpvpn"]:
    demo("First use")
    click("Add device file")
    click(f, 1.6)
    log["enrol " + f] = read()
    shot("enrol-" + f.split(".")[0])
demo("First use")
click("Add device file")
shot("choose-file")
click("laptop.cpvpn", 1.6)
log["enrol laptop.cpvpn"] = read()
shot("enrolled")
click("Connect now", 0.6)
shot("pin-dialog")
d.find_element(By.CSS_SELECTOR, "input[type=password]").send_keys("123456")
click("OK", 1.6)
log["connecting"] = read()
shot("connecting")
time.sleep(3.5)
log["connected"] = read()
shot("connected")
demo("Lose network")
log["network lost"] = read()
shot("network-lost")
demo("Restore network")
time.sleep(4)
log["network restored"] = read()
demo("Server fails its proof")
log["server proof failed"] = read()
shot("server-proof-failed")
click("How to fix this", 0.6)
log["how to fix"] = d.find_element(By.CSS_SELECTOR, ".sheet h2").text
shot("how-to-fix")
click("Close", 0.4)
demo("Service stops")
log["service stopped"] = read()
log["switch disabled while unknown"] = not d.find_element(By.CSS_SELECTOR, "[role=switch]").is_enabled()
shot("service-stopped")
click("Start the service", 2)
log["service started"] = read()
demo("wrong")
d.find_element(By.CSS_SELECTOR, "[role=switch]").click()
time.sleep(0.6)
d.find_element(By.CSS_SELECTOR, "input[type=password]").send_keys("0000")
click("OK", 1.8)
log["wrong PIN"] = read()
shot("wrong-pin")
d.quit()
expected = {
    "enrol laptop.cpvpn": "Device added",
    "connecting": "Connecting…",
    "connected": "Connected",
    "network lost": "Reconnecting…",
    "network restored": "Connected",
    "server proof failed": "Not connected",
    "service stopped": "Status unknown",
    "service started": "Disconnected",
    "wrong PIN": "Not connected",
}
for name, title in expected.items():
    assert log[name]["title"] == title, (name, log[name])
assert log["switch disabled while unknown"]
assert "valid CYPHERPUNK" in log["enrol laptop-corrupt.cpvpn"]["title"]
assert "different operator" in log["enrol laptop-other-operator.cpvpn"]["title"]
assert "expired" in log["enrol laptop-expired.cpvpn"]["title"]
print(json.dumps(log, indent=1))

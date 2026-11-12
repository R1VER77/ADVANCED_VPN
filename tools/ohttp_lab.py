#!/usr/bin/env python3
"""Oblivious control-plane lab: who sees what, on real interfaces in network namespaces.

    member 10.81.0.2 -- 10.81.0.1 relay 10.82.0.1 -- 10.82.0.2 beacon (gateway)

The member has no route to the beacon at all: it can only reach it through the relay.
The member publishes a request carrying a marker and fetches descriptors, through the
relay, sealed to the beacon's gateway key. Raw observers record every source address
that reaches the beacon and every byte that crosses the relay.

Passes when: the member gets authentic answers; the beacon never sees the member's
address (only the relay's); the marker never appears on the relay's links; a forged
request is refused.

usage: unshare --user --map-root-user --map-auto --net --mount python3 tools/ohttp_lab.py
       --state DIR [--json OUT]
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import throughput_bench as tb  # noqa: E402
from avpnctl import lab_guard  # noqa: E402

MARKER = "MARKER-OHTTP-5e1c"
MEMBER = "10.81.0.2"
# Every byte on the relay's interfaces, and every source address at the beacon.
SNIFF = r"""
import json,signal,socket,sys
out,marker=sys.argv[1],sys.argv[2].encode()
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.settimeout(.2)
seen=set();hit=False
def dump(*_):
    open(out,'w').write(json.dumps(dict(sources=sorted(seen),marker_seen=hit)));sys.exit(0)
signal.signal(signal.SIGTERM,dump)
while True:
    try:b=s.recv(65536)
    except socket.timeout:continue
    if len(b)>=34 and b[12:14]==b'\x08\x00':
        seen.add(socket.inet_ntoa(b[26:30]))
    if marker in b:hit=True
"""
MEMBER_SCRIPT = r"""
import json,sys,urllib.request
sys.path.insert(0,sys.argv[1])
import mesh
cfg=json.loads(sys.argv[2])
entry=mesh.beacon_entry(cfg)
out={}
status,doc=mesh.beacon_call(entry,"POST","/gossip",json.dumps({"descriptor":{"note":sys.argv[3]},"hop":0}).encode())
out["gossip"]=[status,doc]
status,doc=mesh.beacon_call(entry,"GET","/descriptors")
out["descriptors"]=[status,len(doc.get("descriptors",[]))]
status,doc=mesh.beacon_call(entry,"GET","/health")
out["health"]=[status,doc]
req=urllib.request.Request(cfg["relay"]+"/relay",data=b"\x01"*600)
try:
    urllib.request.urlopen(req,timeout=10);out["forged"]="accepted"
except urllib.error.HTTPError as e:
    out["forged"]=e.code
try:
    urllib.request.urlopen("http://10.82.0.2:8787/health",timeout=3);out["direct_to_beacon"]="reachable"
except OSError:
    out["direct_to_beacon"]="unreachable"
print(json.dumps(out))
"""


def main():
    """Build the namespaces, run the member's requests, check who saw what."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--json", type=Path)
    a = p.parse_args()
    os.umask(0o077)
    lab_guard()
    state = a.state.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    tb.run("mount", "--make-rprivate", "/")
    tb.run("mount", "-t", "tmpfs", "-o", "size=16m", "tmpfs", "/run")
    nodes = ["member", "relay", "beacon"]
    procs = []

    def spawn(ns, args, name):
        f = (state / (name + ".log")).open("a")
        fd = os.open("/run/netns/av-" + ns, os.O_RDONLY)
        try:
            x = subprocess.Popen(
                list(map(str, args)), preexec_fn=lambda: os.setns(fd, 0), stdout=f, stderr=subprocess.STDOUT
            )
        finally:
            os.close(fd)
        procs.append(x)
        return x

    try:
        for n in nodes:
            tb.run("ip", "netns", "add", "av-" + n)
            tb.run("ip", "-n", "av-" + n, "link", "set", "lo", "up")
        for (n1, ip1, n2, ip2), dev in [
            (("member", "10.81.0.2/30", "relay", "10.81.0.1/30"), "o0"),
            (("relay", "10.82.0.1/30", "beacon", "10.82.0.2/30"), "o1"),
        ]:
            tb.run("ip", "link", "add", dev + "a", "type", "veth", "peer", "name", dev + "b")
            for ns, d, ip in [(n1, dev + "a", ip1), (n2, dev + "b", ip2)]:
                tb.run("ip", "link", "set", d, "netns", "av-" + ns)
                tb.run("ip", "-n", "av-" + ns, "address", "add", ip, "dev", d)
                tb.run("ip", "-n", "av-" + ns, "link", "set", d, "up")
        sniff_relay = spawn("relay", [sys.executable, "-c", SNIFF, state / "relay.json", MARKER], "sniff-relay")
        sniff_beacon = spawn("beacon", [sys.executable, "-c", SNIFF, state / "beacon.json", MARKER], "sniff-beacon")
        spawn("beacon", [sys.executable, ROOT / "tools/mesh_beacon.py", "--dir", state / "beacon-state", "--host",
                         "10.82.0.2", "--port", "8787", "--gateway-key", state / "gateway.key"], "beacon")  # fmt: skip
        spawn("relay", [sys.executable, ROOT / "tools/ohttp_relay.py", "--gateway", "http://10.82.0.2:8787",
                        "--host", "10.81.0.1", "--port", "8788"], "relay")  # fmt: skip
        time.sleep(2)
        # The member learns the gateway key out of band (here: the operator reads it).
        cfg_raw = tb.run("ip", "netns", "exec", "av-beacon", "curl", "-s", "http://10.82.0.2:8787/ohttp-config",
                         timeout=10).stdout  # fmt: skip
        gw = json.loads(cfg_raw)
        route = dict(relay="http://10.81.0.1:8788", gateway_public=gw["public"], key_id=gw["key_id"],
                     relay_operator="!aaaaaaaa", gateway_operator="!bbbbbbbb")  # fmt: skip
        out = tb.run("ip", "netns", "exec", "av-member", sys.executable, "-c", MEMBER_SCRIPT, ROOT / "tools",
                     json.dumps(route), MARKER, timeout=60).stdout  # fmt: skip
        member = json.loads(out.strip().splitlines()[-1])
        time.sleep(0.5)
        for s in (sniff_relay, sniff_beacon):
            s.send_signal(15)
            s.wait(timeout=5)
        relay_view = json.loads((state / "relay.json").read_text())
        beacon_view = json.loads((state / "beacon.json").read_text())
        result = dict(
            member=member,
            beacon_sources=beacon_view["sources"],
            member_address_seen_by_beacon=MEMBER in beacon_view["sources"],
            marker_seen_on_relay_links=relay_view["marker_seen"],
            relay_sources=relay_view["sources"],
        )
        print(json.dumps(result, indent=1))
        if a.json:
            a.json.write_text(json.dumps(result, indent=1) + "\n")
        problems = []
        if MEMBER in beacon_view["sources"]:
            problems.append("the beacon saw the member's address")
        if relay_view["marker_seen"]:
            problems.append("the relay saw the request in the clear")
        if member["health"][0] != 200 or member["descriptors"][0] != 200 or member["gossip"][0] != 200:
            problems.append("the member did not get answers")
        if member["forged"] == "accepted":
            problems.append("a forged request was accepted")
        if member["direct_to_beacon"] != "unreachable":
            problems.append("the lab let the member reach the beacon directly")
        if problems:
            raise SystemExit("; ".join(problems))
    finally:
        for proc in reversed(procs):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for n in reversed(nodes):
            tb.run("ip", "netns", "del", "av-" + n, check=False)


if __name__ == "__main__":
    main()

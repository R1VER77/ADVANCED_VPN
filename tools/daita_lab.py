#!/usr/bin/env python3
"""DAITA lab: capture a padded 2-hop chain while it loads synthetic web pages.

Builds the namespace chain of throughput_bench.py (client, relay, exit, destination),
optionally with netem delay on every link, and loads N synthetic sites K times each in
shuffled order. Every page is a main document plus objects of varied number and size,
fetched over two parallel TCP connections; each load varies sizes by +-15% and skips
about 10% of objects. Writes to --out:
  client_link.pcap  client <-> relay: the WireGuard + DAITA carrier the client's ISP sees
  inner_link.pcap   relay <-> exit: inner QUIC, constant cells, no DAITA
  phases.json       epoch start/end of the idle phase and of every page load
  timeline.json     both carriers' DAITA counters every 0.5 s
Score it with tools/wf_attack.py. Captures are kernel-timestamped nanosecond pcaps.

usage: unshare --user --map-root-user --map-auto --net --mount python3 tools/daita_lab.py
       --state DIR --out DIR [--rate metered|standard|fast|line] [--sites 8] [--loads 15]
       [--delay-ms 10] [--gap 5] [--idle 30] [--bin-dir target/release]
Needs ethtool/tc/ip and a release build. Not run in CI.
"""

import argparse
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import throughput_bench as tb  # noqa: E402
from avpnctl import identity_of, lab_guard, runtime_dir  # noqa: E402
from managed_profile import lab_setup, RATE_CLASSES  # noqa: E402

# Raw capture with kernel timestamps, written as nanosecond pcap (both directions).
# Headers only (96 bytes, original length kept): the attack uses sizes and timing, and
# the faster rate classes would otherwise write tens of GB per run.
CAPTURE = r"""
import signal, socket, struct, sys
dev, out = sys.argv[1], sys.argv[2]
SO_TIMESTAMPNS = 35
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 25)
s.bind((dev, 0))
f = open(out, "wb")
f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 96, 1))
def stop(*_):
    f.flush(); f.close(); sys.exit(0)
signal.signal(signal.SIGTERM, stop)
while True:
    data, anc, _, _ = s.recvmsg(65535, 64)
    sec = nsec = 0
    for level, kind, val in anc:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            sec, nsec = struct.unpack("qq", val[:16])
    f.write(struct.pack("<IIII", sec, nsec, min(len(data), 96), len(data)) + data[:96])
"""
# Web server stand-in: each 300-byte request names an object size; it replies with that many bytes.
SITES_SERVER = r"""
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(8)
blob = b"\xa5" * 1048576
def serve(c):
    while True:
        req = b""
        while len(req) < 300:
            part = c.recv(300 - len(req))
            if not part: c.close(); return
            req += part
        n = int(req[:12])
        while n:
            k = min(n, len(blob)); c.sendall(blob[:k]); n -= k
while True:
    c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
"""
# Page load: objects split over two parallel connections, as a browser would.
LOAD = r"""
import json, socket, sys, threading, time
sizes = json.loads(sys.argv[1])
def fetch(part):
    s = socket.create_connection(("203.0.113.2", 5303), 10); s.settimeout(300)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    for n in part:
        s.sendall(str(n).encode().ljust(12) + b"r" * 288)
        got = 0
        while got < n:
            got += len(s.recv(65536))
    s.close()
t = time.time()
ts = [threading.Thread(target=fetch, args=(sizes[i::2],)) for i in range(2)]
[x.start() for x in ts]; [x.join() for x in ts]
print(json.dumps(dict(start=t, end=time.time(), bytes=sum(sizes))))
"""


def sites(n, seed=20261109):
    """N synthetic page structures: a main document, then 3-28 objects of log-normal size."""
    r = random.Random(seed)  # noqa: S311 (lab workload, not security)
    out = {}
    for i in range(n):
        objs = [r.randint(15000, 90000)] + [int(r.lognormvariate(9.0, 1.1)) + 300 for _ in range(r.randint(3, 28))]
        out["S%d" % i] = objs
    return out


def instance(objs, r):
    """One load of a page: sizes vary +-15% and about 10% of objects are skipped (cached, ads)."""
    first = [int(objs[0] * r.uniform(0.85, 1.15))]
    return first + [int(o * r.uniform(0.85, 1.15)) for o in objs[1:] if r.random() > 0.1]


def main():
    """Build the chain, run the idle phase and every page load, and save the captures."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--rate", choices=list(RATE_CLASSES), default="metered")
    p.add_argument("--sites", type=int, default=8)
    p.add_argument("--loads", type=int, default=15)
    p.add_argument("--idle", type=float, default=30.0)
    p.add_argument("--gap", type=float, default=5.0, help="seconds between page loads")
    p.add_argument("--delay-ms", type=float, default=10.0, help="one-way delay at each link end")
    p.add_argument("--bin-dir", type=Path, default=ROOT / "target/release")
    a = p.parse_args()
    os.umask(0o077)
    lab_guard()
    state = a.state.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    a.out.mkdir(parents=True, exist_ok=True)
    nodes, links = tb.topology(2)
    ep = tb.endpoints(2, 2)
    lab_setup(state, ep["relay"], ep["exit"], destinations=["203.0.113.0/30"], rate=a.rate, hops=2,
              middle=None, dns=dict(upstream="203.0.113.2:8530", server_name="dns.lab.internal"))  # fmt: skip
    tb.run("mount", "--make-rprivate", "/")
    tb.run("mount", "-t", "tmpfs", "-o", "size=64m", "tmpfs", "/run")
    target = Path("/etc/resolv.conf").resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text("")
    namespaces = ["av-" + n for n in nodes]
    procs, captures = [], []

    def spawn(ns, args, name):
        f = (state / (name + ".log")).open("a")
        fd = os.open("/run/netns/" + ns, os.O_RDONLY)
        try:
            x = subprocess.Popen(
                list(map(str, args)), preexec_fn=lambda: os.setns(fd, 0), stdout=f, stderr=subprocess.STDOUT
            )
        finally:
            os.close(fd)
        procs.append(x)
        return x

    def manager(role):
        return spawn("av-" + role, [sys.executable, ROOT / "tools/avpnctl.py", "--state", state / role,
                                    "--bin-dir", a.bin_dir, "--lab", "connect"], role)  # fmt: skip

    def app(argv, check=True):
        return tb.run("ip", "netns", "exec", "av-client", sys.executable, ROOT / "tools/avpnctl.py", "--state",
                      state / "client", "--lab", "run", "--", *argv, check=check, timeout=900)  # fmt: skip

    def counters():
        out = {}
        for role in ("client", "relay"):
            f = runtime_dir(state / role) / "carrier-status.json"
            out[role] = json.loads(f.read_text()) if f.exists() else None
        return out

    phases, timeline, sampling = [], [], threading.Event()

    def sampler():
        while not sampling.is_set():
            try:
                timeline.append(dict(t=time.time(), **counters()))
            except (OSError, ValueError):
                pass
            sampling.wait(0.5)

    try:
        for ns in namespaces:
            tb.run("ip", "netns", "add", ns)
            tb.run("ip", "-n", ns, "link", "set", "lo", "up")
        devs = {}
        for k, (n1, ip1, n2, ip2) in enumerate(links):
            d1, d2 = "l%da" % k, "l%db" % k
            tb.run("ip", "link", "add", d1, "type", "veth", "peer", "name", d2)
            for ns, dev, addr in [("av-" + n1, d1, ip1), ("av-" + n2, d2, ip2)]:
                tb.run("ip", "link", "set", dev, "netns", ns)
                tb.run("ip", "-n", ns, "address", "add", addr, "dev", dev)
                tb.run("ip", "-n", ns, "link", "set", dev, "up")
                # No offload merging: capture packets as sent (GSO is split by wf_attack.py if left on).
                tb.run("ip", "netns", "exec", ns, "/usr/sbin/ethtool", "-K", dev, "gro", "off", "gso", "off",
                       "tso", "off", check=False)  # fmt: skip
                if a.delay_ms:
                    tb.run("ip", "netns", "exec", ns, "/usr/sbin/tc", "qdisc", "add", "dev", dev, "root", "netem",
                           "delay", "%gms" % a.delay_ms, "limit", "100000")  # fmt: skip
            devs[(n1, n2)] = (d1, d2)
        for node, net, via in tb.routes(nodes, links):
            tb.run("ip", "-n", "av-" + node, "route", "add", net, "via", via)
        for ns in namespaces[1:-1]:
            tb.run("ip", "netns", "exec", ns, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        spawn("av-destination", [sys.executable, "-c", SITES_SERVER, "203.0.113.2", 5303], "sites")
        client_dev, inner_dev = devs[("client", "relay")][0], devs[("relay", "exit")][0]
        captures.append(
            spawn("av-client", [sys.executable, "-c", CAPTURE, client_dev, state / "client_link.pcap"], "cap-client")
        )
        captures.append(
            spawn("av-relay", [sys.executable, "-c", CAPTURE, inner_dev, state / "inner_link.pcap"], "cap-inner")
        )
        time.sleep(1)
        for role in ["exit", "relay"]:
            manager(role)
        client = manager("client")
        threading.Thread(target=sampler, daemon=True).start()
        end = time.monotonic() + 120
        while time.monotonic() < end:
            if client.poll() is not None:
                raise RuntimeError("client supervisor exited")
            if app(["ping", "-n", "-c", "1", "-W", "1", "10.77.0.1"], check=False).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("tunnel did not come up")
        time.sleep(5)
        t0 = time.time()
        time.sleep(a.idle)
        phases.append(dict(name="idle", start=t0, end=time.time()))
        r = random.Random(7)  # noqa: S311 (lab workload, not security)
        pages = sites(a.sites)
        order = [(site, k) for site in pages for k in range(a.loads)]
        r.shuffle(order)
        for n, (site, k) in enumerate(order):
            sizes = instance(pages[site], r)
            t0 = time.time()
            res = json.loads(app([sys.executable, "-c", LOAD, json.dumps(sizes)]).stdout.strip().splitlines()[-1])
            time.sleep(a.gap)
            phases.append(dict(name="load-%s-%d" % (site, k), start=t0, end=time.time(), site=site,
                               load_start=res["start"], load_end=res["end"], bytes=res["bytes"]))  # fmt: skip
            if n % 20 == 0:
                print("load %d/%d" % (n + 1, len(order)), flush=True)
    finally:
        sampling.set()
        for c in captures:
            if c.poll() is None:
                c.send_signal(signal.SIGTERM)
                try:
                    c.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    c.kill()
        for role in ["client", "relay", "exit"]:
            path = runtime_dir(state / role) / "status.json"
            if path.exists():
                for child in json.loads(path.read_text()).get("children", {}).values():
                    try:
                        if identity_of(child["pid"]) == child["identity"]:
                            os.kill(child["pid"], signal.SIGTERM)
                    except ProcessLookupError:
                        pass
        for proc in reversed(procs):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for ns in reversed(namespaces):
            tb.run("ip", "netns", "del", ns, check=False)
        for name in ("client_link.pcap", "inner_link.pcap"):
            if (state / name).exists():
                (a.out / name).write_bytes((state / name).read_bytes())
        (a.out / "phases.json").write_text(json.dumps(dict(rate=a.rate, phases=phases), indent=1))
        (a.out / "timeline.json").write_text(json.dumps(timeline))
        for f in a.out.iterdir():
            f.chmod(0o644)


if __name__ == "__main__":
    main()

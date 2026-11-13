#!/usr/bin/env python3
"""Website fingerprinting on real browser traces: collection.

A real headless Firefox loads live websites through a tunnel built in network
namespaces, while a capture on the client's own link records what its ISP would see:
the time, direction and size of every packet (never contents). Configurations:

  undefended   kernel WireGuard client -> exit, no shaping (the attacks must win here)
  metered|standard|fast|line   the real ADVANCED_VPN 2-hop chain at that rate class
                               (request -> init -> enroll, constant-rate carrier, cloak)

Each worker is its own user, network and mount namespace with its own chain; pasta gives
the worker live internet. Loads are spread over workers. Output per worker: packets.bin
(time and signed IP length of every packet on the captured link, offload off so sizes
are wire sizes) and loads.jsonl (site, label, window, outcome).

usage: python3 tools/wf_real.py collect --config fast --sites SITES.json --out DIR
           --pasta PASTA --geckodriver GECKODRIVER --python VENV_PYTHON [--workers 4]
SITES.json: {"monitored": [...], "loads": 30, "open_world": [...]} (domains). Not CI.
"""

import argparse
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

WINDOW = 12.0  # seconds of trace kept per load, from its start (the same for every config)
SNIFF = r"""
import socket,struct,sys,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((sys.argv[1],0))
out=open(sys.argv[2],'ab',buffering=0);rec=struct.Struct('<di')
while True:
    b,a=s.recvfrom(65535);t=time.time()
    if len(b)<34 or b[12:14]!=b'\x08\x00':continue
    n=struct.unpack('!H',b[16:18])[0]
    out.write(rec.pack(t, n if a[2]==socket.PACKET_OUTGOING else -n))
"""
BROWSE = r"""
import json,sys,tempfile,time
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
PREFS={"browser.cache.disk.enable":False,"browser.cache.memory.enable":False,"network.http.http3.enable":False,
"network.trr.mode":5,"datareporting.healthreport.uploadEnabled":False,"toolkit.telemetry.enabled":False,
"browser.safebrowsing.malware.enabled":False,"browser.safebrowsing.phishing.enabled":False,
"browser.safebrowsing.downloads.enabled":False,"network.captive-portal-service.enabled":False,
"network.connectivity-service.enabled":False,"app.normandy.enabled":False,"extensions.update.enabled":False,
"app.update.auto":False,"browser.newtabpage.enabled":False,"network.prefetch-next":False,
"network.dns.disablePrefetch":True,"network.http.speculative-parallel-limit":0,"browser.ping-centre.telemetry":False,
"services.settings.server":"http://127.0.0.1:1/","security.OCSP.enabled":0,"dom.push.enabled":False}
gecko,site,out=sys.argv[1],sys.argv[2],sys.argv[3]
o=Options();o.add_argument("-headless")
for k,v in PREFS.items():o.set_preference(k,v)
o.add_argument("-profile");o.add_argument(tempfile.mkdtemp())
d=webdriver.Firefox(options=o,service=Service(gecko));d.set_page_load_timeout(30)
time.sleep(3)  # let the browser's own start-up settle before the window opens
t=time.time();status="ok"
try:d.get("https://"+site+"/")
except Exception as e:status=type(e).__name__
loaded=time.time();time.sleep(max(0,t+%(window)s-time.time()))
try:d.quit()
except Exception:pass
print(json.dumps(dict(start=t,loaded=loaded,end=t+%(window)s,status=status)))
""" % {"window": WINDOW}


def sh(*args, check=True, timeout=60, **k):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, check=check, timeout=timeout, **k)


def nsexec(ns, *args, **k):
    return sh("/usr/sbin/ip", "netns", "exec", ns, *args, **k)


def in_netns(ns, args, **k):
    """Start `args` in network namespace `ns` only, keeping this worker's mount namespace
    (so a namespace the child creates, such as the client's avpn-app, stays visible)."""
    fd = os.open("/run/netns/" + ns, os.O_RDONLY)
    try:
        return subprocess.Popen(list(map(str, args)), preexec_fn=lambda: os.setns(fd, 0), **k)
    finally:
        os.close(fd)


def link(a, b, a_ip, b_ip, name):
    sh("/usr/sbin/ip", "link", "add", name + "a", "type", "veth", "peer", "name", name + "b")
    for ns, dev, ip in [(a, name + "a", a_ip), (b, name + "b", b_ip)]:
        if ns:
            sh("/usr/sbin/ip", "link", "set", dev, "netns", ns)
        pre = ["/usr/sbin/ip", "-n", ns] if ns else ["/usr/sbin/ip"]
        sh(*pre, "address", "add", ip, "dev", dev)
        sh(*pre, "link", "set", dev, "up")


def worker(a):
    """Inside the worker's namespaces: build the tunnel, then load every assigned page."""
    from avpnctl import lab_guard
    from lab_resolver import private_resolver

    lab_guard()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sh("mount", "--make-rprivate", "/")
    sh("mount", "-t", "tmpfs", "-o", "size=512m,mode=0755", "tmpfs", "/run")
    sh("mount", "-t", "tmpfs", "-o", "size=1g,mode=1777", "tmpfs", "/tmp")
    resolv = private_resolver()
    # pasta attaches after start: wait for its default route.
    for _ in range(100):
        if "default" in sh("/usr/sbin/ip", "route").stdout:
            break
        time.sleep(0.2)
    wan = sh("/usr/sbin/ip", "route", "show", "default").stdout.split(" dev ")[1].split()[0]
    sh("/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
    procs = []
    loads = json.loads(a.loads.read_text())
    try:
        if a.config == "undefended":
            for ns in ["cli", "ext"]:
                sh("/usr/sbin/ip", "netns", "add", ns)
                sh("/usr/sbin/ip", "-n", ns, "link", "set", "lo", "up")
            link("cli", "ext", "192.0.2.2/30", "192.0.2.1/30", "u")
            link("ext", None, "203.0.113.2/30", "203.0.113.1/30", "w")
            nsexec("ext", "/usr/sbin/ip", "route", "add", "default", "via", "203.0.113.1")
            keys = {}
            for ns in ["cli", "ext"]:
                priv = sh("wg", "genkey").stdout.strip()
                keys[ns] = (priv, sh("wg", "pubkey", input=priv).stdout.strip())
                (out / (ns + ".key")).write_text(priv)
            nsexec("ext", "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
            for ns, other, me, peer_ep, allowed in [
                ("cli", "ext", "10.9.0.2/24", "192.0.2.1:51820", "0.0.0.0/0"),
                ("ext", "cli", "10.9.0.1/24", None, "10.9.0.2/32"),
            ]:
                nsexec(ns, "/usr/sbin/ip", "link", "add", "wg0", "type", "wireguard")
                args = [
                    "wg",
                    "set",
                    "wg0",
                    "private-key",
                    out / (ns + ".key"),
                    "peer",
                    keys[other][1],
                    "allowed-ips",
                    allowed,
                ]
                if ns == "ext":
                    args[5:5] = ["listen-port", "51820"]
                if peer_ep:
                    args += ["endpoint", peer_ep, "persistent-keepalive", "25"]
                nsexec(ns, *args)
                nsexec(ns, "/usr/sbin/ip", "address", "add", me, "dev", "wg0")
                nsexec(ns, "/usr/sbin/ip", "link", "set", "wg0", "up", "mtu", "1420")
            nsexec("cli", "/usr/sbin/ip", "route", "add", "default", "dev", "wg0")
            nat = 'table ip wf {\n chain post {\n  type nat hook postrouting priority 100;\n  oifname "wa" masquerade\n }\n}\n'
            nsexec("ext", "/usr/sbin/nft", "-f", "-", input=nat)
            browse_ns, capture_ns, capture_dev = "cli", "cli", "ua"
            resolver = "nameserver 9.9.9.9\n"
        else:
            from managed_profile import lab_setup

            for ns in ["cli", "rel", "ext"]:
                sh("/usr/sbin/ip", "netns", "add", ns)
                sh("/usr/sbin/ip", "-n", ns, "link", "set", "lo", "up")
            link("cli", "rel", "192.0.2.2/30", "192.0.2.1/30", "c")
            link("rel", "ext", "198.51.100.1/30", "198.51.100.2/30", "r")
            link("ext", None, "203.0.113.2/30", "203.0.113.1/30", "w")
            nsexec("cli", "/usr/sbin/ip", "route", "add", "default", "via", "192.0.2.1")
            nsexec("rel", "/usr/sbin/ip", "route", "add", "default", "via", "198.51.100.2")
            nsexec("ext", "/usr/sbin/ip", "route", "add", "default", "via", "203.0.113.1")
            for ns in ["rel", "ext"]:
                nsexec(ns, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
            state = out / "chain"
            state.mkdir()
            lab_setup(
                state,
                "192.0.2.1:443",
                "198.51.100.2:4444",
                destinations=["0.0.0.0/0"],
                rate=a.config,
                hops=2,
                dns=dict(upstream="1.1.1.1:853", server_name="one.one.one.one"),
            )
            for role, ns in [("exit", "ext"), ("relay", "rel"), ("client", "cli")]:
                f = (out / (role + ".log")).open("a")
                procs.append(
                    in_netns(ns, [sys.executable, ROOT / "tools/avpnctl.py", "--state", state / role, "--bin-dir",
                                  a.bin_dir, "--lab", "connect"], stdout=f, stderr=subprocess.STDOUT)
                )  # fmt: skip
                time.sleep(2)
            browse_ns, capture_ns, capture_dev = "avpn-app", "cli", "ca"
            resolver = "nameserver 10.77.0.1\n"
        # Live internet for the exit: masquerade it behind pasta.
        nat = (
            'table ip wfwan {\n chain post {\n  type nat hook postrouting priority 100;\n  oifname "%s" masquerade\n }\n}\n'
            % wan
        )
        sh("/usr/sbin/nft", "-f", "-", input=nat)
        # The worker's private resolver file (lab_resolver): every namespace here reads it.
        resolv.write_text(resolver)

        def in_browser_ns(*argv, timeout=60):
            """Run argv where the browser runs: the client namespace, or (chain) its
            protected application namespace through `avpnctl run`, as a user would."""
            if a.config == "undefended":
                return nsexec("cli", *argv, check=False, timeout=timeout)
            run = [sys.executable, ROOT / "tools/avpnctl.py", "--state", out / "chain/client", "--lab", "run", "--"]
            p = in_netns("cli", run + list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                o, e = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill()
                o, e = p.communicate()
            return subprocess.CompletedProcess(p.args, p.returncode, o, e)

        # Up when the browser's namespace reaches the internet through the tunnel.
        for _ in range(240):
            probe = in_browser_ns(sys.executable, "-c", "import socket;socket.create_connection(('9.9.9.9',443),3)")
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            from avpnctl import runtime_dir

            print("namespaces:", sh("/usr/sbin/ip", "netns", "list", check=False).stdout.split(), file=sys.stderr)
            for ns, cmd in [
                (browse_ns, ["ping", "-c", "2", "-W", "2", "10.77.0.1"]),
                (browse_ns, ["ping", "-c", "2", "-W", "2", "9.9.9.9"]),
                ("ext", ["/usr/sbin/ip", "route"]),
                ("ext", ["ping", "-c", "2", "-W", "2", "9.9.9.9"]),
                (None, ["/usr/sbin/nft", "list", "ruleset"]),
                (None, ["/usr/sbin/ip", "route"]),
            ]:
                r = nsexec(ns, *cmd, check=False) if ns else sh(*cmd, check=False)
                print("##", ns, " ".join(cmd), "->", r.returncode, (r.stdout + r.stderr)[-400:], file=sys.stderr)
            if a.config != "undefended":
                for role in ["client", "relay"]:
                    for f in ["carrier-status.json", "cloak-status.json"]:
                        p = runtime_dir(out / "chain" / role, create=False) / f
                        print("##", role, f, p.read_text()[:300] if p.exists() else "missing", file=sys.stderr)
            if a.config != "undefended":
                for role in ["client", "relay", "exit"]:
                    for log in sorted(runtime_dir(out / "chain" / role, create=False).glob("*.lab.log")):
                        print("=====", role, log.name, file=sys.stderr)
                        print("\n".join(log.read_text(errors="replace").splitlines()[-15:]), file=sys.stderr)
            raise RuntimeError("the tunnel did not come up")
        # Wire-sized packets, as an ISP sees them: no offload super-frames on the captured link.
        for ns, dev in [(capture_ns, capture_dev)]:
            r = nsexec(ns, a.ethtool, "-K", dev, "gro", "off", "gso", "off", "tso", "off", check=False)
            if r.returncode:
                raise RuntimeError("cannot turn offload off on the captured link: " + r.stderr.strip()[:200])
        packets = out / "packets.bin"
        procs.append(
            subprocess.Popen(
                ["/usr/sbin/ip", "netns", "exec", capture_ns, sys.executable, "-c", SNIFF, capture_dev, str(packets)]
            )  # fmt: skip
        )
        with (out / "loads.jsonl").open("a") as log:
            for site, label in loads:
                r = in_browser_ns("env", "HOME=/tmp", a.python, "-c", BROWSE, a.geckodriver, site, out,
                                  timeout=WINDOW + 90)  # fmt: skip
                try:
                    row = json.loads(r.stdout.strip().splitlines()[-1])
                except (ValueError, IndexError):
                    row = dict(status="browser_failed")
                log.write(json.dumps(dict(site=site, label=label, **row)) + "\n")
                log.flush()
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()


def collect(a):
    """Spread the loads over workers, give each live internet, wait for all."""
    sites = json.loads(a.sites.read_text())
    plan = [(s, i) for i, s in enumerate(sites["monitored"]) for _ in range(sites["loads"])]
    plan += [(s, -1) for s in sites.get("open_world", [])]
    random.Random(7).shuffle(plan)
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    workers = []
    for w in range(a.workers):
        part = out / ("plan%d.json" % w)
        part.write_text(json.dumps(plan[w :: a.workers]))
        log = (out / ("worker%d.log" % w)).open("w")
        p = subprocess.Popen(
            ["unshare", "--user", "--map-root-user", "--map-auto", "--net", "--mount", sys.executable, __file__,
             "worker", "--config", a.config, "--loads", str(part), "--out", str(out / ("w%d" % w)), "--bin-dir",
             str(a.bin_dir), "--geckodriver", str(a.geckodriver), "--python", str(a.python), "--ethtool",
             str(a.ethtool)],
            stdout=log, stderr=subprocess.STDOUT,
        )  # fmt: skip
        time.sleep(0.5)
        sh(a.pasta, "--config-net", "--quiet", p.pid)
        workers.append(p)
        time.sleep(5)
    for p in workers:
        p.wait()
    print(json.dumps(dict(config=a.config, workers=a.workers, loads=len(plan), out=str(out))))


def main():
    """Command line."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    s = p.add_subparsers(dest="cmd", required=True)
    for name in ["collect", "worker"]:
        x = s.add_parser(name)
        x.add_argument("--config", required=True, choices=["undefended", "metered", "standard", "fast", "line"])
        x.add_argument("--out", type=Path, required=True)
        x.add_argument("--bin-dir", type=Path, default=ROOT / "target/release")
        x.add_argument("--geckodriver", type=Path, required=True)
        x.add_argument("--python", type=Path, required=True)
        x.add_argument("--ethtool", type=Path, default=Path("/usr/sbin/ethtool"))
        if name == "collect":
            x.add_argument("--sites", type=Path, required=True)
            x.add_argument("--workers", type=int, default=4)
            x.add_argument("--pasta", type=Path, required=True)
        else:
            x.add_argument("--loads", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o022)
    (collect if a.cmd == "collect" else worker)(a)


if __name__ == "__main__":
    main()

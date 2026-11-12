#!/usr/bin/env python3
"""Failover and rotation lab: a 2-hop chain with a standby exit, in network namespaces.

    client 192.0.2.2 -- 192.0.2.1 relay 198.51.100.1 -- 198.51.100.2 exit  203.0.113.1 -- destination
                                        198.51.100.5 -- 198.51.100.6 exit2 203.0.113.5 --

Runs the real request -> init -> enroll flow (exit2 is a standby exit), connects every
device, then:

  failover   takes the primary exit's link down while a prober inside the tunnel asks
             the destination every 250 ms which exit address it sees, and measures how
             long until traffic flows again through the standby exit;
  rotation   (--rotate) with short sessions and a short rotation window, records the
             exits used over time while the client's only peer stays the relay.

Throughout, the destination records every source address that reaches it: the client's
real address must never appear (nothing escapes the tunnel while the chain heals).

usage: unshare --user --map-root-user --map-auto --net --mount python3 tools/failover_lab.py
       --state DIR [--rate metered|standard|fast|line] [--rotate] [--json OUT]
Not run in CI (it takes minutes); its result is docs/evidence/FAILOVER.json.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import throughput_bench as tb  # noqa: E402
from avpnctl import identity_of, lab_guard, runtime_dir  # noqa: E402
from managed_profile import RATE_CLASSES, lab_setup  # noqa: E402

CLIENT_IP = "192.0.2.2"
EXITS = {"203.0.113.1": "exit", "203.0.113.5": "exit2"}
# (namespace a, address a, namespace b, address b, device name)
LINKS = [
    ("client", "192.0.2.2/30", "relay", "192.0.2.1/30", "l0"),
    ("relay", "198.51.100.1/30", "exit", "198.51.100.2/30", "l1"),
    ("relay", "198.51.100.5/30", "exit2", "198.51.100.6/30", "l2"),
    ("exit", "203.0.113.1/30", "destination", "203.0.113.2/30", "l3"),
    ("exit2", "203.0.113.5/30", "destination", "203.0.113.6/30", "l4"),
]
NODES = ["client", "relay", "exit", "exit2", "destination"]
# The destination: answer each TCP connection with the source address it came from,
# and remember every source address that ever reached it.
WHO = r"""
import json,socket,sys,threading
seen=set();out=sys.argv[1]
def sniff():
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
    while True:
        b=s.recv(128)
        if len(b)>=34 and b[12:14]==b'\x08\x00':
            seen.add(socket.inet_ntoa(b[26:30]))
            open(out,'w').write(json.dumps(sorted(seen)))
threading.Thread(target=sniff,daemon=True).start()
srv=socket.socket();srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);srv.bind(('0.0.0.0',5400));srv.listen(64)
while True:
    c,a=srv.accept()
    try:c.sendall(a[0].encode())
    finally:c.close()
"""
# Inside the tunnel: every 250 ms, which exit does the destination see? One JSON line each.
PROBE = r"""
import json,socket,sys,time
end=time.time()+float(sys.argv[1])
while time.time()<end:
    t=time.time()
    try:
        s=socket.create_connection(('203.0.113.2',5400),1.0);s.settimeout(1.0);who=s.recv(64).decode();s.close()
    except OSError:
        who=None
    print(json.dumps(dict(t=round(t,3),exit=who)),flush=True)
    time.sleep(max(0,0.25-(time.time()-t)))
"""


def main():
    """Build the lab, run failover (and optionally rotation), print the result."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--rate", choices=list(RATE_CLASSES), default="standard")
    p.add_argument("--rotate", action="store_true", help="also run the rotation phase")
    p.add_argument("--json", type=Path, help="write the result here too")
    a = p.parse_args()
    os.umask(0o077)
    lab_guard()
    state = a.state.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    # Short sessions in the lab, so a rotation shows within minutes (production: 300 s).
    lab_setup(
        state,
        "192.0.2.1:443",
        "198.51.100.2:4444",
        destinations=["203.0.113.0/30"],
        rate=a.rate,
        hops=2,
        dns=dict(upstream="203.0.113.2:8530", server_name="dns.lab.internal"),
        standby=[("exit2", "198.51.100.6:4444")],
        rotate=(60, 90) if a.rotate else (3600, 3600),
        rates=dict(session_seconds=30) if a.rotate else None,
    )
    tb.run("mount", "--make-rprivate", "/")
    tb.run("mount", "-t", "tmpfs", "-o", "size=64m", "tmpfs", "/run")
    target = Path("/etc/resolv.conf").resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text("")
    namespaces = ["av-" + n for n in NODES]
    procs = []

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
        return spawn(
            "av-" + role,
            [sys.executable, ROOT / "tools/avpnctl.py", "--state", state / role, "--bin-dir",
             ROOT / "target/release", "--lab", "connect"],
            role,
        )  # fmt: skip

    def app_proc(argv, out):
        f = out.open("w")
        fd = os.open("/run/netns/av-client", os.O_RDONLY)
        try:
            x = subprocess.Popen(
                [sys.executable, str(ROOT / "tools/avpnctl.py"), "--state", str(state / "client"), "--lab", "run",
                 "--", *argv],
                preexec_fn=lambda: os.setns(fd, 0), stdout=f, stderr=subprocess.DEVNULL,
            )  # fmt: skip
        finally:
            os.close(fd)
        procs.append(x)
        return x

    def probes(path):
        rows = []
        for line in path.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
        return rows

    result = dict(rate=a.rate, hops=2, standby_exits=1)
    try:
        for ns in namespaces:
            tb.run("ip", "netns", "add", ns)
            tb.run("ip", "-n", ns, "link", "set", "lo", "up")
        for n1, ip1, n2, ip2, dev in LINKS:
            tb.run("ip", "link", "add", dev + "a", "type", "veth", "peer", "name", dev + "b")
            for ns, d, ip in [("av-" + n1, dev + "a", ip1), ("av-" + n2, dev + "b", ip2)]:
                tb.run("ip", "link", "set", d, "netns", ns)
                tb.run("ip", "-n", ns, "address", "add", ip, "dev", d)
                tb.run("ip", "-n", ns, "link", "set", d, "up")
        for ns in ["av-relay", "av-exit", "av-exit2"]:
            tb.run("ip", "netns", "exec", ns, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        # The standby exit reaches the destination's .2 address through its own link.
        tb.run("ip", "-n", "av-exit2", "route", "add", "203.0.113.0/30", "via", "203.0.113.6")
        seen_file = state / "destination-sources.json"
        spawn("av-destination", [sys.executable, "-c", WHO, seen_file], "who")
        for role in ["exit", "exit2", "relay"]:
            manager(role)
        time.sleep(2)
        client = manager("client")
        end = time.monotonic() + 90
        while time.monotonic() < end:
            if client.poll() is not None:
                raise RuntimeError("client supervisor exited")
            ok = tb.run("ip", "netns", "exec", "av-client", sys.executable, ROOT / "tools/avpnctl.py", "--state",
                        state / "client", "--lab", "run", "--", "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1",
                        check=False, timeout=20).returncode == 0  # fmt: skip
            if ok:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("tunnel did not come up")

        # Failover: steady on the primary, then take its link down.
        probe_file = state / "probe-failover.jsonl"
        prober = app_proc([sys.executable, "-c", PROBE, "60"], probe_file)
        time.sleep(10)
        before = [r for r in probes(probe_file) if r["exit"]]
        killed_at = time.time()
        tb.run("ip", "-n", "av-exit", "link", "set", "l1b", "down")
        prober.wait(timeout=90)
        rows = probes(probe_file)
        after = [r for r in rows if r["t"] > killed_at]
        healed = next((r for r in after if r["exit"] == "203.0.113.5"), None)
        result["failover"] = dict(
            before={EXITS.get(r["exit"], r["exit"]) for r in before}
            and sorted({EXITS.get(r["exit"], r["exit"]) for r in before}),
            recovered_via=EXITS.get(healed["exit"]) if healed else None,
            outage_seconds=round(healed["t"] - killed_at, 2) if healed else None,
            probes_after=len(after),
            probes_ok_after_recovery=sum(1 for r in after if healed and r["t"] >= healed["t"] and r["exit"]),
            probes_failed_after_recovery=sum(1 for r in after if healed and r["t"] >= healed["t"] and not r["exit"]),
        )
        if a.rotate:
            # Bring the primary back; rotation should move sessions between the exits.
            tb.run("ip", "-n", "av-exit", "link", "set", "l1b", "up")
            probe_file = state / "probe-rotation.jsonl"
            prober = app_proc([sys.executable, "-c", PROBE, "300"], probe_file)
            prober.wait(timeout=400)
            rows = [r for r in probes(probe_file) if r["exit"]]
            changes = [
                dict(t=round(b["t"] - rows[0]["t"], 1), to=EXITS.get(b["exit"], b["exit"]))
                for x, b in zip(rows, rows[1:], strict=False)
                if x["exit"] != b["exit"]
            ]
            result["rotation"] = dict(
                window_seconds=[60, 90],
                session_seconds=30,
                exits_used=sorted({EXITS.get(r["exit"], r["exit"]) for r in rows}),
                changes=changes,
                probes=len(rows),
            )
        seen = json.loads(seen_file.read_text()) if seen_file.exists() else []
        result["leak"] = dict(
            destination_sources=seen,
            client_address_reached_destination=CLIENT_IP in seen,
        )
        print(json.dumps(result, indent=1))
        if a.json:
            a.json.write_text(json.dumps(result, indent=1) + "\n")
        if CLIENT_IP in seen:
            raise SystemExit("the client's own address reached the destination: a leak")
        if not healed:
            raise SystemExit("traffic never recovered through the standby exit")
    finally:
        for role in ["client", "relay", "exit", "exit2"]:
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
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for ns in reversed(namespaces):
            tb.run("ip", "netns", "del", ns, check=False)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""I2P front lab: a private I2P network and a 2-hop chain whose client reaches its entry
only through I2P, in network namespaces.

    I2P routers r1..r6 (r1-r3 floodfill), each on its own address
    client 192.0.2.2 (whole-device mode)        entry (relay) 192.0.2.66
    exit 198.51.100.130                          destination 203.0.113.200
    all joined by one routing namespace ("inet"), like hosts on the internet.

Runs the real request -> init (--front i2p) -> enroll flow, connects every device, then:

  transfer   fetches a file from the destination through the tunnel, SHA-256 verified,
             and pings through it for the round-trip time;
  router     kills the client's I2P router (the supervisor restarts it) and measures
             the outage while probes keep trying to leave;
  observe    throughout, packet capture records every address the entry and the
             destination ever receive from, and every address the client sends to.

Gates (the lab fails if any is broken): the entry never receives a packet from the
client's address; the client never sends one to the entry's address, the exit or the
destination; everything the client sends goes to I2P routers (the whole-device kill
switch lets only the I2P router's user out); the destination never sees the client.

usage: unshare --user --map-root-user --map-auto --net --mount python3 tools/i2p_lab.py
       --state DIR --i2pd-root DIR [--rate metered|standard] [--front-hops 1|2|3] [--json OUT]
--i2pd-root is an unpacked i2pd package (usr/bin/i2pd and its libraries), e.g.
`apt-get download i2pd libminiupnpc18 && dpkg -x` each into one directory.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import i2p  # noqa: E402
from lab_resolver import private_resolver  # noqa: E402
import throughput_bench as tb  # noqa: E402
from avpnctl import identity_of, lab_guard, runtime_dir  # noqa: E402
from managed_profile import lab_setup  # noqa: E402

NETID = 7
ROUTERS = {
    "r1": "198.51.100.10",
    "r2": "198.51.100.20",
    "r3": "198.51.100.30",
    "r4": "203.0.113.40",
    "r5": "203.0.113.50",
    "r6": "203.0.113.60",
}
FLOODFILL = {"r1", "r2", "r3"}
CLIENT, ENTRY, EXIT, DEST = "192.0.2.2", "192.0.2.66", "198.51.100.130", "203.0.113.200"
NODES = dict(ROUTERS, client=CLIENT, relay=ENTRY, exit=EXIT, destination=DEST)
SIZE = {"metered": 2 * 1048576, "standard": 8 * 1048576}
# Packet capture: every IPv4 source (and destination) address seen on the namespace's
# links, with byte counts, rewritten once a second.
SNIFF = r"""
import json,socket,sys,time
out=sys.argv[1];src={};dst={};last=0
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
while True:
    b,addr=s.recvfrom(128)
    if not addr[0].startswith('n') or len(b)<34 or b[12:14]!=b'\x08\x00':continue
    a,d=socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34])
    n=int.from_bytes(b[16:18],'big')
    if addr[2]==socket.PACKET_OUTGOING:
        dst[d]=dst.get(d,0)+n
    else:
        src[a]=src.get(a,0)+n
    if time.time()-last>1:
        last=time.time();open(out+'.tmp','w').write(json.dumps(dict(received_from=src,sent_to=dst)));__import__('os').replace(out+'.tmp',out)
"""
# The destination: serves SIZE random bytes and their SHA-256 on port 5401.
SERVE = r"""
import hashlib,os,socket,sys
n=int(sys.argv[1]);data=os.urandom(n);open(sys.argv[2],'w').write(hashlib.sha256(data).hexdigest())
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',5401));s.listen(8)
while True:
    c,a=s.accept()
    try:c.sendall(data)
    finally:c.close()
"""
FETCH = r"""
import hashlib,json,socket,sys,time
t=time.time();h=hashlib.sha256();n=0
s=socket.create_connection((sys.argv[1],5401),30);s.settimeout(60)
while True:
    b=s.recv(65536)
    if not b:break
    h.update(b);n+=len(b)
print(json.dumps(dict(bytes=n,sha256=h.hexdigest(),seconds=round(time.time()-t,2))))
"""


def dump_logs(state, lines=40):
    """On failure, print the tail of every log that explains it (CI shows nothing else):
    the supervisors, their children (the I2P routers and the cloaks, in RAM) and the
    lab's own I2P routers."""
    logs = sorted(state.glob("*.log"))
    for role in ["client", "relay", "exit"]:
        rt = runtime_dir(state / "keys" / role, create=False)
        if rt.exists():
            logs += sorted(rt.glob("*.lab.log"))
    for log in logs:
        try:
            text = log.read_text(errors="replace").splitlines()
        except OSError:
            continue
        # Repeated errors fill the tail; the cause is usually near the start.
        shown = text if len(text) <= 2 * lines else text[:lines] + ["..."] + text[-lines:]
        print("===== %s (%d lines)" % (log, len(text)), file=sys.stderr)
        for line in shown:
            print(line[:300], file=sys.stderr)


def main():
    """Build the lab, run it, gate the result."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--i2pd-root", type=Path, required=True)
    p.add_argument("--rate", choices=list(i2p.FRONT_RATES), default="metered")
    p.add_argument("--front-hops", type=int, choices=list(i2p.FRONT_HOPS), default=i2p.DEFAULT_HOPS)
    p.add_argument(
        "--entry-transit",
        action="store_true",
        help="adversarial entry: its I2P router offers itself as a tunnel hop, hoping to carry the client's own tunnels",
    )
    p.add_argument("--json", type=Path)
    a = p.parse_args()
    os.umask(0o077)
    lab_guard()
    state = a.state.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    tb.run("mount", "--make-rprivate", "/")
    tb.run("mount", "-t", "tmpfs", "-o", "size=256m,mode=0755", "tmpfs", "/run")
    # Whole-device mode rewrites the resolver file: give it a private one in this lab's
    # mount namespace (the host's file is never written).
    private_resolver()
    # i2pd runs as an unprivileged user that cannot enter the developer's home: give it
    # its own copy, with its libraries, on the lab's tmpfs.
    lab_i2p = Path("/run/i2p-lab")
    shutil.copytree(a.i2pd_root.resolve() / "usr", lab_i2p / "usr", symlinks=True)
    for d in [lab_i2p, *lab_i2p.rglob("*")]:
        d.chmod(0o755 if d.is_dir() or os.access(d, os.X_OK) else 0o644)
    i2pd = lab_i2p / "usr/bin/i2pd"
    libs = str(lab_i2p / "usr/lib/x86_64-linux-gnu")
    env = dict(os.environ, AVPN_I2PD=str(i2pd), LD_LIBRARY_PATH=libs)
    env.pop("SSH_CONNECTION", None)
    procs = []

    def spawn(ns, args, name, extra_env=None):
        f = (state / (name + ".log")).open("a")
        fd = os.open("/run/netns/av-" + ns, os.O_RDONLY)
        try:
            x = subprocess.Popen(
                list(map(str, args)),
                preexec_fn=lambda: os.setns(fd, 0),
                stdout=f,
                stderr=subprocess.STDOUT,
                env=dict(env, **(extra_env or {})),
            )
        finally:
            os.close(fd)
        procs.append(x)
        return x

    def nsrun(ns, *args, check=True, timeout=60):
        return subprocess.run(
            ["/usr/sbin/ip", "netns", "exec", "av-" + ns, *map(str, args)],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    def router(name, seed=None):
        d = Path("/run/i2p-lab") / name
        d.mkdir(exist_ok=True)
        # Without a reseed bundle (first start) the router only creates its identity.
        net = dict(netid=NETID, address=ROUTERS[name], floodfill=name in FLOODFILL, transit=True, reseed=seed)
        (d / "i2pd.conf").write_text(i2p.router_conf(d, port=12345, verbose=True, testnet=net))
        (d / "tunnels.conf").write_text("")
        return spawn(name, [i2pd, "--datadir", d, "--conf", d / "i2pd.conf", "--tunconf", d / "tunnels.conf"], name)

    def counts(name):
        try:
            return json.loads((state / ("seen-" + name + ".json")).read_text())
        except (OSError, ValueError):
            return dict(received_from={}, sent_to={})

    def ping(count=1, wait=1):
        return nsrun("client", "ping", "-n", "-q", "-c", count, "-W", wait, "10.77.0.1", check=False, timeout=90)

    result = dict(
        rate=a.rate,
        front_hops=a.front_hops,
        i2p_routers=len(ROUTERS),
        mode="whole-device",
        entry_transit=a.entry_transit,
    )
    try:
        tb.run("ip", "netns", "add", "av-inet")
        tb.run("ip", "-n", "av-inet", "link", "set", "lo", "up")
        tb.run("ip", "netns", "exec", "av-inet", "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        for k, (name, ip) in enumerate(NODES.items()):
            ns = "av-" + name
            gw = ip.rsplit(".", 1)[0] + "." + str(int(ip.rsplit(".", 1)[1]) - 1)
            tb.run("ip", "netns", "add", ns)
            tb.run("ip", "-n", ns, "link", "set", "lo", "up")
            tb.run("ip", "link", "add", "n%d" % k, "type", "veth", "peer", "name", "i%d" % k)
            tb.run("ip", "link", "set", "n%d" % k, "netns", ns)
            tb.run("ip", "link", "set", "i%d" % k, "netns", "av-inet")
            tb.run("ip", "-n", ns, "address", "add", ip + "/32", "peer", gw, "dev", "n%d" % k)
            tb.run("ip", "-n", "av-inet", "address", "add", gw + "/32", "peer", ip, "dev", "i%d" % k)
            tb.run("ip", "-n", ns, "link", "set", "n%d" % k, "up")
            tb.run("ip", "-n", "av-inet", "link", "set", "i%d" % k, "up")
            tb.run("ip", "-n", ns, "route", "add", "default", "via", gw)
        for name in ["relay", "exit"]:
            nsrun(name, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        for name in ["relay", "destination"]:
            spawn(name, [sys.executable, "-c", SNIFF, state / ("seen-" + name + ".json")], "sniff-" + name)

        # The private I2P network: identities, a reseed bundle of all six, then the network.
        first = [router(n) for n in ROUTERS]
        for _ in range(100):
            if all((lab_i2p / n / "router.info").exists() for n in ROUTERS):
                break
            time.sleep(0.2)
        for x in first:
            x.kill()
            x.wait()
        seed = lab_i2p / "seed.zip"
        with zipfile.ZipFile(seed, "w") as z:
            for n in ROUTERS:
                z.write(lab_i2p / n / "router.info", "routerInfo-%s.dat" % n)
        seed.chmod(0o644)
        for n in ROUTERS:
            router(n, seed)

        # The chain, signed with the I2P front.
        (state / "keys").mkdir(mode=0o700)
        lab_setup(
            state / "keys",
            ENTRY + ":443",
            EXIT + ":4444",
            destinations=[DEST + "/32"],
            rate=a.rate,
            hops=2,
            dns=dict(upstream=DEST + ":8530", server_name="dns.lab.internal"),
            front="i2p",
            front_hops=a.front_hops,
        )
        client_profile = json.loads((state / "keys/client/profile.json").read_text())
        result["entry_destination"] = client_profile["front"]["destination"]
        for name, ip in [("client", CLIENT), ("relay", ENTRY)]:
            f = state / ("testnet-" + name + ".json")
            net = dict(netid=NETID, reseed=str(seed), address=ip)
            if name == "relay" and a.entry_transit:
                net["transit"] = True
            f.write_text(json.dumps(net))
        digest_file = state / "served.sha256"
        spawn("destination", [sys.executable, "-c", SERVE, SIZE[a.rate], digest_file], "serve")

        def manager(role, whole=False):
            args = [sys.executable, ROOT / "tools/avpnctl.py", "--state", state / "keys" / role, "--bin-dir",
                    ROOT / "target/release", "--lab", "connect"] + (["--whole-device"] if whole else [])  # fmt: skip
            return spawn(role, args, role, dict(AVPN_LAB_I2P=str(state / ("testnet-" + role + ".json"))))

        manager("exit")
        manager("relay")
        time.sleep(2)
        t0 = time.monotonic()
        client = manager("client", whole=True)
        # The client's own capture starts once its kill switch exists: from then on, the
        # only packets that may leave are the I2P router's.
        while nsrun("client", "/usr/sbin/nft", "list", "table", "inet", "advanced_vpn", check=False).returncode:
            if client.poll() is not None or time.monotonic() - t0 > 60:
                raise RuntimeError("the client's kill switch never came up")
            time.sleep(0.1)
        spawn("client", [sys.executable, "-c", SNIFF, state / "seen-client.json"], "sniff-client")
        while time.monotonic() - t0 < 240:
            if client.poll() is not None:
                raise RuntimeError("client supervisor exited")
            if ping().returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("the tunnel did not come up through I2P")
        result["tunnel_up_seconds"] = round(time.monotonic() - t0, 1)

        # Transfer and round trip through the front.
        fetch = nsrun("client", sys.executable, "-c", FETCH, DEST, timeout=600)
        got = json.loads(fetch.stdout.strip().splitlines()[-1])
        served = digest_file.read_text().strip()
        result["transfer"] = dict(
            bytes=got["bytes"],
            sha256_verified=got["sha256"] == served and got["bytes"] == SIZE[a.rate],
            seconds=got["seconds"],
            mbit_per_s=round(got["bytes"] * 8 / got["seconds"] / 1e6, 2),
        )
        pings = ping(20, 3).stdout
        rtt = [x for x in pings.splitlines() if "min/avg/max" in x]
        result["ping"] = dict(
            summary=pings.strip().splitlines()[-2] if pings else "",
            rtt_ms=rtt[0].split("=")[1].strip() if rtt else None,
        )

        # Kill the client's I2P router: nothing may leave while it is gone, and the
        # supervisor restarts it.
        status = json.loads((runtime_dir(state / "keys/client") / "status.json").read_text())
        front = status["children"]["front"]
        killed = time.monotonic()
        os.kill(front["pid"], signal.SIGKILL)
        while time.monotonic() - killed < 300:
            if ping().returncode == 0:
                break
            time.sleep(1)
        result["router_restart"] = dict(
            recovered=ping().returncode == 0, outage_seconds=round(time.monotonic() - killed, 1)
        )
        time.sleep(2)

        # The front table, directly: the I2P router's own user (the one the kill switch
        # lets out) tries to reach the entry's I2P router. Only that table stops it.
        router_port = json.loads((state / "keys/relay/profile.json").read_text())["front"]["router_port"]
        probe = "import os,socket,sys;os.setgid(2);os.setuid(2);s=socket.socket();s.settimeout(3);s.connect((sys.argv[1],int(sys.argv[2])))"
        reached = nsrun("client", sys.executable, "-c", probe, ENTRY, router_port, check=False).returncode == 0
        result["front_table"] = dict(i2p_user_reached_entry=reached)
        time.sleep(2)

        # What each vantage saw, over the whole run.
        entry, dest, cl = counts("relay"), counts("destination"), counts("client")
        routers = set(ROUTERS.values())
        sent_to = cl["sent_to"]
        result["entry_view"] = dict(
            received_from=sorted(entry["received_from"]),
            client_address_seen=CLIENT in entry["received_from"],
            sent_to_client=CLIENT in entry["sent_to"],
        )
        result["client_view"] = dict(
            sent_to=sorted(sent_to),
            bytes_to_i2p_routers=sum(v for k, v in sent_to.items() if k in routers),
            bytes_elsewhere=sum(v for k, v in sent_to.items() if k not in routers),
            sent_to_entry=ENTRY in sent_to,
        )
        result["destination_view"] = dict(
            received_from=sorted(dest["received_from"]), client_address_seen=CLIENT in dest["received_from"]
        )
        result["gates"] = gates = dict(
            entry_never_saw_client=not result["entry_view"]["client_address_seen"],
            entry_never_addressed_client=not result["entry_view"]["sent_to_client"],
            client_never_sent_to_entry=not result["client_view"]["sent_to_entry"],
            client_sent_only_to_i2p_routers=set(sent_to) <= routers,
            destination_never_saw_client=not result["destination_view"]["client_address_seen"],
            transfer_verified=result["transfer"]["sha256_verified"],
            router_restart_recovered=result["router_restart"]["recovered"],
            front_table_blocks_entry=not reached,
        )
        print(json.dumps(result, indent=1))
        if a.json:
            a.json.write_text(json.dumps(result, indent=1) + "\n")
        failed = [k for k, v in gates.items() if not v]
        if failed:
            raise SystemExit("I2P front gates failed: " + ", ".join(failed))
    except BaseException:
        dump_logs(state)
        raise
    finally:
        for role in ["client", "relay", "exit"]:
            path = runtime_dir(state / "keys" / role, create=False) / "status.json"
            if path.exists():
                for child in json.loads(path.read_text()).get("children", {}).values():
                    try:
                        if identity_of(child["pid"]) == child["identity"]:
                            os.kill(child["pid"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for proc in reversed(procs):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for name in list(NODES) + ["inet"]:
            tb.run("ip", "netns", "del", "av-" + name, check=False)


if __name__ == "__main__":
    main()

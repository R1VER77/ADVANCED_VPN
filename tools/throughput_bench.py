#!/usr/bin/env python3
"""Multi-hop tunnel test and throughput benchmark in disposable namespaces.

Requires: unshare --user --map-root-user --map-auto --net --mount
Builds a chain of namespaces joined by veth links (no host network change):

  1 hop   client - exit - destination
  2 hops  client - relay - exit - destination
  3 hops  client - relay - middle - exit - destination

enrolls every role with the real request -> init -> enroll flow, and times a
SHA-checked TCP bulk transfer whose payload carries a random marker. A raw
observer on each server's ingress link proves the onion property on the wire:
no server sees the plaintext marker, and only the first hop sees the client's
address (later hops see only their predecessor).

--mode carrier times WireGuard+DAITA alone (client host namespace -> first hop).
Rate-budget and DAITA-profile overrides exist only to measure their effect.
"""

import argparse
import itertools
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from managed_profile import lab_setup, CHAINS, RATE_CLASSES  # noqa: E402
from avpnctl import lab_guard, identity_of, runtime_dir  # noqa: E402

CLIENT_IP = "192.0.2.2"
SINK = r"""
import hashlib,socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])));s.listen(4)
while True:
    c,_=s.accept();h=hashlib.sha256();n=0
    while True:
        b=c.recv(1<<16)
        if not b:break
        h.update(b);n+=len(b)
    c.sendall((h.hexdigest()+' %d'%n).encode());c.close()
"""
SEND = r"""
import hashlib,json,os,socket,sys,time
host,port,size,marker=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),bytes.fromhex(sys.argv[4])
block=(marker+os.urandom(4096-len(marker)))*16;h=hashlib.sha256()
s=socket.create_connection((host,port),10);s.settimeout(120);t=time.monotonic();sent=0
while sent<size:
    b=block[:min(len(block),size-sent)];s.sendall(b);h.update(b);sent+=len(b)
s.shutdown(socket.SHUT_WR);r=b''
while True:
    part=s.recv(256)
    if not part:break
    r+=part
dt=time.monotonic()-t;digest,n=r.decode().split()
print(json.dumps(dict(bytes=sent,seconds=round(dt,3),mbit_s=round(sent*8/dt/1e6,2),sha256_verified=digest==h.hexdigest() and int(n)==sent)))
"""
# Raw ingress observer: IPv4 source addresses seen and whether the marker appears.
OBSERVE = r"""
import json,signal,socket,sys
dev,marker,out=sys.argv[1],bytes.fromhex(sys.argv[2]),sys.argv[3]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((dev,0));s.settimeout(.2)
srcs=set();seen=False;packets=0
def dump(*_):
    open(out,'w').write(json.dumps(dict(sources=sorted(srcs),marker_seen=seen,packets=packets)));sys.exit(0)
signal.signal(signal.SIGTERM,dump)
while True:
    try:b,addr=s.recvfrom(65536)
    except socket.timeout:continue
    if addr[2]==socket.PACKET_OUTGOING or len(b)<34 or b[12:14]!=b'\x08\x00':continue
    packets+=1;srcs.add(socket.inet_ntoa(b[26:30]))
    if marker in b:seen=True
"""
# Shape observer on the client <-> first-hop link (what the client's ISP sees): the
# wall time, IPv4 length and direction of every UDP packet, as packed records.
SHAPE = r"""
import signal,socket,struct,sys
dev,out=sys.argv[1],sys.argv[2]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((dev,0));s.settimeout(.2)
s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1<<24)
import time
buf=bytearray();n=0
def dump(*_):
    open(out,'wb').write(bytes(buf));sys.exit(0)
signal.signal(signal.SIGTERM,dump)
while True:
    try:b,addr=s.recvfrom(128)
    except socket.timeout:continue
    if len(b)<34 or b[12:14]!=b'\x08\x00' or b[23]!=17:continue
    if n<4000000:buf+=struct.pack('<dHB',time.time(),int.from_bytes(b[16:18],'big'),addr[2]==socket.PACKET_OUTGOING);n+=1
"""


# The cloak's UDP payload per wire packet (constant cells): 1448-byte IPv4 packets.
WIRE_SEGMENT = 1420


def shape_window(records, a, b, outgoing):
    """Wire shape in [a, b): packets/s, the 100 ms bins' spread, and the IPv4 sizes seen."""
    import collections

    # GSO hands the observer up to 64 KiB super-frames on veth: count wire segments
    # (one per WIRE_SEGMENT bytes of UDP payload), and sizes per segment.
    window = [(t, n) for t, n, o in records if a <= t < b and o == outgoing]
    times = [t for t, n in window for _ in range(max(1, round((n - 28) / WIRE_SEGMENT)))]
    sizes = collections.Counter(
        28 + (n - 28) // max(1, round((n - 28) / WIRE_SEGMENT))
        for t, n in window
        for _ in range(max(1, round((n - 28) / WIRE_SEGMENT)))
    )
    bins = collections.Counter(int((t - a) * 10) for t in times)
    counts = [bins.get(i, 0) for i in range(int((b - a) * 10))]
    return dict(
        seconds=round(b - a, 2),
        packets_per_second=round(len(times) / (b - a), 1),
        bin_100ms_min=min(counts) if counts else 0,
        bin_100ms_max=max(counts) if counts else 0,
        sizes=dict(sizes.most_common(4)),
    )


def shape_report(path, marks):
    """Idle vs transfer shape in both directions of the first link."""
    import struct

    raw = path.read_bytes()
    records = [struct.unpack_from("<dHB", raw, i) for i in range(0, len(raw) - len(raw) % 11, 11)]
    out = {}
    for direction, outgoing in [("client_to_hop", 0), ("hop_to_client", 1)]:
        idle = shape_window(records, *marks["idle"], outgoing)
        busy = shape_window(records, *marks["transfer"], outgoing)
        drift = abs(busy["packets_per_second"] - idle["packets_per_second"]) / max(idle["packets_per_second"], 1e-9)
        out[direction] = dict(idle=idle, transfer=busy, rate_change=round(drift, 4))
    return out


def run(*args, check=True, timeout=15):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, check=check, timeout=timeout)


def topology(hops):
    """Namespaces and links for a chain, plus its public endpoints. Nodes not used by a
    shorter chain inside this topology act as plain IP routers (as on the internet)."""
    servers = CHAINS[hops]
    nodes = ["client"] + servers + ["destination"]
    subnets = ["192.0.2.0"] + {1: [], 2: ["198.51.100.0"], 3: ["198.18.0.0", "198.51.100.0"]}[hops] + ["203.0.113.0"]
    links = []
    for k, (a, b) in enumerate(itertools.pairwise(nodes)):
        net = subnets[k].rsplit(".", 1)[0]
        # Client side is .2; a server's ingress is .1 on the client link and .2 on
        # inter-server links; the exit faces the destination as .1.
        if a == "client":
            links.append((a, "%s.2/30" % net, b, "%s.1/30" % net))
        else:
            links.append((a, "%s.1/30" % net, b, "%s.2/30" % net))
    return nodes, links


def endpoints(chain_hops, topology_hops):
    exit_ip = "192.0.2.1" if topology_hops == 1 else "198.51.100.2"
    return dict(
        relay="192.0.2.1:443" if chain_hops > 1 else None,
        middle="198.18.0.2:4445" if chain_hops == 3 else None,
        exit=exit_ip + (":4444" if chain_hops > 1 else ":443"),
    )


def routes(nodes, links):
    """Static routes so every node reaches every subnet along the chain."""
    out = []
    for i, node in enumerate(nodes):
        for j, (_, ip1, _, _ip2) in enumerate(links):
            if j in (i - 1, i):
                continue
            net = ip1.rsplit(".", 1)[0] + ".0/30"
            via = (links[i][3] if j > i else links[i - 1][1]).split("/")[0]
            out.append((node, net, via))
    return out


def disk_snapshot(directory):
    """Every file under a device's persistent state: name -> (size, mtime)."""
    return {
        str(f.relative_to(directory)): (f.lstat().st_size, f.lstat().st_mtime_ns)
        for f in directory.rglob("*")
        if f.is_file() or f.is_symlink()
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--mib", type=int, default=32)
    p.add_argument("--hops", type=int, choices=[1, 2, 3], default=2)
    p.add_argument(
        "--switch-to",
        type=int,
        choices=[1, 2, 3],
        help="then re-enroll the same devices into this chain (enroll --replace) and test again",
    )
    p.add_argument("--rate", choices=list(RATE_CLASSES), default="metered", help="the chain's signed rate class")
    p.add_argument(
        "--shape-idle",
        type=float,
        default=0,
        help="record the first link's shape: this many idle seconds, then the transfer (0: off)",
    )
    p.add_argument("--max-rate-change", type=float, help="fail if the transfer changes the wire rate by more than this")
    p.add_argument("--rate-bytes", type=int)
    p.add_argument("--rate-packets", type=int)
    p.add_argument("--mode", choices=["tunnel", "carrier"], default="tunnel")
    p.add_argument("--min-mbit", type=float, help="fail below this throughput (regression gate)")
    a = p.parse_args()
    os.umask(0o077)
    lab_guard()
    if {r["ifname"] for r in json.loads(run("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    state = a.state.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    rates = {k: v for k, v in [("bytes_per_second", a.rate_bytes), ("packets_per_second", a.rate_packets)] if v}
    phases = [a.hops] + ([a.switch_to] if a.switch_to else [])
    top = max(phases)
    nodes, links = topology(top)
    lab_dns = dict(upstream="203.0.113.2:8530", server_name="dns.lab.internal")  # no queries are made
    ep = endpoints(a.hops, top)
    lab_setup(
        state,
        ep["relay"],
        ep["exit"],
        destinations=["203.0.113.0/30"],
        rates=rates or None,
        rate=a.rate,
        hops=a.hops,
        middle=ep["middle"],
        dns=lab_dns,
    )
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "size=64m", "tmpfs", "/run")
    # The fresh /run hides resolved's stub file; when /etc/resolv.conf is a symlink
    # into /run (Ubuntu runners), `avpn run` needs its target to bind the private resolver.
    target = Path("/etc/resolv.conf").resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text("")
    namespaces = ["av-" + n for n in nodes]
    procs = []
    results = []

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
            [
                sys.executable,
                ROOT / "tools/avpnctl.py",
                "--state",
                state / role,
                "--bin-dir",
                ROOT / "target/release",
                "--lab",
                "connect",
            ],
            role,
        )

    def app(argv, timeout=60, check=True):
        return run(
            "ip",
            "netns",
            "exec",
            "av-client",
            sys.executable,
            ROOT / "tools/avpnctl.py",
            "--state",
            state / "client",
            "--lab",
            "run",
            "--",
            *argv,
            check=check,
            timeout=timeout,
        )

    def stop_chain(roles, managers):
        for role in roles:
            path = runtime_dir(state / role) / "status.json"
            if path.exists():
                for child in json.loads(path.read_text()).get("children", {}).values():
                    try:
                        if identity_of(child["pid"]) == child["identity"]:
                            os.kill(child["pid"], signal.SIGTERM)
                    except ProcessLookupError:
                        pass
        for m in managers:
            if m.poll() is None:
                m.terminate()
            try:
                m.wait(timeout=10)
            except subprocess.TimeoutExpired:
                m.kill()

    marker = os.urandom(16).hex()
    ingress = {}
    try:
        for ns in namespaces:
            run("ip", "netns", "add", ns)
            run("ip", "-n", ns, "link", "set", "lo", "up")
        for k, (n1, ip1, n2, ip2) in enumerate(links):
            d1, d2 = "l%da" % k, "l%db" % k
            run("ip", "link", "add", d1, "type", "veth", "peer", "name", d2)
            for ns, dev, addr in [("av-" + n1, d1, ip1), ("av-" + n2, d2, ip2)]:
                run("ip", "link", "set", dev, "netns", ns)
                run("ip", "-n", ns, "address", "add", addr, "dev", dev)
                run("ip", "-n", ns, "link", "set", dev, "up")
            if n2 != "destination":
                ingress[n2] = d2  # server's link from its predecessor
        for node, net, via in routes(nodes, links):
            run("ip", "-n", "av-" + node, "route", "add", net, "via", via)
        for ns in namespaces[1:-1]:
            run("ip", "netns", "exec", ns, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        if a.mode == "tunnel":
            spawn("av-destination", [sys.executable, "-c", SINK, "203.0.113.2", 5300], "sink")
        for phase, hops in enumerate(phases):
            chain = CHAINS[hops]
            if phase:
                # Re-sign a new chain from the SAME device keys and switch every device.
                ep = endpoints(hops, top)
                roles = ["client"] + chain
                for role in roles:
                    if not (state / role).exists():
                        from managed_profile import request

                        request(role, state / role, "none")
                from managed_profile import create, enroll, SoftwareOperator
                from keyguard import read_private

                ops = state / ("operator-%d" % phase)
                create(
                    ops,
                    {r: read_private(state / r / "request.json") for r in roles},
                    ep["relay"],
                    ep["exit"],
                    SoftwareOperator(state / "operator-keys"),
                    destinations=["203.0.113.0/30"],
                    rates=rates or None,
                    rate=a.rate,
                    hops=hops,
                    middle=ep["middle"],
                    dns=lab_dns,
                )
                keys_before = (state / "client" / "wireguard-key.bin").read_bytes()[:32]
                for role in roles:
                    enroll(
                        ops / (role + ".avpn"),
                        ops / "operator.pub",
                        state / role,
                        replace=(state / role / "profile.json").exists(),
                    )
                assert (state / "client" / "wireguard-key.bin").read_bytes()[:32] == keys_before, (
                    "device key changed on switch"
                )
            observers = [
                (
                    s,
                    spawn(
                        "av-" + s,
                        [
                            sys.executable,
                            "-c",
                            OBSERVE,
                            ingress[s],
                            marker,
                            state / ("observe-%d-%s.json" % (phase, s)),
                        ],
                        "observe-" + s,
                    ),
                )
                for s in chain
            ]
            if a.shape_idle:
                shape_file = state / ("shape-%d.bin" % phase)
                observers.append(
                    (
                        "shape",
                        spawn("av-" + chain[0], [sys.executable, "-c", SHAPE, ingress[chain[0]], shape_file], "shape"),
                    )
                )
            # Mullvad-style: servers must write nothing persistent while carrying traffic.
            before_disk = {role: disk_snapshot(state / role) for role in ["client"] + chain}
            managers = [manager(s) for s in reversed(chain)]
            client = manager("client")
            managers.append(client)
            # Readiness only (not the measured quantity); slow shared runners need margin,
            # and the measured time-to-online makes any slowness visible.
            started = time.monotonic()
            end = started + 90
            while time.monotonic() < end:
                if client.poll() is not None:
                    raise RuntimeError("client supervisor exited")
                probe = app(["ping", "-n", "-c", "1", "-W", "1", "10.77.0.1"], check=False)
                if probe.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("tunnel did not come up within 90 s; last app error: " + probe.stderr[-800:])
            online_seconds = round(time.monotonic() - started, 2)
            marks = {}
            if a.shape_idle:
                time.sleep(2)  # let the stream settle after the readiness pings
                marks["idle"] = (time.time(), time.time() + a.shape_idle)
                time.sleep(a.shape_idle)
            started_transfer = time.time()
            if a.mode == "carrier":
                sink = spawn("av-" + chain[0], [sys.executable, "-c", SINK, "10.78.0.1", 5300], "sink-carrier")
                time.sleep(0.5)
                out = run(
                    "ip",
                    "netns",
                    "exec",
                    "av-client",
                    sys.executable,
                    "-c",
                    SEND,
                    "10.78.0.1",
                    5300,
                    a.mib * 1048576,
                    marker,
                    timeout=300,
                ).stdout
                sink.terminate()
            else:
                time.sleep(0.5)
                out = app(
                    [sys.executable, "-c", SEND, "203.0.113.2", 5300, a.mib * 1048576, marker], timeout=300
                ).stdout
            r = json.loads(out)
            # The sender's clock ends after the sink's digest; trim 0.5 s at both ends.
            marks["transfer"] = (started_transfer + 0.5, time.time() - 0.5)
            audit = {}
            for server, proc in observers:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=5)
                if server == "shape":
                    continue
                audit[server] = json.loads((state / ("observe-%d-%s.json" % (phase, server))).read_text())
            if a.shape_idle:
                r["shape"] = shape_report(shape_file, marks)
            changed = {
                role: sorted(k for k, v in disk_snapshot(state / role).items() if before_disk[role].get(k) != v)
                for role in ["client"] + chain
            }
            leaked = []
            for role in chain:
                for f in (state / role).rglob("*"):
                    if f.is_file() and not f.is_symlink():
                        b = f.read_bytes()
                        if CLIENT_IP.encode() in b or bytes.fromhex(marker) in b or marker.encode() in b:
                            leaked.append(role + "/" + f.name)
            disk = dict(
                server_files_written=[r + "/" + k for r in chain for k in changed[r]],
                client_files_written=changed["client"],
                client_ip_or_payload_in_server_state=leaked,
            )
            first = chain[0]
            onion = dict(
                marker_seen_by_any_server=any(v["marker_seen"] for v in audit.values()),
                client_ip_seen_beyond_first_hop=any(CLIENT_IP in v["sources"] for s, v in audit.items() if s != first),
                first_hop_sees_client=CLIENT_IP in audit.get(first, {}).get("sources", []),
                ingress_sources={s: v["sources"] for s, v in audit.items()},
            )
            r.update(
                hops=hops,
                mode=a.mode,
                rate=a.rate,
                rates=rates or "profile default",
                online_seconds=online_seconds,
                onion=onion,
                switched=bool(phase),
                disk=disk,
            )
            results.append(r)
            print(json.dumps(r), flush=True)
            if not r["sha256_verified"]:
                raise SystemExit("transfer corrupted")
            if a.mode == "tunnel" and (
                onion["marker_seen_by_any_server"]
                or onion["client_ip_seen_beyond_first_hop"]
                or not onion["first_hop_sees_client"]
            ):
                raise SystemExit("onion property violated: " + json.dumps(onion))
            if (
                disk["server_files_written"]
                or disk["client_ip_or_payload_in_server_state"]
                or set(disk["client_files_written"]) - {"network-before.json"}
            ):
                raise SystemExit("persistent data written during a session: " + json.dumps(disk))
            if a.max_rate_change is not None and any(v["rate_change"] > a.max_rate_change for v in r["shape"].values()):
                raise SystemExit("the transfer changed the wire rate: " + json.dumps(r["shape"]))
            if a.min_mbit is not None and r["mbit_s"] < a.min_mbit:
                raise SystemExit("throughput %.2f Mbit/s below floor %.1f" % (r["mbit_s"], a.min_mbit))
            if phase + 1 < len(phases):
                stop_chain(["client"] + chain, managers)
                blocked = app(["ping", "-n", "-c", "1", "-W", "1", "10.77.0.1"], check=False).returncode != 0
                if not blocked:
                    raise SystemExit("traffic escaped while switching chains")
                results[-1]["blocked_while_switching"] = True
        (state / "RESULT.json").write_text(json.dumps(results if len(results) > 1 else results[0], indent=2) + "\n")
    except BaseException:
        # Diagnostics for CI, where the namespaces vanish with the job.
        for log in sorted(state.glob("*.log")) + [
            f
            for role in ["client", "relay", "middle", "exit"]
            if (state / role).exists()
            for f in sorted(runtime_dir(state / role).glob("*.lab.log"))
        ]:
            print("==== " + log.name, file=sys.stderr)
            print(log.read_text(errors="replace")[-2500:], file=sys.stderr)
        for role in ["client", "relay", "middle", "exit"]:
            st = runtime_dir(state / role) / "status.json"
            if st.exists():
                print("==== status " + role + ": " + st.read_text(), file=sys.stderr)
        raise
    finally:
        for role in ["client", "relay", "middle", "exit"]:
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
        for ns in ["avpn-app", *reversed(namespaces)]:
            run("ip", "netns", "del", ns, check=False)
        shutil.rmtree(state / "operator-keys", ignore_errors=True)


if __name__ == "__main__":
    main()

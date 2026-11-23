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

--cpu-probe N measures the busy-CPU leak instead of a transfer: the client's processes
are pinned to --client-cpus, busy loops load those cores on a random balanced schedule
of N windows while the tunnel idles, and the client's wire packets per window on the
first link are scored against the schedule: packets per window, and the spread and
largest gap between them (catch-up restores the count but not the timing); each with
AUC, permutation p-value and a shuffled-label control. Set CPVPN_CATCH_UP_MS in the environment to measure the catch-up variant.
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
from cypherpunkctl import lab_guard, identity_of, runtime_dir  # noqa: E402

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


def segment_size(records):
    """The link's cell payload: the most common UDP payload of packets that fit one MTU."""
    import collections

    small = collections.Counter(n - 28 for _, n, _ in records if 28 < n <= 1500)
    return small.most_common(1)[0][0] if small else WIRE_SEGMENT


def shape_window(records, a, b, outgoing, segment=WIRE_SEGMENT):
    """Wire shape in [a, b): packets/s, the 100 ms bins' spread, and the IPv4 sizes seen."""
    import collections

    # GSO hands the observer up to 64 KiB super-frames on veth: count wire segments
    # (one per `segment` bytes of UDP payload), and sizes per segment.
    def parts(n):
        return max(1, round((n - 28) / segment))

    window = [(t, n) for t, n, o in records if a <= t < b and o == outgoing]
    times = [t for t, n in window for _ in range(parts(n))]
    sizes = collections.Counter(28 + (n - 28) // parts(n) for t, n in window for _ in range(parts(n)))
    bins = collections.Counter(int((t - a) * 10) for t in times)
    counts = [bins.get(i, 0) for i in range(int((b - a) * 10))]
    return dict(
        seconds=round(b - a, 2),
        packets_per_second=round(len(times) / (b - a), 1),
        bin_100ms_min=min(counts) if counts else 0,
        bin_100ms_max=max(counts) if counts else 0,
        sizes=dict(sizes.most_common(4)),
    )


def load_schedule(windows, rng):
    """A random on/off CPU-load schedule with as many on as off windows (balanced, so
    the score cannot come from an imbalance), shuffled by `rng`."""
    plan = [1] * (windows // 2) + [0] * (windows - windows // 2)
    rng.shuffle(plan)
    return plan


def window_counts(records, start, window, n, outgoing=0, segment=WIRE_SEGMENT, trim=0.1):
    """Wire packets per schedule window on the observed link (GSO super-frames counted as
    the segments they carry). The first and last `trim` of each window are left out, so
    the time a load takes to start or stop is not scored."""

    def parts(size):
        return max(1, round((size - 28) / segment))

    counts = [0] * n
    for t, size, o in records:
        if o != outgoing:
            continue
        k, offset = divmod(t - start, window)
        k = int(k)
        if 0 <= k < n and trim * window <= offset < (1 - trim) * window:
            counts[k] += parts(size)
    return counts


def window_timing(records, start, window, n, outgoing=0, segment=WIRE_SEGMENT, trim=0.1):
    """Per schedule window: the spread of gaps between the client's wire packets and the
    largest gap. Catch-up keeps the count per window but sends missed packets late and
    bunched, so on a busy CPU the timing leaks even when the count does not."""
    import statistics

    def parts(size):
        return max(1, round((size - 28) / segment))

    times = [[] for _ in range(n)]
    for t, size, o in records:
        if o != outgoing:
            continue
        k, offset = divmod(t - start, window)
        k = int(k)
        if 0 <= k < n and trim * window <= offset < (1 - trim) * window:
            times[k].extend([t] * parts(size))
    out = []
    for ts in times:
        ts.sort()
        gaps = [b - a for a, b in itertools.pairwise(ts)] or [0.0]
        out.append(dict(gap_sd=statistics.pstdev(gaps), max_gap=max(gaps)))
    return out


def _auc(on, off):
    """P(an 'on' window has fewer packets than an 'off' one), ties counted half: 0.5 is
    chance, 1.0 means every loaded window sent less (the busy-CPU leak)."""
    if not on or not off:
        return 0.5
    wins = sum((a < b) + 0.5 * (a == b) for a in on for b in off)
    return wins / (len(on) * len(off))


def separation(values, schedule, rng, permutations=2000):
    """(AUC, permutation p) for how well per-window `values` tell loaded windows from idle
    ones. AUC is P(a loaded window's value is the smaller), 0.5 is chance; p tests
    |AUC - 0.5| against `permutations` shuffles of the schedule."""
    on = [v for v, s in zip(values, schedule, strict=True) if s]
    off = [v for v, s in zip(values, schedule, strict=True) if not s]
    auc = _auc(on, off)
    observed = abs(auc - 0.5)
    labels = list(schedule)
    extreme = 0
    controls = []
    for _ in range(permutations):
        rng.shuffle(labels)
        a = _auc(
            [v for v, s in zip(values, labels, strict=True) if s],
            [v for v, s in zip(values, labels, strict=True) if not s],
        )
        controls.append(a)
        extreme += abs(a - 0.5) >= observed
    return auc, (extreme + 1) / (permutations + 1), sum(controls) / len(controls) if controls else 0.5


def leak_score(counts, schedule, rng, permutations=2000, timing=None):
    """How well the CPU-load schedule shows on the wire, per window.

    Counts: the mean packets per window with and without load, the relative drop, AUC,
    permutation p and a shuffled-label control that must sit near 0.5. With `timing`
    (from window_timing), the same for the gap spread and the largest gap. `leak` is
    true when any feature separates the schedule at p < 0.01 / (number of features)."""
    on = [c for c, s in zip(counts, schedule, strict=True) if s]
    off = [c for c, s in zip(counts, schedule, strict=True) if not s]
    auc, p, control = separation(counts, schedule, rng, permutations)
    mean_on = sum(on) / len(on) if on else 0.0
    mean_off = sum(off) / len(off) if off else 0.0
    out = dict(
        windows=len(counts),
        packets_per_window_loaded=round(mean_on, 1),
        packets_per_window_idle=round(mean_off, 1),
        drop_under_load=round((mean_off - mean_on) / mean_off, 4) if mean_off else 0.0,
        auc=round(auc, 4),
        p_value=round(p, 4),
        control_auc_mean=round(control, 4),
    )
    features = {"count": p}
    for name in ("gap_sd", "max_gap") if timing else ():
        f_auc, f_p, f_control = separation([w[name] for w in timing], schedule, rng, permutations)
        out[name] = dict(auc=round(f_auc, 4), p_value=round(f_p, 4), control_auc_mean=round(f_control, 4))
        features[name] = f_p
    out["leak"] = min(features.values()) < 0.01 / len(features)
    return out


def shape_report(path, marks):
    """Idle vs transfer shape in both directions of the observed link (towards the hop
    that observes it, and back)."""
    import struct

    raw = path.read_bytes()
    records = [struct.unpack_from("<dHB", raw, i) for i in range(0, len(raw) - len(raw) % 11, 11)]
    segment = segment_size(records)
    out = {"segment_bytes": segment}
    for direction, outgoing in [("towards_hop", 0), ("from_hop", 1)]:
        idle = shape_window(records, *marks["idle"], outgoing, segment)
        busy = shape_window(records, *marks["transfer"], outgoing, segment)
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


LOAD = "while True:\n    pass\n"

CLOCK_FIELDS = ("fed", "decoys", "skipped", "late", "late_max_us", "unslotted")


def clock_windows(trace, start_mono, window, n):
    """The wire clock's 100 ms trace (rows of at_100ms, fed, decoys, skipped, late,
    late_max_us, unslotted on CLOCK_MONOTONIC) summed per probe window, the largest
    lateness kept as a maximum."""
    out = {k: [0] * n for k in CLOCK_FIELDS}
    for row in trace:
        k = int((row[0] * 0.1 - start_mono) // window)
        if 0 <= k < n:
            for name, value in zip(CLOCK_FIELDS, row[1:], strict=True):
                out[name][k] = max(out[name][k], value) if name == "late_max_us" else out[name][k] + value
    return out


def cpu_probe(a, observers, shape_file, hops, online_seconds):
    """Load the client's cores on a random schedule while the tunnel idles; score how
    well the client's wire packet counts per window reveal the schedule."""
    import random
    import struct

    rng = random.Random(a.seed) if a.seed is not None else random.SystemRandom()
    schedule = load_schedule(a.cpu_probe, rng)
    time.sleep(2)  # let the stream settle after the readiness pings
    loads = []
    start = time.time()
    start_mono = time.monotonic()
    try:
        for k, loaded in enumerate(schedule):
            if loaded and not loads:
                loads = [
                    subprocess.Popen(["taskset", "-c", a.client_cpus, sys.executable, "-c", LOAD])
                    for _ in range(a.load_procs)
                ]
            elif not loaded and loads:
                for x in loads:
                    x.kill()
                    x.wait()
                loads = []
            time.sleep(max(0.0, start + (k + 1) * a.probe_window - time.time()))
    finally:
        for x in loads:
            x.kill()
            x.wait()
    for server, proc in observers:
        if server == "shape":
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
    clock = None
    if os.environ.get("CPVPN_WIRE_CLOCK_PPS"):
        time.sleep(1.5)  # the cloak writes its status once a second
        status = runtime_dir(shape_file.parent / "client", create=False) / "cloak-status.json"
        try:
            c = json.loads(status.read_text()).get("clock") or {}
        except (OSError, ValueError):
            c = {}
        if c:
            clock = {k: c[k] for k in (*CLOCK_FIELDS, "slot_queue_max") if k in c}
            clock["per_window"] = clock_windows(c.get("trace", []), start_mono, a.probe_window, len(schedule))
    carriers = carrier_health(shape_file.parent)
    raw = shape_file.read_bytes()
    records = [struct.unpack_from("<dHB", raw, i) for i in range(0, len(raw) - len(raw) % 11, 11)]
    segment = segment_size(records)
    counts = window_counts(records, start, a.probe_window, len(schedule), segment=segment)
    timing = window_timing(records, start, a.probe_window, len(schedule), segment=segment)
    score = leak_score(counts, schedule, random.Random(0), timing=timing)
    return dict(
        probe="busy-CPU leak",
        hops=hops,
        rate=a.rate,
        catch_up_ms=int(os.environ.get("CPVPN_CATCH_UP_MS", "0") or 0),
        wire_clock_pps=float(os.environ.get("CPVPN_WIRE_CLOCK_PPS", "0") or 0),
        wire_clock_lookahead_ms=int(os.environ.get("CPVPN_WIRE_CLOCK_MS", "30") or 30),
        # Declared, not detected: the lab cannot see another user's open files.
        pm_qos_us_declared=os.environ.get("CPVPN_PROBE_PM_QOS_US"),
        client_cpus=a.client_cpus,
        server_cpus=a.server_cpus,
        load_procs=a.load_procs,
        window_seconds=a.probe_window,
        online_seconds=online_seconds,
        host_cpus=os.cpu_count(),
        start=start,
        start_monotonic=start_mono,
        schedule=schedule,
        clock=clock,
        carriers=carriers,
        counts=counts,
        score=score,
        leak=score["leak"],
    )


def carrier_health(state):
    """Both directions of every cloak in the chain, and the client's reconnects: a probe
    that only watches the client's wire would miss a tunnel whose downstream has died
    (the real-website re-run's clock passes lost 96% of the downstream that way)."""
    out = {}
    for role_dir in sorted(p for p in state.iterdir() if p.is_dir()):
        rt = runtime_dir(role_dir, create=False)
        try:
            c = json.loads((rt / "cloak-status.json").read_text())
        except (OSError, ValueError, RuntimeError):
            continue
        out[role_dir.name] = {k: c.get(k) for k in ("role", "sent", "received", "dropped", "sessions")}
    try:
        log = (runtime_dir(state / "client", create=False) / "core.lab.log").read_text(errors="replace")
        out["client_reconnects"] = log.count('"reconnecting"')
    except (OSError, RuntimeError):
        pass
    return out


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
        help="record a link's shape: this many idle seconds, then the transfer (0: off)",
    )
    p.add_argument(
        "--shape-link",
        choices=["first", "last"],
        default="first",
        help="which link to observe: client to first hop, or the link into the exit",
    )
    p.add_argument("--max-rate-change", type=float, help="fail if the transfer changes the wire rate by more than this")
    p.add_argument("--rate-bytes", type=int)
    p.add_argument("--rate-packets", type=int)
    p.add_argument("--mode", choices=["tunnel", "carrier"], default="tunnel")
    p.add_argument("--min-mbit", type=float, help="fail below this throughput (regression gate)")
    p.add_argument(
        "--underlay-mtu",
        type=int,
        help="MTU of the client's link to the first hop; below 1448 the cloak must carry the tunnel over TCP",
    )
    p.add_argument("--cpu-probe", type=int, default=0, help="busy-CPU leak probe: windows (0: off)")
    p.add_argument("--probe-window", type=float, default=1.0, help="seconds per probe window")
    p.add_argument("--load-procs", type=int, default=2, help="busy loops while a window is loaded")
    p.add_argument("--client-cpus", default="0,1", help="cores for the client (and the load)")
    p.add_argument("--server-cpus", default="2,3", help="cores for the servers")
    p.add_argument("--seed", type=int, help="fix the probe schedule (default: random)")
    a = p.parse_args()
    if a.cpu_probe and a.cpu_probe < 10:
        p.error("--cpu-probe needs at least 10 windows")
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
    # into /run (Ubuntu runners), `cypherpunk run` needs its target to bind the private resolver.
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
                list(map(str, args)),
                preexec_fn=lambda: os.setns(fd, os.CLONE_NEWNET),
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        finally:
            os.close(fd)
        procs.append(x)
        return x

    def manager(role):
        pin = []
        if a.cpu_probe:
            # The data plane inherits the controller's affinity: the client's on the
            # loaded cores, the servers' off them.
            pin = ["taskset", "-c", a.client_cpus if role == "client" else a.server_cpus]
        return spawn(
            "av-" + role,
            [
                *pin,
                sys.executable,
                ROOT / "tools/cypherpunkctl.py",
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
            ROOT / "tools/cypherpunkctl.py",
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
            if k == 0 and os.environ.get("CPVPN_WIRE_CLOCK_PPS"):
                # The wire clock's departure times are honoured by the fq qdisc only.
                tc = shutil.which("tc") or "/usr/sbin/tc"
                for ns, dev in [("av-" + n1, d1), ("av-" + n2, d2)]:  # client upstream, first hop downstream
                    run("ip", "netns", "exec", ns, tc, "qdisc", "replace", "dev", dev, "root", "fq",
                        "flow_limit", "10000", "limit", "20000")  # fmt: skip
            if k == 0 and a.underlay_mtu:
                for ns, dev in [("av-" + n1, d1), ("av-" + n2, d2)]:
                    run("ip", "-n", ns, "link", "set", dev, "mtu", str(a.underlay_mtu))
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
                        ops / (role + ".cpvpn"),
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
            if a.shape_idle or a.cpu_probe:
                hop = chain[0] if a.shape_link == "first" or a.cpu_probe else chain[-1]
                shape_file = state / ("shape-%d.bin" % phase)
                observers.append(
                    (
                        "shape",
                        spawn("av-" + hop, [sys.executable, "-c", SHAPE, ingress[hop], shape_file], "shape"),
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
            if a.cpu_probe:
                results.append(cpu_probe(a, observers, shape_file, hops, online_seconds))
                print(json.dumps(results[-1]), flush=True)
                break
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
            if a.underlay_mtu:
                cloak = json.loads((runtime_dir(state / first, create=False) / "cloak-status.json").read_text())
                r["underlay"] = dict(mtu=a.underlay_mtu, first_hop_cloak=cloak)
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
            if a.underlay_mtu and a.underlay_mtu < 1448 and not r["underlay"]["first_hop_cloak"].get("tcp_sessions"):
                raise SystemExit("a path below 1448 bytes was crossed without the TCP carrier")
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
            if a.max_rate_change is not None and any(
                v["rate_change"] > a.max_rate_change for v in r["shape"].values() if isinstance(v, dict)
            ):
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
        for ns in ["cpvpn-app", *reversed(namespaces)]:
            run("ip", "netns", "del", ns, check=False)
        shutil.rmtree(state / "operator-keys", ignore_errors=True)


if __name__ == "__main__":
    main()

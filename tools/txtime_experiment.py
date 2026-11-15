#!/usr/bin/env python3
"""Does kernel-paced departure (SO_TXTIME + fq) make a constant-rate stream's timing
immune to a busy CPU? An isolated experiment for the busy-CPU leak's fix.

Run as `unshare -Urnm python tools/txtime_experiment.py ...` (one user namespace with
its own network: no host change, no extra UIDs). A sender on --sender-cpus emits UDP
packets on a fixed grid (4,000/s, the `fast` class) over a veth pair to a receiver in
another namespace on other cores, which records kernel receive timestamps. Busy loops
load the sender's cores on a random balanced schedule, and the per-window packet count,
gap spread and largest gap are scored against it exactly as `throughput_bench.py
--cpu-probe` scores the real carrier.

Modes:
- naive:  sleep until each tick and send; ticks missed while descheduled are skipped
          (today's shaper: "skipped, never burst").
- txtime: hand packets to the kernel up to --lookahead ms ahead, each stamped with its
          departure time (SO_TXTIME, CLOCK_MONOTONIC); the fq qdisc on the sending
          interface releases each one on time whatever the sender's thread is doing.
          Only a stall longer than the look-ahead can still leave a gap.
"""

import argparse
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from throughput_bench import leak_score, load_schedule, window_counts, window_timing  # noqa: E402

SO_TXTIME = 61
SCM_TXTIME = 61
SO_TIMESTAMPNS = 35
PAYLOAD = 1392  # UDP payload of a 1420-byte IPv4 packet, the carrier's cell size
SENDER, RECEIVER = "10.9.0.1", "10.9.0.2"
TC = "/usr/sbin/tc"

SEND = r"""
import socket, struct, sys, time
mode, rate, lookahead, seconds = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]) / 1000, float(sys.argv[4])
SO_TXTIME = SCM_TXTIME = 61
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.9.0.1", 0))
dest = ("10.9.0.2", 9000)
payload = bytes(1392)
step = 1 / rate
if mode == "txtime":
    s.setsockopt(socket.SOL_SOCKET, SO_TXTIME, struct.pack("iI", time.CLOCK_MONOTONIC, 0))
start = time.monotonic() + 0.2
end = start + seconds
k = 0
while True:
    now = time.monotonic()
    if now >= end:
        break
    due = start + k * step
    if due < now - (step if mode == "naive" else 0):
        # Behind the grid: skip the missed ticks (never burst), as the shaper does.
        k = int((now - start) / step) + 1
        continue
    if mode == "naive":
        if due > now:
            time.sleep(due - now)
        s.sendto(payload, dest)
        k += 1
    else:
        while due < now + lookahead:
            s.sendmsg([payload], [(socket.SOL_SOCKET, SCM_TXTIME, struct.pack("Q", int(due * 1e9)))], 0, dest)
            k += 1
            due = start + k * step
        time.sleep(0.002)
"""

RECEIVE = r"""
import signal, socket, struct, sys
SO_TIMESTAMPNS = 35
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((sys.argv[1], 0))
s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
s.settimeout(0.2)
out = open(sys.argv[2], "wb")
def stop(*_):
    out.close(); sys.exit(0)
signal.signal(signal.SIGTERM, stop)
while True:
    try:
        b, anc, _, _ = s.recvmsg(64, socket.CMSG_SPACE(16))
    except socket.timeout:
        continue
    if len(b) < 34 or b[12:14] != b"\x08\x00" or b[23] != 17:
        continue
    for level, kind, data in anc:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            sec, nsec = struct.unpack("qq", data[:16])
            out.write(struct.pack("<dHB", sec + nsec / 1e9, int.from_bytes(b[16:18], "big"), 0))
"""


def run(*args, check=True):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, check=check)


def network():
    """A veth pair from this namespace (sender) to a second one (receiver), fq on the
    sender's side with room for the look-ahead's queue."""
    run("mount", "-t", "tmpfs", "none", "/run")
    os.makedirs("/run/netns", exist_ok=True)
    run("ip", "netns", "add", "rx")
    run("ip", "link", "add", "veth_s", "type", "veth", "peer", "name", "veth_r")
    run("ip", "link", "set", "veth_r", "netns", "rx")
    run("ip", "address", "add", SENDER + "/30", "dev", "veth_s")
    run("ip", "-n", "rx", "address", "add", RECEIVER + "/30", "dev", "veth_r")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "set", "veth_s", "up")
    run("ip", "-n", "rx", "link", "set", "lo", "up")
    run("ip", "-n", "rx", "link", "set", "veth_r", "up")
    run(TC, "qdisc", "replace", "dev", "veth_s", "root", "fq", "flow_limit", "10000", "limit", "20000")


def one_run(a, mode, seed):
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    schedule = load_schedule(a.windows, rng)
    capture = Path(a.out_dir) / ("capture-%s-%d.bin" % (mode, os.getpid() + int(time.time())))
    rx = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "rx",
            "taskset",
            "-c",
            a.receiver_cpus,
            sys.executable,
            "-c",
            RECEIVE,
            "veth_r",
            str(capture),
        ]
    )
    time.sleep(1)
    seconds = a.windows * a.window + 3
    tx = subprocess.Popen(
        ["taskset", "-c", a.sender_cpus, sys.executable, "-c", SEND, mode, str(a.rate), str(a.lookahead), str(seconds)]
    )
    # Keep-awake control: busy loops on the sender's cores for the whole run, so the
    # cores never idle and their power state does not change with the load schedule.
    awake = [
        subprocess.Popen(["taskset", "-c", a.sender_cpus, sys.executable, "-c", "while True:\n    pass\n"])
        for _ in range(a.background_procs)
    ]
    time.sleep(1.5)  # the sender's grid starts 0.2 s after it does; let it settle
    start = time.time()
    loads = []
    try:
        for k, loaded in enumerate(schedule):
            if loaded and not loads:
                loads = [
                    subprocess.Popen(["taskset", "-c", a.sender_cpus, sys.executable, "-c", "while True:\n    pass\n"])
                    for _ in range(a.load_procs)
                ]
            elif not loaded and loads:
                for x in loads:
                    x.kill()
                    x.wait()
                loads = []
            time.sleep(max(0.0, start + (k + 1) * a.window - time.time()))
    finally:
        for x in loads:
            x.kill()
            x.wait()
    tx.wait()
    for x in awake:
        x.kill()
        x.wait()
    rx.terminate()
    rx.wait()
    raw = capture.read_bytes()
    records = [struct.unpack_from("<dHB", raw, i) for i in range(0, len(raw) - len(raw) % 11, 11)]
    capture.unlink()
    counts = window_counts(records, start, a.window, len(schedule), segment=PAYLOAD)
    timing = window_timing(records, start, a.window, len(schedule), segment=PAYLOAD)
    score = leak_score(counts, schedule, random.Random(0), timing=timing)
    return dict(
        mode=mode,
        lookahead_ms=a.lookahead if mode == "txtime" else None,
        background_procs=a.background_procs,
        pm_qos_us=a.pm_qos_us,
        packets=len(records),
        score=score,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--modes", default="naive,txtime")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--windows", type=int, default=60)
    p.add_argument("--window", type=float, default=1.0)
    p.add_argument("--rate", type=float, default=4000.0, help="packets per second")
    p.add_argument("--lookahead", type=float, default=30.0, help="ms handed to the kernel ahead (txtime)")
    p.add_argument("--load-procs", type=int, default=2)
    p.add_argument(
        "--background-procs",
        type=int,
        default=0,
        help="busy loops on the sender's cores for the whole run (keeps them out of deep idle states)",
    )
    p.add_argument("--sender-cpus", default="0,1")
    p.add_argument("--receiver-cpus", default="4,5")
    p.add_argument(
        "--pm-qos-us",
        type=int,
        help="hold /dev/cpu_dma_latency at this many microseconds for the whole experiment, so CPUs stay "
        "out of deep idle states (needs real root: sudo unshare -nm ...)",
    )
    p.add_argument("--seed", type=int)
    p.add_argument("--out-dir", default="/tmp")
    p.add_argument("--json", type=Path)
    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("run inside `unshare -Urnm` (or, for --pm-qos-us, `sudo unshare -nm`): its own network namespace")
    network()
    qos = None
    if a.pm_qos_us is not None:
        # Held open for the whole experiment; the kernel drops the request when it closes.
        try:
            qos = os.open("/dev/cpu_dma_latency", os.O_WRONLY)
        except PermissionError:
            sys.exit("--pm-qos-us needs real root: sudo unshare -nm ... (a user namespace cannot open it)")
        os.write(qos, struct.pack("i", a.pm_qos_us))
    results = []
    for k in range(a.runs):
        for mode in a.modes.split(","):
            r = one_run(a, mode, None if a.seed is None else a.seed + k)
            s = r["score"]
            print(
                "%-6s run %d: packets %d  count AUC %.3f p %.4f  gap_sd AUC %.3f p %.4f  max_gap AUC %.3f p %.4f  leak %s"
                % (mode, k + 1, r["packets"], s["auc"], s["p_value"], s["gap_sd"]["auc"], s["gap_sd"]["p_value"],
                   s["max_gap"]["auc"], s["max_gap"]["p_value"], s["leak"]),
                flush=True,
            )  # fmt: skip
            results.append(r)
    if qos is not None:
        os.close(qos)
    if a.json:
        a.json.write_text(json.dumps(dict(settings=vars(a) | {"json": str(a.json)}, runs=results), indent=2) + "\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Real nested-PQ transport, routed exit and hostile-relay tests in disposable namespaces.

Run only through: unshare -Urnm python3 tools/namespace_test.py --state /new/path
Refuses host root and any inherited external network interface. No host routing changes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time

from provision import provision

ROOT = Path(__file__).resolve().parents[1]
NAMES = ["av-client", "av-relay", "av-exit", "av-app", "av-destination"]


def run(*args, check=True, timeout=15, input=None):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout, input=input)


def stop(p):
    if p is not None and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    a = p.parse_args()
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.getuid() != 0 or len(mapping) != 3 or mapping[0] != "0" or mapping[1] == "0" or mapping[2] != "1":
        raise RuntimeError("requires an unprivileged isolated user namespace")
    if {r["ifname"] for r in json.loads(run("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("requires a fresh network namespace with only loopback")
    binary = ROOT / "target/release/advanced-vpn"
    state = a.state.resolve()
    configs = provision(state, "192.0.2.1:4433", "198.51.100.1:4444", adversarial=True)
    configs["exit"]["listen"] = "198.51.100.2:4444"
    for role in ["client", "exit"]:
        configs[role]["destinations"] = ["203.0.113.0/30"]
    for role, c in configs.items():
        (state / role / "config.json").write_text(json.dumps(c))
    (state / "proxy-mode").write_text("normal")
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "size=8m", "tmpfs", "/run")
    processes = []
    logs = []

    def spawn(ns, cmd, name):
        f = (state / (name + ".log")).open("w")
        logs.append(f)
        proc = subprocess.Popen(["ip", "netns", "exec", ns, *map(str, cmd)], stdout=f, stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc

    def config_path(role):
        return state / role / "config.json"

    def server(role):
        proc = spawn("av-" + role, [binary, "--config", config_path(role)], role + str(len(processes)))
        time.sleep(0.15)
        if proc.poll() is not None:
            raise RuntimeError("server startup failed")
        return proc

    def client(path=None):
        return spawn(
            "av-app",
            [
                sys.executable,
                ROOT / "tools/lab_peer.py",
                "launch",
                "--state",
                state,
                "--binary",
                binary,
                "--config",
                path or config_path("client"),
            ],
            "client" + str(len(processes)),
        )

    def ping(ok=True, count=1, size=56, dest="10.77.0.1"):
        r = run(
            "ip",
            "netns",
            "exec",
            "av-app",
            "ping",
            "-n",
            "-c",
            str(count),
            "-i",
            "0.03",
            "-W",
            "1",
            "-M",
            "do",
            "-s",
            str(size),
            dest,
            check=False,
            timeout=max(6, count + 3),
        )
        if ok and r.returncode:
            raise RuntimeError("tunnel ping failed: " + r.stdout + r.stderr)
        if not ok and r.returncode == 0:
            raise RuntimeError("traffic escaped a failed tunnel")
        return r.stdout

    def wait_tunnel(proc):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("client exited")
            r = run(
                "ip", "netns", "exec", "av-app", "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1", check=False, timeout=3
            )
            if r.returncode == 0:
                return
            time.sleep(0.1)
        raise RuntimeError("authenticated tunnel deadline exceeded")

    def echo(marker, timeout=2):
        code = (
            "import socket,time,json;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout("
            + str(timeout)
            + ");b="
            + repr(marker)
            + ';t=time.monotonic_ns();s.sendto(b,("203.0.113.2",45991));r=s.recv(65536);assert r==b;print(json.dumps({"rtt_ms":(time.monotonic_ns()-t)/1e6}))'
        )
        return run("ip", "netns", "exec", "av-app", sys.executable, "-c", code, check=False, timeout=timeout + 3)

    try:
        for ns in NAMES:
            run("ip", "netns", "add", ns)
            run("ip", "-n", ns, "link", "set", "lo", "up")
        links = [
            ("av-client", "c0", "192.0.2.2/30", "av-relay", "r0", "192.0.2.1/30"),
            ("av-relay", "r1", "198.51.100.1/30", "av-exit", "e0", "198.51.100.2/30"),
            ("av-exit", "e1", "203.0.113.1/30", "av-destination", "d0", "203.0.113.2/30"),
        ]
        for n1, d1, ip1, n2, d2, ip2 in links:
            run("ip", "link", "add", d1, "type", "veth", "peer", "name", d2)
            for ns, dev, addr in [(n1, d1, ip1), (n2, d2, ip2)]:
                run("ip", "link", "set", dev, "netns", ns)
                run("ip", "-n", ns, "addr", "add", addr, "dev", dev)
                run("ip", "-n", ns, "link", "set", dev, "up")
        for ns, addr in [("av-app", "10.77.0.2/32"), ("av-exit", "10.77.0.1/32")]:
            run("ip", "netns", "exec", ns, "ip", "tuntap", "add", "dev", "avpn0", "mode", "tun")
            run("ip", "-n", ns, "addr", "add", addr, "dev", "avpn0")
            run("ip", "-n", ns, "link", "set", "avpn0", "mtu", "1280", "up")
        run("ip", "-n", "av-app", "route", "add", "default", "dev", "avpn0")
        run("ip", "-n", "av-exit", "route", "add", "10.77.0.2/32", "dev", "avpn0")
        # Owned exit forwards to a controlled destination. Use actual masquerade when available.
        run("ip", "netns", "exec", "av-exit", "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        nat = run(
            "ip",
            "netns",
            "exec",
            "av-exit",
            "/usr/sbin/nft",
            "-f",
            "-",
            input='table ip avpn { chain post { type nat hook postrouting priority srcnat; ip saddr 10.77.0.2 oifname "e1" masquerade; }\n}\n',
            check=False,
        )
        if nat.returncode:
            raise RuntimeError("owned exit NAT setup failed: " + nat.stderr)
        relay = server("relay")
        exit_proc = server("exit")
        _proxy = spawn("av-relay", [sys.executable, ROOT / "tools/lab_peer.py", "proxy", "--state", state], "proxy")
        _echo_proc = spawn(
            "av-destination", [sys.executable, ROOT / "tools/lab_peer.py", "echo", "--state", state], "echo"
        )
        for role in configs:
            run(binary, "--config", config_path(role), "--check")
        c = client()
        wait_tunnel(c)
        ping(size=1252)
        ping(ok=False, size=1253)
        marker = b"AVPN-PRIVATE-" + os.urandom(24).hex().encode()
        r = echo(marker)
        assert r.returncode == 0, r.stderr
        assert json.loads((state / "echo.json").read_text())["marker_seen"]
        raw = ping(count=100)
        values = [float(line.split("time=")[1].split()[0]) for line in raw.splitlines() if "time=" in line]
        assert len(values) == 100
        (state / "proxy-mode").write_text("replay")
        for n in range(5):
            assert echo(marker + str(n).encode()).returncode == 0
        time.sleep(0.2)
        replay = json.loads((state / "echo.json").read_text())
        assert replay["duplicates"] == 0
        (state / "proxy-mode").write_text("tamper")
        assert echo(marker + b"tampered", timeout=0.5).returncode != 0
        (state / "proxy-mode").write_text("normal")
        assert echo(marker + b"restored").returncode == 0
        stream_proc = spawn(
            "av-destination", [sys.executable, ROOT / "tools/lab_peer.py", "stream", "--state", state], "stream"
        )
        time.sleep(0.1)
        code = 'import socket,time,hashlib,json;s=socket.create_connection(("203.0.113.2",45992),3);s.settimeout(20);b=b"AVPN-TCP-PAYLOAD"*65536+b"x"*65536;b=b[:1048576];assert len(b)==1048576;t=time.monotonic();s.sendall(b);r=b""\nwhile len(r)<64:\n part=s.recv(64-len(r))\n if not part:raise RuntimeError("short digest")\n r+=part\nassert r.decode()==hashlib.sha256(b).hexdigest();print(json.dumps({"bytes":len(b),"seconds":time.monotonic()-t,"sha256_verified":True}))'
        streamed = run("ip", "netns", "exec", "av-app", sys.executable, "-c", code, timeout=25)
        stream = json.loads(streamed.stdout)
        stream_proc.wait(timeout=3)
        rss = {}
        for name, proc in [("client", c), ("relay", relay), ("exit", exit_proc)]:
            rows = Path("/proc/" + str(proc.pid) + "/status").read_text().splitlines()
            rss[name] = int(next(row for row in rows if row.startswith("VmRSS:")).split()[1])
        captured = (state / "relay-ciphertext.bin").read_bytes()
        assert marker not in captured
        # Physical relay interfaces must not contain an inner TUN or private inner address.
        relay_links = json.loads(run("ip", "-n", "av-relay", "-j", "address").stdout)
        assert all(r["ifname"] != "avpn0" for r in relay_links)
        assert "10.77." not in json.dumps(relay_links)
        (state / "proxy-mode").write_text("drop")
        ping(ok=False)
        assert echo(marker + b"dropped", timeout=0.5).returncode != 0
        (state / "proxy-mode").write_text("normal")
        wait_tunnel(c)
        stop(relay)
        ping(ok=False)
        relay = server("relay")
        wait_tunnel(c)
        stop(c)
        ping(ok=False)
        # Fresh servers for each rejection, with genuine protocol handshakes.
        negatives = {}
        for label in ["unlisted", "untrusted", "expired", "classical", "wrong_inner_pin"]:
            stop(exit_proc)
            exit_proc = server("exit")
            stop(relay)
            relay = server("relay")
            bad = json.loads(json.dumps(configs["client"]))
            if label == "wrong_inner_pin":
                bad["inner"]["peer_sha256"] = "0" * 64
            else:
                bad["outer"]["key"] = str(state / "tests" / (label + "-key.der"))
                bad["outer"]["cert"] = str(state / "tests" / (label + "-cert.der"))
            path = state / "tests" / (label + ".json")
            path.write_text(json.dumps(bad))
            os.chmod(path, 0o600)
            rejected = client(path)
            time.sleep(2)
            ping(ok=False)
            stop(rejected)
            negatives[label] = True
        # Reset the rejection fixture before the authorized reconnect phase.
        stop(exit_proc)
        exit_proc = server("exit")
        stop(relay)
        relay = server("relay")
        c = client()
        wait_tunnel(c)
        assert echo(marker + b"after-rejections").returncode == 0
        # Cert revocation takes effect by changing the exact pin and restarting the peer.
        stop(relay)
        revoked = dict(configs["relay"])
        revoked["outer"] = dict(revoked["outer"], peer_sha256="0" * 64)
        config_path("relay").write_text(json.dumps(revoked))
        relay = server("relay")
        ping(ok=False)
        stop(c)
        stop(relay)
        config_path("relay").write_text(json.dumps(configs["relay"]))
        relay = server("relay")
        c = client()
        wait_tunnel(c)
        apps = json.loads(run("ip", "-n", "av-app", "-j", "link").stdout)
        assert {r["ifname"] for r in apps} == {"lo", "avpn0"}
        result = dict(
            schema=1,
            profile="nested QUIC DATAGRAM, TLS1.3 hybrid X25519MLKEM768, AES256GCM",
            isolated_namespaces=True,
            host_routes_changed=False,
            owned_exit_forwarding=True,
            owned_exit_nat=nat.returncode == 0,
            inner_mtu=1280,
            mtu_boundary_passed=True,
            relay_capture_bytes=len(captured),
            private_marker_absent_at_relay=True,
            private_marker_seen_at_destination=True,
            duplicate_ciphertext_replay_rejected=True,
            tampered_ciphertext_rejected=True,
            fail_closed_on_drop_and_relay_loss=True,
            reconnect_after_relay_restart=True,
            revoked_peer_rejected=True,
            negative_identities=negatives,
            app_has_only_loopback_and_tun=True,
            ping_samples=len(values),
            rtt_ms=dict(p50=statistics.median(values), p95=sorted(values)[94], p99=sorted(values)[98]),
            tcp_stream=stream,
            rss_kib=rss,
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            wan_tested=False,
            hardware_tested=False,
        )
        (state / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    finally:
        for proc in reversed(processes):
            stop(proc)
        for f in logs:
            f.close()
        for ns in reversed(NAMES):
            run("ip", "netns", "del", ns, check=False)


if __name__ == "__main__":
    main()

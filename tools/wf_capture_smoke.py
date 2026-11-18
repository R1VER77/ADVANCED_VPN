#!/usr/bin/env python3
"""Prove the metadata recorder's interface boundary in a fresh private namespace."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def run(out):
    """Flood loopback during startup; retain only a synthetic frame on the selected veth."""
    from avpnctl import lab_guard

    lab_guard()
    links = json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "link"], text=True))
    if {link["ifname"] for link in links} != {"lo"}:
        raise RuntimeError("requires a fresh network namespace containing only loopback")
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["/usr/sbin/ip", "link", "add", "cap0", "type", "veth", "peer", "name", "peer0"], check=True)
    for name in ("cap0", "peer0"):
        Path(f"/proc/sys/net/ipv6/conf/{name}/disable_ipv6").write_text("1")
        subprocess.run(["/usr/sbin/ip", "link", "set", name, "up"], check=True)
    stop = threading.Event()
    sent = []

    def flood():
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client,
        ):
            server.bind(("127.0.0.1", 0))
            server.settimeout(1)
            target = server.getsockname()
            while not stop.is_set():
                client.sendto(b"unrelated-loopback-payload", target)
                server.recvfrom(1024)
                sent.append(1)
                stop.wait(0.0001)

    noise = threading.Thread(target=flood, daemon=True)
    noise.start()
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "tools/wf_capture.py"),
            "cap0",
            str(out / "packets.bin"),
            "--peer",
            "192.0.2.1",
            "--port",
            "443",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                _, error = process.communicate(timeout=5)
                raise RuntimeError("recorder exited before readiness: " + error.decode(errors="replace")[-1500:])
            if (out / "capture.json").exists():
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("recorder readiness timed out")
        payload = b"never-persist-this-test-payload"
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            28 + len(payload),
            1,
            0,
            64,
            17,
            0,
            socket.inet_aton("192.0.2.2"),
            socket.inet_aton("192.0.2.1"),
        )
        frame = (
            bytes.fromhex("ffffffffffff0200000000020800")
            + header
            + struct.pack("!HHHH", 1000, 443, 8 + len(payload), 0)
            + payload
        )
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sender:
            sender.bind(("peer0", 3))
            sender.send(frame)
        time.sleep(0.2)
        process.terminate()
        _, error = process.communicate(timeout=5)
        if process.returncode != 0:
            raise RuntimeError("recorder failed: " + error.decode(errors="replace")[-300:])
        report = json.loads((out / "capture.json").read_text())
        binary = (out / "packets.bin").read_bytes()
        if len(binary) != 12 or report["records"] != 1 or report["drops"] or not report["clean_stop"] or not sent:
            raise AssertionError(dict(capture=report, bytes=len(binary), loopback_packets=len(sent)))
        timestamp, signed_length = struct.unpack("<di", binary)
        if not report["started"] <= timestamp <= report["stopped"] or signed_length != -(28 + len(payload)):
            raise AssertionError("kernel timestamp or direction/length mismatch")
        if payload in binary or b"unrelated-loopback-payload" in binary or report["unexpected_outgoing"]:
            raise AssertionError("metadata recorder violated its interface/content boundary")
        result = dict(
            schema=1,
            passed=True,
            recorded_packets=1,
            loopback_packets_excluded=len(sent),
            drops=0,
            payload_persisted=False,
            timestamp_source=report["timestamp_source"],
            physical_hardware=False,
            source_sha256={
                name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in ("tools/wf_capture.py", "tools/wf_capture_smoke.py")
            },
        )
        (out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return result
    finally:
        stop.set()
        noise.join(2)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    """Run the recorder proof without external interfaces, production keys or internet access."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    run(args.out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Synthetic-only helpers for namespace_test.py. Never a production service."""

import argparse
import fcntl
import json
import os
import select
import socket
import struct
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["proxy", "echo", "launch", "stream"])
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--binary")
    p.add_argument("--config")
    a = p.parse_args()
    os.umask(0o077)
    if a.role == "launch":
        # Called in the app netns. Only the pre-opened TUN crosses into the underlay netns.
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", b"avpn0", 0x1001))
        os.set_inheritable(fd, True)
        ns = os.open("/run/netns/av-client", os.O_RDONLY)
        os.setns(ns, 0)
        os.close(ns)
        os.execv(a.binary, [a.binary, "--config", a.config, "--tun-fd", str(fd)])
    elif a.role == "stream":
        import hashlib

        s = socket.socket()
        s.bind(("203.0.113.2", 45992))
        s.listen(1)
        c, _ = s.accept()
        c.settimeout(20)
        h = hashlib.sha256()
        n = 0
        while n < 1048576:
            b = c.recv(min(65536, 1048576 - n))
            if not b:
                raise RuntimeError("short test stream")
            h.update(b)
            n += len(b)
        c.sendall(h.hexdigest().encode())
        c.close()
        s.close()
    elif a.role == "echo":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("203.0.113.2", 45991))
        s.settimeout(0.2)
        seen = set()
        duplicates = 0
        while True:
            try:
                b, addr = s.recvfrom(65536)
            except socket.timeout:
                continue
            if b in seen:
                duplicates += 1
            seen.add(b)
            s.sendto(b, addr)
            (a.state / "echo.json").write_text(
                json.dumps(dict(unique=len(seen), duplicates=duplicates, marker_seen=b.startswith(b"AVPN-PRIVATE-")))
            )
    else:
        # Deliberately hostile relay-side forwarder. Captures inner QUIC ciphertext only.
        front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        front.bind(("198.51.100.1", 4444))
        back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        back.connect(("198.51.100.2", 4444))
        peer = None
        count = 0
        with (a.state / "relay-ciphertext.bin").open("xb") as capture:
            while True:
                readable, _, _ = select.select([front, back], [], [], 0.2)
                for s in readable:
                    if s is front:
                        b, peer = front.recvfrom(65536)
                        if peer is None:
                            continue
                        target = back
                    else:
                        b = back.recv(65536)
                        if peer is None:
                            continue
                        target = front
                    if capture.tell() + len(b) + 4 < 16 * 1024 * 1024:
                        capture.write(struct.pack("!I", len(b)) + b)
                        capture.flush()
                    count += 1
                    mode = (a.state / "proxy-mode").read_text().strip()
                    if mode == "drop":
                        continue
                    if mode == "tamper" and len(b) > 40:
                        b = b[:-1] + bytes([b[-1] ^ 1])

                    def send():
                        if target is front:
                            target.sendto(b, peer)
                        else:
                            target.send(b)

                    send()
                    if mode == "replay":
                        send()
                    if count % 10 == 0:
                        (a.state / "proxy.json").write_text(json.dumps(dict(datagrams=count)))


if __name__ == "__main__":
    main()

"""Synthetic peers and outer-wire observations for managed_test.py only."""

import argparse
import json
import socket
import ssl
from pathlib import Path


def read_exact(s, n):
    b = b""
    while len(b) < n:
        part = s.recv(n - len(b))
        if not part:
            raise ValueError("short frame")
        b += part
    return b


def answer(query):
    off = 12
    while query[off]:
        off += query[off] + 1
    off += 1
    qtype = int.from_bytes(query[off : off + 2], "big")
    end = off + 4
    response = query[:2] + b"\x81\x80" + b"\0\1" + (b"\0\1" if qtype == 1 else b"\0\0") + b"\0\0\0\0" + query[12:end]
    if qtype == 1:
        response += b"\xc0\x0c\0\1\0\1\0\0\0\x1e\0\4" + bytes([203, 0, 113, 2])
    return response


def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["dot", "observer", "echo"])
    p.add_argument("--state", type=Path, required=True)
    a = p.parse_args()
    if a.role == "dot":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(a.state / "dns-cert.pem", a.state / "dns-key.pem")
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("203.0.113.2", 8530))
        s.listen(16)
        count = 0
        while True:
            c, _ = s.accept()
            c.settimeout(3)
            try:
                with context.wrap_socket(c, server_side=True) as tls:
                    n = int.from_bytes(read_exact(tls, 2), "big")
                    q = read_exact(tls, n)
                    b = answer(q)
                    tls.sendall(len(b).to_bytes(2, "big") + b)
                    count += 1
                    (a.state / "dot.json").write_text(json.dumps(dict(queries=count, tls=True)))
            except (OSError, ValueError):
                c.close()
    elif a.role == "echo":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("203.0.113.2", 45991))
        while True:
            b, peer = s.recvfrom(65536)
            s.sendto(b, peer)
    else:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.bind(("r0", 0))
        s.settimeout(0.2)
        sizes = []
        n = 0
        with (a.state / "physical-capture.bin").open("xb") as f:
            while True:
                try:
                    b = s.recv(65536)
                except socket.timeout:
                    continue
                if len(b) < 42 or b[12:14] != b"\x08\x00" or b[23] != 17:
                    continue
                ihl = (b[14] & 15) * 4
                udp = 14 + ihl
                payload = b[udp + 8 :]
                # Empty transport keepalives are control traffic, not IP data.
                if len(payload) > 32 and payload[:4] == b"\4\0\0\0":
                    sizes.append(len(payload))
                n += 1
                if f.tell() < 16 * 1024 * 1024:
                    f.write(b)
                    f.flush()
                (a.state / "physical.json").write_text(
                    json.dumps(dict(packets=n, wireguard_data_packets=len(sizes), data_sizes=sorted(set(sizes))))
                )


if __name__ == "__main__":
    main()

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


# A first-party name that resolves through a tracker's domain (CNAME cloaking).
CLOAKED = {"cloaked.test": "edge.tracker.test"}


def qname_of(query):
    labels, off = [], 12
    while query[off]:
        labels.append(query[off + 1 : off + 1 + query[off]].decode().lower())
        off += query[off] + 1
    return ".".join(labels), off + 1


def answer(query):
    name, off = qname_of(query)
    qtype = int.from_bytes(query[off : off + 2], "big")
    end = off + 4
    a_record = b"\0\1\0\1\0\0\0\x1e\0\4" + bytes([203, 0, 113, 2])
    if qtype == 1 and name in CLOAKED:
        target = b"".join(bytes([len(x)]) + x.encode() for x in CLOAKED[name].split(".")) + b"\0"
        head = query[:2] + b"\x81\x80\0\1\0\2\0\0\0\0" + query[12:end]
        cname = b"\xc0\x0c\0\5\0\1\0\0\0\x1e" + len(target).to_bytes(2, "big") + target
        target_at = len(head) + len(cname) - len(target)
        return head + cname + (0xC000 | target_at).to_bytes(2, "big") + a_record
    response = query[:2] + b"\x81\x80" + b"\0\1" + (b"\0\1" if qtype == 1 else b"\0\0") + b"\0\0\0\0" + query[12:end]
    if qtype == 1:
        response += b"\xc0\x0c" + a_record
    return response


STRANGER = bytes([192, 0, 2, 4])


def quic_sizes(iface, out):
    """Record UDP payload sizes on `iface` to `out` (inter-server QUIC links carry raw
    QUIC, not WireGuard). With constant-cell padding the data-bearing packets collapse
    to one size; without it they vary with the inner packet."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((iface, 0))
    s.settimeout(0.2)
    sizes = []
    while True:
        try:
            b = s.recv(65536)
        except socket.timeout:
            out.write_text(json.dumps(sizes))
            continue
        if len(b) < 42 or b[12:14] != b"\x08\x00" or b[23] != 17:
            continue
        ihl = (b[14] & 15) * 4
        sizes.append(len(b[14 + ihl + 8 :]))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["dot", "observer", "echo", "quicsizes"])
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--iface")
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    if a.role == "quicsizes":
        quic_sizes(a.iface, a.out)
        return
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
        n = wireguard = quic = 0
        with (a.state / "physical-capture.bin").open("xb") as f:
            while True:
                try:
                    b = s.recv(65536)
                except socket.timeout:
                    continue
                if len(b) < 42 or b[12:14] != b"\x08\x00" or b[23] != 17:
                    continue
                # The first-hop probe's stranger (192.0.2.4) is not part of the tunnel.
                if STRANGER in (b[26:30], b[30:34]):
                    continue
                ihl = (b[14] & 15) * 4
                udp = 14 + ihl
                payload = b[udp + 8 :]
                # The carrier runs behind the HTTP/3 cloak: no WireGuard message may be on
                # the wire. Its type bytes (0x01-0x04, then three zeros) can never start a
                # QUIC packet, whose first byte always has the fixed bit (0x40) set.
                if len(payload) >= 32 and payload[0] in (1, 2, 3, 4) and payload[1:4] == b"\0\0\0":
                    wireguard += 1
                elif payload and payload[0] & 0x40:
                    quic += 1
                    if len(payload) > 1300:
                        sizes.append(len(payload))
                n += 1
                if f.tell() < 16 * 1024 * 1024:
                    f.write(b)
                    f.flush()
                (a.state / "physical.json").write_text(
                    json.dumps(
                        dict(
                            packets=n,
                            wireguard_messages=wireguard,
                            quic_packets=quic,
                            outer_sizes={str(k): sizes.count(k) for k in sorted(set(sizes))},
                        )
                    )
                )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Lab-only metadata recorder with kernel timestamps, loss counters and an escape audit.

Runs inside the collection's private network/user namespace, never on a host link.
Packet contents are inspected transiently for network headers and never persisted.
The binary record remains <float64 seconds, int32 signed IP length>.
"""

import argparse
import collections
import ipaddress
import json
import os
from pathlib import Path
import resource
import signal
import struct
import time

from wf_pcap import Capture

RECORD = struct.Struct("<di")


def network_metadata(frame, wire_length=None):
    """Return bounded IP header metadata; no payload or unbounded extension parsing."""
    if len(frame) < 14:
        return dict(kind="malformed")
    ether = int.from_bytes(frame[12:14], "big")
    available = len(frame) if wire_length is None else wire_length
    if ether == 0x0806:
        return dict(kind="arp")
    ip = memoryview(frame)[14:]
    if ether == 0x0800 and len(ip) >= 20 and ip[0] >> 4 == 4:
        header = (ip[0] & 15) * 4
        length = int.from_bytes(ip[2:4], "big")
        if header < 20 or length < header or len(ip) < header or available < length + 14:
            return dict(kind="malformed")
        fragmented = bool(int.from_bytes(ip[6:8], "big") & 0x3FFF)
        hop_limit = ip[8]
        protocol, src, dst = (
            ip[9],
            str(ipaddress.IPv4Address(bytes(ip[12:16]))),
            str(ipaddress.IPv4Address(bytes(ip[16:20]))),
        )
    elif ether == 0x86DD and len(ip) >= 40 and ip[0] >> 4 == 6:
        header, length, fragmented = 40, 40 + int.from_bytes(ip[4:6], "big"), False
        if available < length + 14:
            return dict(kind="malformed")
        hop_limit = ip[7]
        protocol, src, dst = (
            ip[6],
            str(ipaddress.IPv6Address(bytes(ip[8:24]))),
            str(ipaddress.IPv6Address(bytes(ip[24:40]))),
        )
    else:
        return dict(kind="other", ether_type=ether)
    ports = protocol in (6, 17) and not fragmented and length >= header + 4 and len(ip) >= header + 4
    return dict(
        kind="ip",
        length=length,
        protocol=protocol,
        src=src,
        dst=dst,
        source_port=int.from_bytes(ip[header : header + 2], "big") if ports else None,
        destination_port=int.from_bytes(ip[header + 2 : header + 4], "big") if ports else None,
        fragmented=fragmented,
        hop_limit=hop_limit,
        icmp_type=ip[header] if protocol in (1, 58) and len(ip) >= header + 2 else None,
        icmp_code=ip[header + 1] if protocol in (1, 58) and len(ip) >= header + 2 else None,
    )


def permitted_outgoing(meta, peer, port):
    """A narrow underlay allowlist; unexpected metadata is a potential escape, not a payload verdict."""
    return (
        meta["kind"] == "arp"
        or (
            meta["kind"] == "ip"
            and meta["dst"] == peer
            and meta["protocol"] in (6, 17)
            and meta["destination_port"] == port
            and not meta["fragmented"]
        )
        or (
            meta["kind"] == "ip"
            and meta["protocol"] == 58
            and meta["dst"] == "ff02::2"
            and meta.get("icmp_type") == 133
            and meta.get("icmp_code") == 0
            and meta.get("hop_limit") == 255
            and meta["length"] in (48, 56)
            and (meta["src"] == "::" or ipaddress.ip_address(meta["src"]).is_link_local)
        )
    )


def write_json(path, value):
    """Replace the recorder-owned report, with no partially readable JSON generation."""
    temporary = path.with_name(path.name + ".next")
    with temporary.open("w") as stream:
        json.dump(value, stream, sort_keys=True, allow_nan=False)
        stream.write("\n")
    os.replace(temporary, path)


def record(interface, output, peer, port):
    """Record one isolated interface until SIGTERM; publish heartbeat and final drop audit."""
    from avpnctl import lab_guard

    lab_guard()
    peer = str(ipaddress.ip_address(peer))
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    report = output.with_name("capture.json")
    heartbeats = output.with_name("capture-heartbeats.jsonl")
    audit = collections.Counter()
    bad_examples = []
    start_wall, start_mono = time.time(), time.monotonic()
    status = dict(
        schema=1,
        interface=interface,
        pid=os.getpid(),
        started=start_wall,
        started_monotonic=start_mono,
        timestamp_source="linux_pcap_host_ns",
        peer=peer,
        port=port,
        packets=0,
        records=0,
        drops=0,
        unexpected_outgoing=0,
        malformed=0,
        max_heartbeat_gap=0.0,
        max_clock_step=0.0,
        clean_stop=False,
    )
    last = start_mono
    with Capture(interface) as capture:
        status.update(
            capture_backend=capture.version,
            capture_library=str(capture.path),
            buffer_requested_per_direction=64 * 1024**2,
            snaplen=96,
            packet_count_semantics="sum of both direction-handle deliveries; may count packets twice",
        )
        with output.open("xb", buffering=1024 * 1024) as stream, heartbeats.open("x") as beats:

            def heartbeat(final=False):
                nonlocal last
                wall, mono = time.time(), time.monotonic()
                status["packets"], status["drops"] = capture.stats()
                status.update(
                    updated=wall,
                    updated_monotonic=mono,
                    stopped=wall if final else None,
                    clean_stop=final,
                    audit_counts=dict(audit),
                    unexpected_examples=bad_examples,
                )
                status["max_heartbeat_gap"] = max(status["max_heartbeat_gap"], mono - last)
                status["max_clock_step"] = max(status["max_clock_step"], abs((wall - start_wall) - (mono - start_mono)))
                stream.flush()
                beats.write(
                    json.dumps(dict(time=wall, monotonic=mono, records=status["records"], drops=status["drops"])) + "\n"
                )
                beats.flush()
                write_json(report, status)
                last = mono

            heartbeat()
            try:
                while not stopped:
                    for timestamp, frame, length, outgoing in capture.next_batch():
                        meta = network_metadata(frame, length)
                        audit[meta["kind"]] += 1
                        if meta["kind"] == "malformed":
                            status["malformed"] += 1
                        if outgoing and not permitted_outgoing(meta, peer, port):
                            status["unexpected_outgoing"] += 1
                            if len(bad_examples) < 16:
                                bad_examples.append(dict(time=timestamp, **meta))
                        if meta["kind"] == "ip":
                            stream.write(RECORD.pack(timestamp, meta["length"] if outgoing else -meta["length"]))
                            status["records"] += 1
                    if time.monotonic() - last >= 0.5:
                        heartbeat()
            finally:
                heartbeat(final=stopped)
                os.fsync(stream.fileno())
                os.fsync(beats.fileno())
    return status


def main():
    """Record lab traffic without persisting packet contents."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("interface")
    p.add_argument("output", type=Path)
    p.add_argument("--peer", required=True)
    p.add_argument("--port", type=int, required=True)
    a = p.parse_args()
    if not 1 <= a.port <= 65535:
        p.error("invalid underlay port")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    record(a.interface, a.output, a.peer, a.port)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Tests for the dual-stack leak suite (tools/ipv6_leak_suite.py).

The STUN and DNS codecs are exercised by REAL network I/O against
in-process UDP servers on loopback (real sockets, real requests, real
parseable responses); the verdict logic is exercised end-to-end through
the same transport the production suite uses. The WebRTC grammar is
exercised with RFC 8445-shaped candidate fixtures, including the
leaking ones.
"""

import socket
import struct
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ipv6_leak_suite as suite  # noqa: E402


# ---------------------------------------------------------------- helpers


def free_port(family):
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        return s.getsockname()


class StunServer(threading.Thread):
    """A real RFC 5389 binding responder: echoes the transaction id and
    returns the XOR-MAPPED-ADDRESS of the observed source, exactly as
    production STUN servers do."""

    def __init__(self, family, mapped_host, mapped_port, host=None):
        super().__init__(daemon=True)
        self.family = family
        self.mapped = (mapped_host, mapped_port)
        self.addr = free_port(family)
        if host is not None:
            self.addr = (host, self.addr[1])
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append(peer)
            if len(data) < suite.STUN_HEADER.size:
                continue
            msg_type, _, cookie, txid = suite.STUN_HEADER.unpack_from(data, 0)
            if msg_type != 0x0001 or cookie != suite.STUN_MAGIC_COOKIE:
                continue
            self.sock.sendto(self._binding_success(txid, peer), peer)

    def _binding_success(self, txid, peer):
        host, port = self.mapped
        family = 0x01 if ":" not in host else 0x02
        packed = socket.inet_pton(socket.AF_INET if family == 1 else socket.AF_INET6, host)
        if family == 0x01:
            port ^= suite.STUN_MAGIC_COOKIE >> 16
            packed = bytes(b ^ m for b, m in zip(packed, struct.pack(">I", suite.STUN_MAGIC_COOKIE), strict=True))
        else:
            port ^= suite.STUN_MAGIC_COOKIE >> 16
            mask = struct.pack(">I", suite.STUN_MAGIC_COOKIE) + b"\x00" * 12
            packed = bytes(b ^ m for b, m in zip(packed, mask, strict=True))
        attr = struct.pack(">BBH", 0, family, port) + packed
        body = suite.STUN_ATTR_HEADER.pack(0x0020, len(attr)) + attr
        return suite.STUN_HEADER.pack(0x0101, len(body), suite.STUN_MAGIC_COOKIE, txid) + body

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


class DnsServer(threading.Thread):
    """A real minimal DNS responder: echoes id and question, answers A
    and AAAA queries for the probe name with configured records."""

    PROBE = "dual-stack.example"

    def __init__(self, family, a_records, aaaa_records, host=None):
        super().__init__(daemon=True)
        self.family = family
        self.a = a_records
        self.aaaa = aaaa_records
        self.addr = (host or ("127.0.0.1" if family == socket.AF_INET else "::1"), free_port(family)[1])
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sock.settimeout(0.2)
        self.queries = []
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            self.queries.append(data)
            try:
                self.sock.sendto(self._answer(data), peer)
            except (ValueError, OSError):
                continue

    def _answer(self, data):
        if len(data) < 12:
            raise ValueError("short")
        qid, flags, qd, *_ = struct.unpack_from(">HHHHHH", data, 0)
        if (flags & 0x8000) or qd != 1:
            raise ValueError("not a query")
        offset = 12
        labels = []
        while data[offset]:
            length = data[offset]
            labels.append(data[offset + 1 : offset + 1 + length].decode("ascii"))
            offset += 1 + length
        offset += 1  # root
        qtype, qclass = struct.unpack_from(">HH", data, offset)
        if ".".join(labels) != self.PROBE:
            raise ValueError("unknown name")
        if qtype == 1:
            rdata = b"".join(socket.inet_aton(a) for a in self.a)
            count = len(self.a)
        elif qtype == 28:
            rdata = b"".join(socket.inet_pton(socket.AF_INET6, a) for a in self.aaaa)
            count = len(self.aaaa)
        else:
            raise ValueError("unknown qtype")
        question = data[12 : offset + 4]
        header = struct.pack(">HHHHHH", qid, 0x8180, 1, count, 0, 0)
        answers = b""
        name_ref = b"\xc0\x0c"
        for i in range(count):
            chunk = rdata[i * 4 : i * 4 + 4] if qtype == 1 else rdata[i * 16 : i * 16 + 16]
            answers += name_ref + struct.pack(">HHIH", qtype, 1, 60, len(chunk)) + chunk
        return header + question + answers

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


CLEAN_CANDIDATES = [
    "candidate:1 1 UDP 2130706431 192.168.1.42 54321 typ host",
    "candidate:2 1 UDP 1694498815 fd12:3456::42 54322 typ host",
    "candidate:3 1 UDP 16777215 203.0.113.99 54323 typ srflx",
]
LEAKING_CANDIDATES = CLEAN_CANDIDATES + [
    "candidate:4 1 UDP 16777215 2001:db8:1:2::99 54324 typ srflx",
]
TUNNEL_OWNED = ["2001:db8:1:2::99"]


class CodecTests(unittest.TestCase):
    def test_stun_round_trip_over_real_udp(self):
        server = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        server.start()
        try:
            observed = suite.UDPSocketTransport(timeout=1.0).stun(server.addr, socket.AF_INET)
            self.assertEqual(observed, "203.0.113.7:40000")
        finally:
            server.stop()

    def test_stun_v6_round_trip_over_real_udp(self):
        server = StunServer(socket.AF_INET6, "2001:db8::1", 40001)
        server.start()
        try:
            observed = suite.UDPSocketTransport(timeout=1.0).stun(server.addr, socket.AF_INET6)
            self.assertEqual(observed, "[2001:db8::1]:40001")
        finally:
            server.stop()

    def test_stun_rejects_foreign_transaction_id(self):
        request, txid = suite.stun_binding_request()
        other = bytes(b ^ 1 for b in txid)
        response = StunServer(socket.AF_INET, "203.0.113.7", 1)._binding_success(other, ("127.0.0.1", 5))
        with self.assertRaises(ValueError):
            suite.stun_parse_binding_response(response, txid)

    def test_dns_a_and_aaaa_over_real_udp(self):
        server = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=["2001:db8:8::10"])
        server.start()
        try:
            transport = suite.UDPSocketTransport(timeout=1.0)
            self.assertEqual(transport.resolve(server.addr, DnsServer.PROBE, 1), ["198.51.100.10"])
            self.assertEqual(transport.resolve(server.addr, DnsServer.PROBE, 28), ["2001:db8:8::10"])
        finally:
            server.stop()

    def test_dns_rejects_mismatched_id(self):
        query, qid = suite.dns_query("example.com", 1)
        other = struct.pack(">HHHHHH", qid ^ 1, 0x8180, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            suite.dns_parse_answer(other, qid, 1)
        _ = query

    def test_candidate_grammar(self):
        c = suite.parse_candidate("candidate:8 1 UDP 1694498815 2001:db8::1 5000 typ host")
        self.assertEqual(c.transport, "udp")
        self.assertEqual(c.address, "2001:db8::1")
        self.assertEqual(c.type, "host")
        with self.assertRaises(ValueError):
            suite.parse_candidate("candidate:1 1 UDP")
        with self.assertRaises(ValueError):
            suite.parse_candidate("candidate:1 1 GGP 1 10.0.0.1 1 typ host")

    def test_scope_classification(self):
        self.assertTrue(suite.is_global_v6("2001:db8::1"))
        self.assertTrue(suite.is_global_v6("2606:4700::1111"))
        self.assertFalse(suite.is_global_v6("fd12::1"))  # ULA
        self.assertFalse(suite.is_global_v6("fe80::1"))  # link-local
        self.assertFalse(suite.is_global_v6("::1"))
        self.assertFalse(suite.is_global_v6("not an address"))
        self.assertTrue(suite.is_ula_v6("fd00::5"))
        self.assertFalse(suite.is_ula_v6("2001:db8::5"))


class WebrtcLeakTests(unittest.TestCase):
    def test_no_leak_when_tunnel_owns_the_global(self):
        leaks = suite.webrtc_leak_addresses(LEAKING_CANDIDATES, set(TUNNEL_OWNED))
        self.assertEqual(leaks, [])

    def test_leak_when_tunnel_owns_nothing(self):
        leaks = suite.webrtc_leak_addresses(LEAKING_CANDIDATES, set())
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0]["address"], "2001:db8:1:2::99")

    def test_ula_and_v4_candidates_never_leak(self):
        leaks = suite.webrtc_leak_addresses(CLEAN_CANDIDATES, set())
        self.assertEqual(leaks, [])

    def test_unparseable_candidate_is_a_finding(self):
        leaks = suite.webrtc_leak_addresses(["candidate:1 1 UDP"], set())
        self.assertEqual(len(leaks), 1)
        self.assertIn("unparseable", leaks[0]["reason"])


class SuiteBlockedPostureTests(unittest.TestCase):
    """Today's posture: IPv6 blocked, v4-only tunnel. Every v6 traversal
    that succeeds is a leak; every refused v6 is a pass."""

    # a v6 probe target with no listener: UDP sends succeed, the reply
    # wait raises ConnectionRefusedError - the OS's own "refused as designed"
    REFUSED_V6 = ("::1", 9)

    def test_clean_blocked_environment_passes(self):
        dns = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=[])
        stun = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        dns.start()
        stun.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns.addr,
                stun_server=stun.addr,
                candidate_lines=CLEAN_CANDIDATES,
                tunnel_v6=[],
                posture="blocked",
                v6_probe=self.REFUSED_V6,
            )
        finally:
            dns.stop()
            stun.stop()
        self.assertEqual(record["overall"], "pass")
        by_check = {c["check"]: c for c in record["checks"]}
        self.assertEqual(by_check["dns"]["verdict"], "pass")
        self.assertEqual(by_check["stun"]["verdict"], "pass")
        self.assertEqual(by_check["webrtc"]["verdict"], "pass")
        self.assertEqual(by_check["ipv6"]["verdict"], "pass")
        self.assertEqual(record["posture"], "blocked")

    def test_v6_stun_success_is_a_leak(self):
        dns = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=[])
        stun = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        v6stun = StunServer(socket.AF_INET6, "2001:db8::1", 40001, host="::1")
        dns.start()
        stun.start()
        v6stun.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns.addr,
                stun_server=stun.addr,
                stun_server_v6=v6stun.addr,
                candidate_lines=CLEAN_CANDIDATES,
                tunnel_v6=[],
                posture="blocked",
                v6_probe=self.REFUSED_V6,
            )
        finally:
            dns.stop()
            stun.stop()
            v6stun.stop()
        by_check = {c["check"]: c for c in record["checks"]}
        self.assertEqual(by_check["stun"]["verdict"], "leak")
        self.assertIn("v6 STUN traversal succeeded", by_check["stun"]["detail"])
        self.assertEqual(record["overall"], "leak")

    def test_working_v6_probe_is_a_leak(self):
        # a v6 resolver that answers: under 'blocked', that success IS the leak
        dns = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=[])
        stun = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        dns6 = DnsServer(socket.AF_INET6, a_records=[], aaaa_records=["2001:db8:8::10"], host="::1")
        dns.start()
        stun.start()
        dns6.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns.addr,
                stun_server=stun.addr,
                candidate_lines=CLEAN_CANDIDATES,
                tunnel_v6=[],
                posture="blocked",
                v6_probe=dns6.addr,
                probe_name=DnsServer.PROBE,
            )
        finally:
            dns.stop()
            stun.stop()
            dns6.stop()
        by_check = {c["check"]: c for c in record["checks"]}
        self.assertEqual(by_check["ipv6"]["verdict"], "leak")
        self.assertEqual(record["overall"], "leak")

    def test_global_v6_candidate_is_a_leak(self):
        dns = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=[])
        stun = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        dns.start()
        stun.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns.addr,
                stun_server=stun.addr,
                candidate_lines=LEAKING_CANDIDATES,
                tunnel_v6=[],
                posture="blocked",
                v6_probe=self.REFUSED_V6,
            )
        finally:
            dns.stop()
            stun.stop()
        self.assertEqual(record["overall"], "leak")
        by_check = {c["check"]: c for c in record["checks"]}
        self.assertEqual(by_check["webrtc"]["verdict"], "leak")
        self.assertEqual(by_check["webrtc"]["evidence"]["leaking"][0]["address"], "2001:db8:1:2::99")


class SuiteTunneledPostureTests(unittest.TestCase):
    """The future gate: IPv6 tunneled. The only working global v6 must be
    the tunnel's own; DNS must answer AAAA; v6 must traverse."""

    def test_full_tunneled_pass_with_dual_stack_servers(self):
        dns4 = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=["2001:db8:8::10"])
        dns6 = DnsServer(socket.AF_INET6, a_records=[], aaaa_records=["2001:db8:8::10"], host="::1")
        stun = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        stun6 = StunServer(socket.AF_INET6, "2001:db8:8::1", 40001, host="::1")
        dns4.start()
        dns6.start()
        stun.start()
        stun6.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns4.addr,
                stun_server=stun.addr,
                stun_server_v6=stun6.addr,
                candidate_lines=CLEAN_CANDIDATES + ["candidate:4 1 UDP 16777215 2001:db8:8::99 54324 typ srflx"],
                tunnel_v6=["2001:db8:8::99"],
                posture="tunneled",
                v6_probe=dns6.addr,
                probe_name=DnsServer.PROBE,
            )
        finally:
            dns4.stop()
            dns6.stop()
            stun.stop()
            stun6.stop()
        by_check = {c["check"]: c for c in record["checks"]}
        self.assertEqual(by_check["dns"]["verdict"], "pass")
        self.assertEqual(by_check["stun"]["verdict"], "pass")
        self.assertEqual(by_check["webrtc"]["verdict"], "pass")
        # ipv6 probe talks to the v6 resolver: a real v6 exchange over ::1
        self.assertEqual(by_check["ipv6"]["verdict"], "pass")
        self.assertEqual(record["overall"], "pass")

    def test_tunneled_posture_fails_when_aaaa_is_silent(self):
        dns = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=[])
        stun = StunServer(socket.AF_INET, "203.0.113.7", 40000)
        dns.start()
        stun.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns.addr,
                stun_server=stun.addr,
                candidate_lines=CLEAN_CANDIDATES,
                tunnel_v6=[],
                posture="tunneled",
                probe_name=DnsServer.PROBE,
            )
        finally:
            dns.stop()
            stun.stop()
        by_check = {c["check"]: c for c in record["checks"]}
        self.assertEqual(by_check["dns"]["verdict"], "leak")
        self.assertIn("AAAA", by_check["dns"]["detail"])
        self.assertEqual(record["overall"], "leak")


class RecordShapeTests(unittest.TestCase):
    def test_posture_is_validated(self):
        with self.assertRaises(ValueError):
            suite.run_suite(
                suite.UDPSocketTransport(),
                resolver=("127.0.0.1", 53),
                stun_server=("127.0.0.1", 3478),
                candidate_lines=[],
                tunnel_v6=[],
                posture="sideways",
            )

    def test_record_carries_date_and_posture(self):
        dns = DnsServer(socket.AF_INET, a_records=["198.51.100.10"], aaaa_records=[])
        dns.start()
        try:
            record = suite.run_suite(
                suite.UDPSocketTransport(timeout=1.0),
                resolver=dns.addr,
                stun_server=("127.0.0.1", 3478),
                candidate_lines=[],
                tunnel_v6=[],
                posture="blocked",
                v6_probe=("::1", 9),
            )
        finally:
            dns.stop()
        self.assertTrue(record["checked"].startswith("20"))
        self.assertEqual(record["posture"], "blocked")
        self.assertEqual(len(record["checks"]), 4)
        self.assertIn(record["overall"], ("pass", "leak", "unavailable"))


if __name__ == "__main__":
    unittest.main()

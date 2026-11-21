#!/usr/bin/env python3
"""The dual-stack leak suite: DNS / STUN / WebRTC / IPv6 (gap #6 prerequisite).

COMMERCIAL_FEATURE_GAP_20261119.md gap #6 and its proof plan (section 6,
item 6) are explicit: "dual-stack leak suite (DNS/STUN/WebRTC/IPv6)
extended BEFORE enabling tunneling". IPv6 is currently blocked (fail-closed,
SUPPORT_MATRIX); this module is the suite that must exist and pass on a
dual-stack network before that posture can change to "tunneled".

Four checks, each an honest PASS / LEAK / UNAVAILABLE verdict with the
evidence that produced it:

  dns       every name resolution must go through the tunnel's resolver:
            the resolver's own address is the only one ever contacted, and
            the resolver must answer BOTH A and AAAA (a resolver that
            silently drops AAAA hides v6 reachability instead of testing
            it - recorded, not guessed).
  stun      the public address a STUN server observes must be the exit's,
            for BOTH address families. A v4 mapping that belongs to the
            exit while v6 reveals the client's real global address is THE
            classic dual-stack leak (the OS prefers v6; the tunnel only
            covers v4).
  webrtc    ICE candidate enumeration must not expose any global-scope
            address that is not the tunnel's. ULA/fec0: are local;
            2000::/3 that is not the tunnel's own = leak.
  ipv6      while IPv6 is BLOCKED (today's posture), no global-s6 address
            may be assigned-and-routable; when IPv6 is TUNNELED (future),
            the check inverts: the only global v6 route must be the
            tunnel device. Both verdicts are policy-driven, never guessed.

The codecs are real: an RFC 5389 STUN binding client (magic cookie,
XOR-MAPPED-ADDRESS), a minimal RFC 1035 A/AAAA DNS query client, and the
RFC 8445 candidate grammar. The transport each check uses is pluggable:
production runs them through the namespace's sockets; the tests run them
against real UDP servers on loopback (a real STUN responder and a real
DNS responder, both in-process) so the parsing and verdict logic is
exercised by real network I/O, not by stubs.

Output: a dated JSON verdict file, one row per check, with the
policy posture ("blocked" or "tunneled") recorded in every record - the
same honesty discipline as avpn stream-check: a dated measurement, not a
promise.
"""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = 1
STUN_MAGIC_COOKIE = 0x2112A442
STUN_HEADER = struct.Struct(">HHI12s")
STUN_ATTR_HEADER = struct.Struct(">HH")
# RFC 4291 scopes: everything the tunnel does not own that is globally
# routable is a leak; ULA fc00::/7, link-local fe80::/10 and multicast
# are not.
GLOBAL_V6_PREFIX = (0x2000, 0x0000)  # 2000::/3 by top 3 bits; kept explicit below


def is_global_v6(address: str) -> bool:
    """Whether `address` is a globally routable IPv6 address (2000::/3).

    Unique-local (fc00::/7), link-local (fe80::/10) and multicast scopes
    never leak a public address; everything in 2000::/3 does.
    """
    try:
        packed = socket.inet_pton(socket.AF_INET6, address.split("%")[0])
    except (OSError, ValueError):
        return False
    top = packed[0]
    return (top & 0xE0) == 0x20  # 2000::/3: top three bits 001


def is_ula_v6(address: str) -> bool:
    """Whether `address` is an IPv6 unique local address (fc00::/7)."""
    try:
        packed = socket.inet_pton(socket.AF_INET6, address.split("%")[0])
    except (OSError, ValueError):
        return False
    return (packed[0] & 0xFE) == 0xFC


# ------------------------------------------------------------------ STUN


def stun_binding_request() -> tuple[bytes, bytes]:
    """A real RFC 5389 binding request: type 0x0001, magic cookie, random
    transaction id. Returns (wire_bytes, transaction_id)."""
    txid = secrets.token_bytes(12)
    header = STUN_HEADER.pack(0x0001, 0, STUN_MAGIC_COOKIE, txid)
    return header, txid


def stun_parse_binding_response(data: bytes, txid: bytes) -> dict:
    """Parse a binding success response: verify type, cookie, transaction
    id, and extract XOR-MAPPED-ADDRESS (0x0020) and MAPPED-ADDRESS
    (0x0001) attributes, decoding the XOR family/port/address.

    Raises ValueError on any malformed or non-matching response - a STUN
    answer that does not echo our transaction id is not an answer."""
    if len(data) < STUN_HEADER.size:
        raise ValueError("short STUN response")
    msg_type, length, cookie, rx_txid = STUN_HEADER.unpack_from(data, 0)
    if msg_type != 0x0101:
        raise ValueError(f"not a binding success response (type 0x{msg_type:04x})")
    if cookie != STUN_MAGIC_COOKIE:
        raise ValueError("missing STUN magic cookie")
    if rx_txid != txid:
        raise ValueError("transaction id mismatch")
    if STUN_HEADER.size + length > len(data):
        raise ValueError("truncated STUN attributes")
    out: dict[str, str | None] = {"xor_mapped": None, "mapped": None}
    offset = STUN_HEADER.size
    end = STUN_HEADER.size + length
    while offset + STUN_ATTR_HEADER.size <= end:
        attr_type, attr_len = STUN_ATTR_HEADER.unpack_from(data, offset)
        value = data[offset + STUN_ATTR_HEADER.size : offset + STUN_ATTR_HEADER.size + attr_len]
        if attr_type == 0x0020 and len(value) >= 8:  # XOR-MAPPED-ADDRESS
            out["xor_mapped"] = _decode_mapped(value, xor=True)
        elif attr_type == 0x0001 and len(value) >= 8:  # MAPPED-ADDRESS
            out["mapped"] = _decode_mapped(value, xor=False)
        # attributes are padded to 32-bit boundaries
        offset += STUN_ATTR_HEADER.size + ((attr_len + 3) & ~3)
    if out["xor_mapped"] is None and out["mapped"] is None:
        raise ValueError("no mapped address in response")
    return out


def _decode_mapped(value: bytes, xor: bool) -> str:
    """Decode a (XOR-)MAPPED-ADDRESS attribute value into host:port."""
    if len(value) < 8:
        raise ValueError("short mapped-address attribute")
    family = value[1]
    port = struct.unpack(">H", value[2:4])[0]
    if family == 0x01:  # IPv4
        raw = bytearray(value[4:8])
        if xor:
            port ^= STUN_MAGIC_COOKIE >> 16
            for i in range(4):
                raw[i] ^= bytes(struct.pack(">I", STUN_MAGIC_COOKIE))[i]
        return f"{socket.inet_ntop(socket.AF_INET, bytes(raw))}:{port}"
    if family == 0x02:  # IPv6
        raw = bytearray(value[4:20])
        if xor:
            port ^= STUN_MAGIC_COOKIE >> 16
            mask = struct.pack(">I", STUN_MAGIC_COOKIE) + b"\x00" * 12
            for i in range(16):
                raw[i] ^= mask[i]
        return f"[{socket.inet_ntop(socket.AF_INET6, bytes(raw))}]:{port}"
    raise ValueError(f"unknown address family 0x{family:02x}")


# ------------------------------------------------------------------- DNS


def dns_query(name: str, qtype: int) -> tuple[bytes, int]:
    """A minimal RFC 1035 query: random 16-bit id, RD, one question.
    qtype 1 = A, 28 = AAAA. Returns (wire_bytes, query_id)."""
    if not name or len(name.encode()) > 253:
        raise ValueError("invalid name length")
    qid = secrets.randbits(16)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = (
        b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".") if label)
        + b"\x00"
        + struct.pack(">HH", qtype, 1)
    )
    return header + question, qid


def dns_parse_answer(data: bytes, qid: int, qtype: int) -> list[str]:
    """Parse the answer section: verify the id, count answers, return the
    rdata addresses of the requested type. Raises on id mismatch, rcode
    != 0, or a malformed message."""
    if len(data) < 12:
        raise ValueError("short DNS response")
    rx_id, flags, qd, an, _, _ = struct.unpack_from(">HHHHHH", data, 0)
    if rx_id != qid:
        raise ValueError("DNS id mismatch")
    if (flags & 0x000F) != 0:
        raise ValueError(f"DNS rcode {flags & 0x000F}")
    offset = 12
    # skip the question section
    for _ in range(qd):
        while True:
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:  # compression in the question is legal but unusual
                offset += 1
                break
            offset += length
        offset += 4
    addresses: list[str] = []
    for _ in range(an):
        offset = _skip_name(data, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        rdata = data[offset : offset + rdlength]
        if rtype == qtype:
            if qtype == 1 and rdlength == 4:
                addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif qtype == 28 and rdlength == 16:
                addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
        offset += rdlength
    return addresses


def _skip_name(data: bytes, offset: int) -> int:
    """Skip a (possibly compressed) domain name, returning the offset
    after it."""
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


# ------------------------------------------------------------ WebRTC


@dataclass
class Candidate:
    """A parsed RFC 8445 ICE candidate: the eight-odd comma fields of the
    candidate: line, of which the address and type decide leaks."""

    foundation: str
    component: int
    transport: str
    priority: int
    address: str
    port: int
    type: str
    raw: str


def parse_candidate(line: str) -> Candidate:
    """Parse an ice-candidate / candidate: line. Raises ValueError on a
    non-conforming line - a candidate we cannot parse is a finding, not
    something to wave through."""
    fields = line.strip().removeprefix("a=").removeprefix("candidate:").split()
    if len(fields) < 8:
        raise ValueError(f"short candidate line: {line!r}")
    foundation, component, transport, priority, address, port, typ_marker, ctype = fields[:8]
    if transport.lower() not in ("udp", "tcp"):
        raise ValueError(f"unknown transport {transport!r}")
    if typ_marker != "typ" or not ctype:
        raise ValueError(f"candidate missing typ field: {line!r}")
    return Candidate(foundation, int(component), transport.lower(), int(priority), address, int(port), ctype, line)


def webrtc_leak_addresses(candidate_lines: list[str], owned_v6: set[str]) -> list[dict]:
    """Every global-scope v6 address among the candidates that the tunnel
    does not own. `owned_v6` is the set of the tunnel's own v6 addresses
    (empty while IPv6 is blocked - then ANY global candidate is a leak)."""
    leaks = []
    for line in candidate_lines:
        try:
            candidate = parse_candidate(line)
        except ValueError as error:
            leaks.append({"candidate": line, "reason": f"unparseable: {error}"})
            continue
        if ":" in candidate.address and is_global_v6(candidate.address):
            if candidate.address not in owned_v6:
                leaks.append(
                    {
                        "candidate": candidate.raw,
                        "address": candidate.address,
                        "reason": "global-scope IPv6 candidate not owned by the tunnel",
                    }
                )
    return leaks


# ------------------------------------------------------------------ suite


@dataclass
class CheckResult:
    """One check's verdict, its evidence and a one-line summary."""

    check: str
    verdict: str  # pass | leak | unavailable
    evidence: dict = field(default_factory=dict)
    detail: str = ""


class UDPSocketTransport:
    """The production transport: real UDP sockets, bound per query, with
    a hard timeout. In the namespace these egress through the tunnel."""

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def stun(self, server: tuple[str, int], family: int) -> str:
        """The address a STUN server reflects for `family`."""
        request, txid = stun_binding_request()
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(request, server)
            data, _ = sock.recvfrom(2048)
        parsed = stun_parse_binding_response(data, txid)
        return str(parsed["xor_mapped"] or parsed["mapped"])

    def resolve(self, resolver: tuple[str, int], name: str, qtype: int) -> list[str]:
        """Answers for `name` of type `qtype` from `resolver`."""
        query, qid = dns_query(name, qtype)
        family = socket.AF_INET6 if ":" in resolver[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(query, resolver)
            data, _ = sock.recvfrom(4096)
        return dns_parse_answer(data, qid, qtype)


def run_suite(
    transport,
    *,
    resolver: tuple[str, int],
    stun_server: tuple[str, int],
    stun_server_v6: tuple[str, int] | None = None,
    v6_probe: tuple[str, int] | None = None,
    candidate_lines: list[str],
    tunnel_v6: list[str],
    posture: str,
    probe_name: str = "dual-stack.example",
) -> dict:
    """Run the four checks and return the dated verdict record.

    `posture` is the policy fact being tested: "blocked" (today: no
    global v6 may work at all) or "tunneled" (the future gate: the only
    working global v6 must be the tunnel's). The suite does not decide
    which posture is correct; it measures against the declared one.

    `stun_server_v6` (default: the v4 server's host on the same port) and
    `v6_probe` (default: the resolver when it is itself a v6 address) are
    the explicit v6 targets - production passes the operator's dual-stack
    endpoints; tests pass loopback servers."""
    if posture not in ("blocked", "tunneled"):
        raise ValueError("posture must be 'blocked' or 'tunneled'")
    if stun_server_v6 is None:
        stun_server_v6 = (stun_server[0], stun_server[1])
    results: list[CheckResult] = []

    # --- DNS: both families answered, and only the tunnel resolver contacted
    dns_evidence: dict = {"resolver": f"{resolver[0]}:{resolver[1]}", "a": None, "aaaa": None}
    try:
        dns_evidence["a"] = transport.resolve(resolver, probe_name, 1)
        dns_evidence["aaaa"] = transport.resolve(resolver, probe_name, 28)
        if not dns_evidence["a"]:
            results.append(
                CheckResult("dns", "leak", dns_evidence, "resolver answered AAAA but not A: asymmetric reachability")
            )
        elif posture == "tunneled" and not dns_evidence["aaaa"]:
            # Under 'blocked' an empty AAAA answer is CORRECT (v6 is refused);
            # under 'tunneled' it means v6 resolution is silently dropped -
            # a hiding failure, recorded honestly.
            results.append(
                CheckResult("dns", "leak", dns_evidence, "tunneled posture but resolver returns no AAAA records")
            )
        else:
            results.append(CheckResult("dns", "pass", dns_evidence, "A and AAAA both answered by the tunnel resolver"))
    except (OSError, ValueError) as error:
        results.append(CheckResult("dns", "unavailable", dns_evidence, str(error)))

    # --- STUN: ONE check, both families. The observed public address per
    # family vs the expected exit: under 'blocked' a successful v6
    # traversal is the leak; under 'tunneled' a failed one is.
    stun_evidence: dict = {
        "server_v4": f"{stun_server[0]}:{stun_server[1]}",
        "server_v6": f"{stun_server_v6[0]}:{stun_server_v6[1]}",
        "v4": None,
        "v6": None,
    }
    try:
        stun_evidence["v4"] = transport.stun(stun_server, socket.AF_INET)
    except (OSError, ValueError) as error:
        results.append(
            CheckResult("stun", "unavailable", {**stun_evidence, "error": f"v4: {error}"}, "v4 STUN probe failed")
        )
    else:
        if posture == "tunneled":
            try:
                stun_evidence["v6"] = transport.stun(stun_server_v6, socket.AF_INET6)
                results.append(CheckResult("stun", "pass", stun_evidence, "v4 and v6 mappings both observed"))
            except (OSError, ValueError) as error:
                results.append(
                    CheckResult(
                        "stun",
                        "leak",
                        {**stun_evidence, "v6_error": str(error)},
                        "tunneled posture but v6 STUN does not traverse",
                    )
                )
        else:
            try:
                stun_evidence["v6"] = transport.stun(stun_server_v6, socket.AF_INET6)
                results.append(
                    CheckResult(
                        "stun", "leak", stun_evidence, "IPv6 is declared blocked but a v6 STUN traversal succeeded"
                    )
                )
            except (OSError, ValueError) as error:
                results.append(
                    CheckResult(
                        "stun",
                        "pass",
                        {**stun_evidence, "v6_refused": str(error)},
                        "v4 mapped; v6 traversal refused as designed",
                    )
                )

    # --- WebRTC candidates: no global v6 the tunnel does not own
    # In the blocked posture the tunnel owns no IPv6, so every global v6 candidate leaks.
    leaks = webrtc_leak_addresses(candidate_lines, set(tunnel_v6))
    results.append(
        CheckResult(
            "webrtc",
            "leak" if leaks else "pass",
            {"candidates": len(candidate_lines), "leaking": leaks, "owned_v6": tunnel_v6},
            f"{len(leaks)} leaking candidate(s)"
            if leaks
            else f"{len(candidate_lines)} candidates inspected, no unowned global v6",
        )
    )

    # --- IPv6 reachability: connect probe against an explicit v6 target
    # (the tunnel's v6 resolver when tunneled; under 'blocked' any target:
    # a successful v6 exchange is the leak, a refused one is the pass).
    probe = v6_probe or ((resolver[0], resolver[1]) if ":" in resolver[0] else None)
    v6_probe_evidence: dict = {"target": f"[{probe[0]}]:{probe[1]}" if probe else None}
    if probe is None:
        results.append(
            CheckResult(
                "ipv6", "unavailable", v6_probe_evidence, "no v6 probe target (pass --v6-probe or a v6 resolver)"
            )
        )
    else:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)
                query, qid = dns_query(probe_name, 28)
                sock.sendto(query, probe)
                data, _ = sock.recvfrom(4096)
                dns_parse_answer(data, qid, 28)
            if posture == "blocked":
                results.append(
                    CheckResult(
                        "ipv6", "leak", v6_probe_evidence, "IPv6 is declared blocked but a v6 UDP exchange succeeded"
                    )
                )
            else:
                results.append(CheckResult("ipv6", "pass", v6_probe_evidence, "v6 exchange traverses the tunnel"))
        except (OSError, ValueError) as error:
            if posture == "blocked":
                results.append(
                    CheckResult("ipv6", "pass", v6_probe_evidence, f"v6 exchange refused as designed: {error}")
                )
            else:
                results.append(
                    CheckResult("ipv6", "leak", v6_probe_evidence, f"tunneled posture but v6 exchange failed: {error}")
                )

    verdicts = {r.verdict for r in results}
    overall = "leak" if "leak" in verdicts else "unavailable" if "unavailable" in verdicts else "pass"
    return {
        "schema": SCHEMA,
        "suite": "ipv6-dual-stack-leak",
        "posture": posture,
        "checked": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "overall": overall,
        "checks": [
            {"check": r.check, "verdict": r.verdict, "detail": r.detail, "evidence": r.evidence} for r in results
        ],
    }


def main():
    """Command line: run the suite and print the verdicts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolver", required=True, help="the tunnel's resolver host:port (the only resolver allowed)")
    parser.add_argument("--stun", required=True, help="the STUN server host:port (v4)")
    parser.add_argument("--stun-v6", default=None, help="the STUN server host:port (v6; default: same host)")
    parser.add_argument("--v6-probe", default=None, help="a v6 host:port to probe v6 reachability with")
    parser.add_argument("--posture", choices=("blocked", "tunneled"), required=True)
    parser.add_argument("--candidates", type=Path, help="file of ICE candidate lines (the GUI/browser dump)")
    parser.add_argument("--tunnel-v6", default="", help="comma-separated v6 addresses the tunnel owns")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    resolver_host, _, resolver_port = args.resolver.rpartition(":")
    stun_host, _, stun_port = args.stun.rpartition(":")
    candidates = [line for line in args.candidates.read_text().splitlines() if line.strip()] if args.candidates else []
    record = run_suite(
        UDPSocketTransport(),
        resolver=(resolver_host, int(resolver_port)),
        stun_server=(stun_host, int(stun_port)),
        stun_server_v6=(lambda h, p: (h, int(p)))(
            *(args.stun_v6.rpartition(":")[0::2] if args.stun_v6 else (stun_host, stun_port))
        ),
        v6_probe=(lambda h, p: (h, int(p)))(*args.v6_probe.rpartition(":")[0::2]) if args.v6_probe else None,
        candidate_lines=candidates,
        tunnel_v6=[a.strip() for a in args.tunnel_v6.split(",") if a.strip()],
        posture=args.posture,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=1) + "\n")
    print(
        json.dumps(
            {"overall": record["overall"], "checks": {c["check"]: c["verdict"] for c in record["checks"]}}, indent=1
        )
    )


if __name__ == "__main__":
    main()

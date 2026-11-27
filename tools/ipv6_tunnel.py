"""Opt-in inside-tunnel IPv6 dual-stack planner, symmetric guard, and family telemetry.

Implements stages 2-4 of docs/IPV6_TUNNELING_DESIGN.md while keeping the default
client posture fail-closed IPv4-only until live dual-stack qualification passes:
- Refuses 6in4/6to4/NAT64 translation, split-tunnel IPv6 exceptions, and v4-only exits.
- Enforces IPv6 minimum MTU (1280 B) inside the unchanged 1380 B constant-rate cell.
- Generates per-family symmetric nftables guards (IPv4 and IPv6 allowed ONLY via the
  tunnel interface, with AAAA DNS confined strictly to the in-tunnel loopback forwarder).
- Records per-family throughput and stream-check address-family observations.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


IPV6_MIN_MTU = 1280
PADDED_CELL_BYTES = 1380
IFNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")


class Ipv6TunnelError(ValueError):
    """Refusal to build or activate an unsafe dual-stack IPv6 tunnel configuration."""


def validate_exit_v6_descriptor(v6: dict | None) -> tuple[ipaddress.IPv6Network, str]:
    """Validate an exit descriptor's `v6` capability (must be global 2000::/3 /64 with v6 egress)."""
    if not isinstance(v6, dict):
        raise Ipv6TunnelError("exit descriptor advertises no IPv6 egress; refusing dual-stack chain")
    egress = v6.get("egress")
    if egress not in ("both", "v6"):
        raise Ipv6TunnelError(f"exit does not permit IPv6 egress ({egress!r})")
    prefix_raw = v6.get("prefix")
    if not isinstance(prefix_raw, str):
        raise Ipv6TunnelError("missing exit IPv6 prefix")
    try:
        net = ipaddress.IPv6Network(prefix_raw, strict=False)
    except ValueError:
        raise Ipv6TunnelError("malformed exit IPv6 prefix") from None
    if net.prefixlen != 64:
        raise Ipv6TunnelError("exit IPv6 prefix must be a /64")
    if not (0x2000 <= (int(net.network_address) >> 112) <= 0x3FFF):
        raise Ipv6TunnelError("exit IPv6 prefix must be globally routable (2000::/3)")
    return net, egress


@dataclass(frozen=True)
class DualStackPlan:
    """Validated dual-stack namespace plan for native inside-tunnel IPv6."""

    tunnel_interface: str
    client_v4: str
    client_v6: str
    exit_v6_prefix: str
    exit_egress: str
    inner_mtu: int = IPV6_MIN_MTU
    dns_loopback_v4: str = "127.0.0.1"
    dns_loopback_v6: str = "::1"

    def __post_init__(self):
        if not IFNAME_RE.fullmatch(self.tunnel_interface):
            raise Ipv6TunnelError("invalid tunnel interface name")
        if not IPV6_MIN_MTU <= self.inner_mtu <= PADDED_CELL_BYTES - 40:
            raise Ipv6TunnelError("IPv6 inner MTU must be between 1280 and 1340 bytes (fits 1380 B cell)")
        ipaddress.IPv4Interface(self.client_v4)
        v6_if = ipaddress.IPv6Interface(self.client_v6)
        if v6_if.ip.is_multicast or v6_if.ip.is_loopback or v6_if.ip.is_unspecified:
            raise Ipv6TunnelError("invalid client inner IPv6 address")
        ipaddress.IPv4Address(self.dns_loopback_v4)
        ipaddress.IPv6Address(self.dns_loopback_v6)

    @classmethod
    def build(
        cls,
        *,
        exit_v6: dict | None,
        tunnel_interface: str = "cpvpn0",
        client_v4: str = "10.77.0.2/24",
        client_v6: str = "fd77:6370:7670:6e00::2/64",
        inner_mtu: int = IPV6_MIN_MTU,
        split_v6_exceptions: tuple[str, ...] = (),
        use_translation: bool = False,
    ) -> DualStackPlan:
        """Build a fail-closed dual-stack plan; refuses translation, split-tunneling, and v4-only exits."""
        if use_translation:
            raise Ipv6TunnelError("6in4/6to4/NAT64 translation is refused; native IPv6 payloads only")
        if split_v6_exceptions:
            raise Ipv6TunnelError("per-family IPv6 split-tunnel exceptions are refused (deanonymization oracle)")
        net, egress = validate_exit_v6_descriptor(exit_v6)
        return cls(
            tunnel_interface=tunnel_interface,
            client_v4=client_v4,
            client_v6=client_v6,
            exit_v6_prefix=str(net),
            exit_egress=egress,
            inner_mtu=inner_mtu,
        )

    def namespace_commands(self) -> list[list[str]]:
        """Return exact iproute2 argv commands to configure dual-stack routing inside the app namespace."""
        return [
            ["ip", "addr", "replace", self.client_v4, "dev", self.tunnel_interface],
            ["ip", "-6", "addr", "replace", self.client_v6, "dev", self.tunnel_interface],
            ["ip", "link", "set", "dev", self.tunnel_interface, "mtu", str(self.inner_mtu), "up"],
            ["ip", "route", "replace", "default", "dev", self.tunnel_interface],
            ["ip", "-6", "route", "replace", "default", "dev", self.tunnel_interface],
        ]

    def symmetric_guard_nft(self, *, dns_port: int = 53) -> str:
        """Generate per-family symmetric nftables guard confining all IPv4, IPv6, and AAAA DNS to the tunnel."""
        if not 1 <= dns_port <= 65535:
            raise Ipv6TunnelError("invalid DNS port")
        tif = self.tunnel_interface
        return (
            "table inet cypherpunk_vpn_dualstack_guard {\n"
            "  chain output {\n"
            "    type filter hook output priority 0; policy drop;\n"
            '    oifname "lo" ip daddr %s udp dport %d accept\n'
            '    oifname "lo" ip daddr %s tcp dport %d accept\n'
            '    oifname "lo" ip6 daddr %s udp dport %d accept\n'
            '    oifname "lo" ip6 daddr %s tcp dport %d accept\n'
            '    oifname "lo" accept\n'
            '    oifname "%s" meta nfproto { ipv4, ipv6 } accept\n'
            "    # Drop all non-tunnel IPv4 and IPv6 (including link-local/SLAAC/direct AAAA leaks).\n"
            "    meta nfproto { ipv4, ipv6 } drop\n"
            "  }\n"
            "  chain input {\n"
            "    type filter hook input priority 0; policy drop;\n"
            '    iifname "lo" accept\n'
            '    iifname "%s" ct state established,related accept\n'
            "    meta nfproto { ipv4, ipv6 } drop\n"
            "  }\n"
            "}\n"
        ) % (
            self.dns_loopback_v4,
            dns_port,
            self.dns_loopback_v4,
            dns_port,
            self.dns_loopback_v6,
            dns_port,
            self.dns_loopback_v6,
            dns_port,
            tif,
            tif,
        )


def record_family_goodput(v4_mbps: float, v6_mbps: float, *, cell_bytes: int = PADDED_CELL_BYTES) -> dict:
    """Record Stage 3 per-family goodput alongside fixed constant-rate cell size verification."""
    if cell_bytes != PADDED_CELL_BYTES:
        raise Ipv6TunnelError("constant-rate cell size must stay fixed at 1380 bytes across IPv4 and IPv6")
    if v4_mbps < 0 or v6_mbps < 0:
        raise Ipv6TunnelError("goodput values must be non-negative")
    delta_pct = round(((v6_mbps - v4_mbps) / v4_mbps) * 100.0, 2) if v4_mbps > 0 else None
    return {
        "schema": 1,
        "cell_bytes": cell_bytes,
        "ipv4_mbps": round(v4_mbps, 3),
        "ipv6_mbps": round(v6_mbps, 3),
        "ipv6_vs_ipv4_delta_pct": delta_pct,
    }


def annotate_stream_family(row: dict, observed_ip: str) -> dict:
    """Tag Stage 4 `cypherpunk stream-check` eligibility rows with the exact IP family observed."""
    addr = ipaddress.ip_address(observed_ip)
    return {**row, "family": "ipv6" if addr.version == 6 else "ipv4"}

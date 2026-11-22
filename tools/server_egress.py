"""A server sends only VPN traffic, and never more than its monthly cap (nftables text).

Two tables, both `inet` (every rule covers IPv4 and IPv6):

- `advanced_vpn_egress` (watched: restored if anyone alters it). Inbound: drop unless it
  is loopback or the tunnels, an established flow, the chain's own ports, SSH, DHCP, or
  the ICMP/ICMPv6 a network needs (errors, packet-too-big, neighbour discovery with
  hop limit 255; no echo, so a server stays silent to scanners). Outbound: drop unless
  it is the data plane's own user, a reply on an established flow (SSH), DHCP, NTP, the
  provider's link-local metadata service (EC2 Instance Connect reads keys from it), or
  the ICMP a network needs. Forwarding: only what comes out of the exit's tunnel, and its
  replies. Nothing else on the host (update timers, agents, a stray process) can send.
  A maintenance window (`avpn cloud host update`, or the supervisor's daily security
  update) lets root send too, still counted, and the users root's updates depend on:
  apt's download sandbox (`_apt`) and the system resolver. Without them the window was
  useless: apt's downloads and every name lookup are not root's, so updates hung.
- `advanced_vpn_quota` (not watched: its counter moves; the supervisor reinstalls it from
  the meter if it disappears). It runs after the egress table, so a packet the egress table
  drops never uses up allowance. One kernel quota on everything sent or forwarded past the
  tunnels: when the month's remaining allowance is spent, the kernel drops, with no
  polling gap. SSH replies stay outside it, rate-limited, so a capped server can still
  be reached to raise its cap.

A shared host (other workloads on it) gets no egress table: its other traffic is not the
VPN's to block. Its quota then counts only the data plane's user and the exit's
forwarded traffic, and so does its meter (an nftables counter), so the other workloads
neither use up the cap nor get cut off by it.
"""

EGRESS_TABLE = "advanced_vpn_egress"
QUOTA_TABLE = "advanced_vpn_quota"
INTERNAL = ("lo", "avpn0", "avwg0")
SSH_REPLY_RATE = "1 mbytes/second"  # outside the quota; the cap's 10% margin covers it

ICMP_IN = "destination-unreachable, time-exceeded, parameter-problem"
ICMP_OUT = "destination-unreachable, time-exceeded, parameter-problem"
ICMPV6_ERRORS = "destination-unreachable, packet-too-big, time-exceeded, parameter-problem"
ICMPV6_ND = "nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert"


def _set(items):
    return "{ " + ", ".join(items) + " }"


def ports(profile, cfg):
    """The TCP/UDP ports this server is reached on: its data plane listener, the cloak's
    unprivileged listener and, on a first hop, the public port redirected to it."""
    host, port = cfg["core"]["listen"].rsplit(":", 1)
    # A relay's data plane listens on its WireGuard overlay address only: reached through
    # the (internal) carrier interface, never from the public one.
    found = set() if host.startswith("10.78.") else {int(port)}
    if "cloak" in cfg:
        found.add(int(cfg["cloak"]["listen"].rsplit(":", 1)[1]))
        found.add(int(profile["network"]["relay_endpoint"].rsplit(":", 1)[1]))
    if not all(1 <= p <= 65535 for p in found):
        raise ValueError("port out of range")
    return sorted(found)


def egress_rules(profile, cfg, service_uid, extra_uids=(), maintenance=False, lab_transit=False, maintenance_uids=()):
    """The `advanced_vpn_egress` table for a dedicated server. `lab_transit` (namespace labs
    only, `avpnctl --lab`): the namespace doubles as the lab's internet router, so plain
    transit between its non-tunnel interfaces is forwarded; never on a real server."""
    uids = [int(service_uid)] + [int(u) for u in extra_uids]
    if any(u <= 0 for u in uids[:1]):
        raise ValueError("the data plane must run as its own unprivileged user")
    internal = _set('"%s"' % i for i in INTERNAL)
    listen = _set(str(p) for p in ports(profile, cfg))
    out_users = "".join("  meta skuid %d accept\n" % u for u in uids)
    if maintenance:
        out_users += "  meta skuid 0 accept\n"  # an update window: counted, then closed
        # ...with apt's download sandbox and the resolver, which root's updates go through.
        out_users += "".join("  meta skuid %d accept\n" % int(u) for u in maintenance_uids if int(u) > 0)
    forward = ""
    if lab_transit:
        forward += "  iifname != %s oifname != %s accept\n" % (internal, internal)
    if profile["role"] == "exit":
        forward += '  iifname "avpn0" accept\n  oifname "avpn0" ct state established,related accept\n'
    return (
        "table inet %s {\n" % EGRESS_TABLE
        + " chain input { type filter hook input priority -120; policy drop;\n"
        + "  iifname %s accept\n" % internal
        + "  ct state invalid drop\n"
        + "  ct state established,related accept\n"
        + "  meta l4proto { tcp, udp } th dport %s accept\n" % listen
        + "  tcp dport 22 accept\n"
        + "  udp sport 67 udp dport 68 accept\n"
        + "  ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n"
        + "  icmp type { %s } accept\n" % ICMP_IN
        + "  icmpv6 type { %s } accept\n" % ICMPV6_ERRORS
        + "  icmpv6 type { %s } ip6 hoplimit 255 accept\n" % ICMPV6_ND
        + " }\n"
        + " chain output { type filter hook output priority -120; policy drop;\n"
        + "  oifname %s accept\n" % internal
        + "  ct state established,related accept\n"
        + out_users
        + "  udp sport 68 udp dport 67 accept\n"
        + "  udp sport 546 udp dport 547 accept\n"
        + "  udp dport 123 accept\n"
        + "  ip daddr 169.254.169.254 tcp dport { 80, 443 } accept\n"
        + "  ip6 daddr fd00:ec2::254 tcp dport 80 accept\n"
        + "  icmp type { %s } accept\n" % ICMP_OUT
        + "  icmpv6 type { %s } accept\n" % ICMPV6_ERRORS
        + "  icmpv6 type { %s, mld2-listener-report } accept\n" % ICMPV6_ND
        + " }\n"
        + " chain forward { type filter hook forward priority -120; policy drop;\n"
        + forward
        + " }\n"
        + "}\n"
    )


def quota_rules(remaining, service_uid=None, shared=False):
    """The `advanced_vpn_quota` table: everything leaving past the tunnels counts against
    `remaining` bytes (on a shared host: only the data plane's user and forwarded traffic)."""
    remaining = max(0, int(remaining))
    internal = _set('"%s"' % i for i in INTERNAL)
    only_vpn = ""
    if shared:
        if service_uid is None or int(service_uid) <= 0:
            raise ValueError("a shared host's quota needs the data plane's own user")
        only_vpn = "  meta skuid != %d accept\n" % int(service_uid)
    return (
        "table inet %s {\n" % QUOTA_TABLE
        + " quota month { over %d bytes; }\n" % remaining
        + " counter vpn { }\n"
        + " chain output { type filter hook output priority -115; policy accept;\n"
        + "  oifname %s accept\n" % internal
        + "  tcp sport 22 limit rate over %s drop\n" % SSH_REPLY_RATE
        + "  tcp sport 22 accept\n"
        + only_vpn
        + '  counter name "vpn"\n'
        + '  quota name "month" drop\n'
        + " }\n"
        + " chain forward { type filter hook forward priority -115; policy accept;\n"
        + "  oifname %s accept\n" % internal
        + '  counter name "vpn"\n'
        + '  quota name "month" drop\n'
        + " }\n"
        + "}\n"
    )

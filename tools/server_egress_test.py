#!/usr/bin/env python3
"""The server egress lock and monthly quota (tools/server_egress.py), on real nftables in
disposable namespaces, over IPv4 and IPv6.

Run only through: unshare --user --map-root-user --map-auto --net --mount python3 tools/server_egress_test.py
Proves: nothing but the data plane's user can send; the kernel quota stops it at the cap;
SSH replies survive a spent quota; unlisted ports and pings get no answer on either
family; IPv6 neighbour discovery still works; a shared host's quota counts only the VPN.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

import server_egress as se  # noqa: E402

SERVICE = 1  # the lab's data-plane user (managed_test uses the same)
PY = "/usr/bin/python3"  # helpers run as the service user, who cannot read a venv under /home
SRV4, PEER4 = "192.0.2.10", "192.0.2.20"
SRV6, PEER6 = "2001:db8:5::10", "2001:db8:5::20"


def run(*args, check=True, input=None, timeout=20):
    return subprocess.run(args, check=check, capture_output=True, text=True, input=input, timeout=timeout)


def ns(name, *args, **kw):
    return run("ip", "netns", "exec", name, *args, **kw)


def as_user(uid):
    return ["setpriv", "--reuid", str(uid), "--regid", str(uid), "--clear-groups"] if uid else []


SEND = r"""
import socket, sys
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
n = 0
for i in range(int(sys.argv[3])):
    try:
        s.sendto(b"x" * int(sys.argv[4]), (sys.argv[1], int(sys.argv[2]))); n += 1
    except OSError:
        pass
print(n)
"""

# Count UDP bytes received on a port until idle for a moment.
RECV = r"""
import socket, sys, json
fam = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
s.settimeout(float(sys.argv[3]))
got = 0
try:
    while True:
        got += len(s.recv(65536))
except socket.timeout:
    pass
print(got)
"""


def udp(src_ns, uid, dst, port, count, size, listen_ns, listen_addr, idle=1.5):
    """Bytes `listen_ns` receives when `src_ns` (as `uid`) sends `count` datagrams."""
    rx = subprocess.Popen(["ip", "netns", "exec", listen_ns, PY, "-c", RECV, listen_addr, str(port),
                           str(idle)], stdout=subprocess.PIPE, text=True)  # fmt: skip
    time.sleep(0.3)
    ns(src_ns, *as_user(uid), PY, "-c", SEND, dst, str(port), str(count), str(size), check=False)
    return int(rx.communicate(timeout=30)[0].strip() or 0)


def tcp_reply_after(port, family_addr):
    """Peer connects to the server's `port`; the server answers 64 KiB. Bytes the peer got."""
    srv = (
        "import socket,sys;fam=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET;"
        "s=socket.socket(fam);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])));"
        "s.listen();c,_=s.accept();c.sendall(b'y'*65536);c.close()"
    )
    cli = (
        "import socket,sys;fam=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET;"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5);n=0\n"
        "while True:\n b=s.recv(65536)\n if not b: break\n n+=len(b)\nprint(n)"
    )
    p = subprocess.Popen(["ip", "netns", "exec", "srv", PY, "-c", srv, family_addr, str(port)])
    time.sleep(0.3)
    try:
        r = ns("peer", PY, "-c", cli, family_addr, str(port), check=False)
        return int(r.stdout.strip() or 0)
    finally:
        p.kill()
        p.wait()


def pings(dst):
    r = ns("peer", "ping", "-n", "-c", "2", "-W", "1", dst, check=False)
    return r.returncode == 0


def quota_used():
    raw = json.loads(ns("srv", "/usr/sbin/nft", "-j", "list", "quota", "inet", se.QUOTA_TABLE, "month").stdout)
    return next(x["quota"]["used"] for x in raw["nftables"] if "quota" in x)


def main():
    if os.getuid() != 0 or {r["ifname"] for r in json.loads(run("ip", "-j", "link").stdout)} != {"lo"}:
        raise SystemExit("run inside a fresh user+network+mount namespace (see the docstring)")
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "size=8m", "tmpfs", "/run")
    for n in ("srv", "peer"):
        run("ip", "netns", "add", n)
        ns(n, "ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "s0", "type", "veth", "peer", "name", "p0")
    run("ip", "link", "set", "s0", "netns", "srv")
    run("ip", "link", "set", "p0", "netns", "peer")
    for n, dev, a4, a6 in (("srv", "s0", SRV4, SRV6), ("peer", "p0", PEER4, PEER6)):
        ns(n, "ip", "address", "add", a4 + "/24", "dev", dev)
        ns(n, "ip", "-6", "address", "add", a6 + "/64", "dev", dev, "nodad")
        ns(n, "ip", "link", "set", dev, "up")
    result = {}
    profile = {"role": "exit", "network": {"relay_endpoint": "198.51.100.1:443"}}
    cfg = {"core": {"listen": "[::]:4444"}}
    cap = 200_000

    # Controls before any rule: everything flows, pings answer (so the checks can fail).
    result["control_root_sends"] = udp("srv", 0, PEER4, 9000, 20, 1000, "peer", PEER4) == 20_000
    result["control_ping4_answers"] = pings(SRV4)
    result["control_ping6_answers"] = pings(SRV6)
    result["control_unlisted_port_reachable"] = udp("peer", 0, SRV6, 5555, 5, 100, "srv", SRV6) == 500

    ns("srv", "/usr/sbin/nft", "-f", "-", input=se.egress_rules(profile, cfg, SERVICE) + se.quota_rules(cap))
    # Silence first, while the quota still has room: a reply must be stopped by the egress
    # rules themselves, not by a spent quota (which once hid an answered ping).
    result["listed_port_reachable_v6"] = udp("peer", 0, SRV6, 4444, 5, 100, "srv", "::") == 500
    result["unlisted_port_silent_v4"] = udp("peer", 0, SRV4, 5555, 5, 100, "srv", SRV4) == 0
    result["unlisted_port_silent_v6"] = udp("peer", 0, SRV6, 5555, 5, 100, "srv", SRV6) == 0
    result["no_ping_answer_v4"] = not pings(SRV4)
    result["no_ping_answer_v6"] = not pings(SRV6)
    for fam_dst, label in ((PEER4, "4"), (PEER6, "6")):
        result["root_blocked_v" + label] = udp("srv", 0, fam_dst, 9001, 20, 1000, "peer", fam_dst) == 0
    # The data plane's user sends over IPv6, which needs neighbour discovery to work.
    first = udp("srv", SERVICE, PEER6, 9002, 50, 1000, "peer", PEER6)
    result["service_sends_v6_nd_works"] = first == 50_000
    # Then it keeps sending far past the cap: the kernel stops it near the cap.
    more = udp("srv", SERVICE, PEER4, 9003, 400, 1000, "peer", PEER4)
    total = first + more
    result["delivered_bytes_with_cap_%d" % cap] = total
    # The kernel counts whole packets (IP and UDP headers too): the payload that got
    # through is a little under the cap, and nothing past it.
    result["kernel_quota_stops_at_cap"] = 0.93 * cap <= total <= cap
    result["quota_used_reported"] = quota_used() >= cap
    result["ssh_reply_survives_spent_quota_v4"] = tcp_reply_after(22, SRV4) == 65536
    result["ssh_reply_survives_spent_quota_v6"] = tcp_reply_after(22, SRV6) == 65536

    # Forwarding (an exit): what arrives on its tunnel is forwarded, the same traffic
    # arriving on any other interface is not. "tun" stands in for avpn0 (a veth named so).
    ns("srv", "/usr/sbin/nft", "-f", "-", input="add table inet %s\ndelete table inet %s\n" % (se.QUOTA_TABLE,
       se.QUOTA_TABLE) + se.quota_rules(10**9))  # fmt: skip
    run("ip", "netns", "add", "inner")
    ns("inner", "ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "avpn0", "type", "veth", "peer", "name", "i0")
    run("ip", "link", "set", "avpn0", "netns", "srv")
    run("ip", "link", "set", "i0", "netns", "inner")
    ns("srv", "ip", "address", "add", "10.77.0.1/30", "dev", "avpn0")
    ns("srv", "ip", "link", "set", "avpn0", "up")
    ns("inner", "ip", "address", "add", "10.77.0.2/30", "dev", "i0")
    ns("inner", "ip", "link", "set", "i0", "up")
    ns("inner", "ip", "route", "add", "default", "via", "10.77.0.1")
    ns("peer", "ip", "route", "add", "10.77.0.0/30", "via", SRV4)
    ns("srv", "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
    result["exit_forwards_from_its_tunnel"] = udp("inner", 0, PEER4, 9006, 10, 100, "peer", PEER4) == 1000
    # The internet cannot open a flow into the tunnel (only replies come back in).
    result["internet_cannot_open_flows_into_the_tunnel"] = (
        udp("peer", 0, "10.77.0.2", 9007, 10, 100, "inner", "10.77.0.2") == 0
    )
    # Control: without the egress table the same packets are forwarded, so the check above could fail.
    ns("srv", "/usr/sbin/nft", "delete", "table", "inet", se.EGRESS_TABLE)
    result["control_forwarded_without_the_lock"] = (
        udp("peer", 0, "10.77.0.2", 9008, 10, 100, "inner", "10.77.0.2") == 1000
    )

    # An update window lets root send (still counted); closing it shuts root out again.
    reload = "add table inet %s\ndelete table inet %s\n" % (se.EGRESS_TABLE, se.EGRESS_TABLE)
    ns("srv", "/usr/sbin/nft", "-f", "-", input=reload + se.egress_rules(profile, cfg, SERVICE, maintenance=True))
    result["maintenance_window_lets_root_send"] = udp("srv", 0, PEER4, 9010, 5, 100, "peer", PEER4) == 500
    ns("srv", "/usr/sbin/nft", "-f", "-", input=reload + se.egress_rules(profile, cfg, SERVICE))
    result["closed_window_blocks_root_again"] = udp("srv", 0, PEER4, 9011, 5, 100, "peer", PEER4) == 0

    # A shared host: no egress table, and the quota counts only the data plane's user.
    ns("srv", "/usr/sbin/nft", "flush", "ruleset")
    ns("srv", "/usr/sbin/nft", "-f", "-", input=se.quota_rules(50_000, service_uid=SERVICE, shared=True))
    result["shared_other_workloads_unaffected"] = udp("srv", 0, PEER4, 9004, 100, 1000, "peer", PEER4) == 100_000
    result["shared_vpn_capped"] = udp("srv", SERVICE, PEER4, 9005, 100, 1000, "peer", PEER4) <= 50_000

    print(json.dumps(result, indent=1))
    failed = [k for k, v in result.items() if v is False]
    if failed:
        raise SystemExit("FAILED: " + ", ".join(failed))


if __name__ == "__main__":
    main()

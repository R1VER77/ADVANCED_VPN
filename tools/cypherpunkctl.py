#!/usr/bin/env python3
"""Managed Linux VPN: one enrollment import, persistent firewall, isolated DNS and supervision.

No commands in this file are run on the host by the test suite: integration tests
enter a new unprivileged user/mount/network namespace first. Whole-device mode
is opt-in and is never automatically selected over an existing VPN.
"""

import argparse
import contextlib
import datetime as dt
import fcntl
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import random
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

from keyguard import atomic, read_private, trusted_exe
import retention
from i2p import FRONT_RATES
from managed_profile import (
    RATE_CLASSES,
    choose_rate,
    rate_cost_gib,
    create,
    enroll,
    profile_validate,
    require_current,
    runtime,
    cloak_certificate,
    canonical,
    refresh_leaves,
    sign_session,
    request,
    load_keys,
    HardwareOperator,
    SoftwareOperator,
    server_locked,
    server_unlock,
    unlock_items,
)

APP = "cpvpn-app"
LAYER_KEYS = ("outer", "middle", "inner")
# Smallest underlay link MTU the HTTP/3 cloak can use: a 1420-byte QUIC UDP payload in an IPv4+UDP packet.
UNDERLAY_MIN_MTU = 1448
TUN = "cpvpn0"
WG = "cpwg0"


def cmd(*args, input=None, check=True):
    """Run a system command as an argument list (no shell), resolving a bare
    executable name inside fixed root-owned directories rather than $PATH."""
    if "/" not in args[0]:
        args = (trusted_exe(args[0]),) + tuple(args[1:])
    return subprocess.run(args, input=input, text=True, capture_output=True, check=check, timeout=15)


def lab_guard():
    """Refuse lab mode unless this process is root inside an unprivileged user namespace."""
    rows = Path("/proc/self/uid_map").read_text().splitlines()
    if os.geteuid() != 0 or not rows or rows[0].split()[0] != "0" or rows[0].split()[1] == "0":
        raise RuntimeError("lab mode requires an unprivileged user namespace")


def root_guard(lab):
    """Refuse privileged commands unless running as root (and, for --lab, in a user namespace)."""
    if os.geteuid() != 0:
        raise RuntimeError("managed networking requires the installed root supervisor")
    if lab:
        lab_guard()


def save(path, value):
    """Write `value` to `path` as canonical JSON, atomically and readable by root only."""
    atomic(path, canonical(value))


def runtime_root():
    """Where the per-state runtime directories live. Unprivileged tests may point it
    elsewhere with CPVPN_RUNTIME_ROOT, so they never depend on a VPN running on the
    machine; root never honours it (`sudo -E` must not move a service's state)."""
    override = os.environ.get("CPVPN_RUNTIME_ROOT")
    return Path(override) if override and os.geteuid() != 0 else Path("/run/cypherpunk-vpn")


# What a non-root caller is told while the root service keeps its status to itself
# (/run/cypherpunk-vpn is root's, 0700): not "not running", which may be false.
STATUS_ROOT_ONLY = dict(
    state="unknown", detail="only root can read the service's status", next="sudo cypherpunk status"
)


def read_status(state, default=None):
    """The running service's status for `state`, `default` when there is none, or
    STATUS_ROOT_ONLY when this user may not look."""
    try:
        return read_json_private(runtime_dir(state, create=False) / "status.json", default)
    except PermissionError:
        return dict(STATUS_ROOT_ONLY)


def runtime_dir(state, create=True):
    """RAM-only (tmpfs) home for everything written while running: status, PIDs,
    locks, rotated leaves, resolver file and namespace marker. Servers persist nothing
    at runtime, so a powered-off or seized server holds no record of its sessions: the one
    exception is the month's outbound total, rounded up to 16 MiB, that keeps a free
    account free across reboots (tools/fee_guard.py; no sessions, users or times).

    Read-only queries pass ``create=False``: they get the path without creating it,
    and an existing directory is still checked before anything inside it is trusted."""
    import hashlib

    d = runtime_root() / ("state-" + hashlib.sha256(str(Path(state).resolve()).encode()).hexdigest()[:16])
    if create:
        d.mkdir(mode=0o700, parents=True, exist_ok=True)
    elif not os.path.lexists(d):
        return d
    m = d.lstat()
    if stat.S_ISLNK(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
        raise RuntimeError("unsafe runtime directory")
    return d


def restore_dir(state, profile):
    """Where the pre-VPN network snapshot lives: the client keeps it on disk so it can
    restore its own routes/DNS after a reboot; servers keep it in RAM only."""
    return state if profile["role"] == "client" else runtime_dir(state)


def load_profile(state):
    """Load and strictly validate this device's enrolled profile."""
    p = profile_validate(json.loads(read_private(state / "profile.json")))
    return p


def link_exists(name, ns=None):
    """Whether network link `name` exists (in namespace `ns`, if given)."""
    args = ["ip"] + (["-n", ns] if ns else []) + ["link", "show", "dev", name]
    return cmd(*args, check=False).returncode == 0


def tun(name, addr, mtu, ns=None, owner=0):
    """Create (or reconfigure) TUN device `name` with address `addr` and `mtu`, owned by `owner`."""
    prefix = ["ip", "netns", "exec", ns] if ns else []
    if not link_exists(name, ns):
        cmd(*prefix, "ip", "tuntap", "add", "dev", name, "mode", "tun", "user", str(owner))
        cmd(*prefix, "ip", "link", "set", name, "alias", "cypherpunk-vpn-managed")
    else:
        row = json.loads(cmd(*prefix, "ip", "-j", "link", "show", "dev", name).stdout)[0]
        if row.get("ifalias") != "cypherpunk-vpn-managed":
            raise RuntimeError("refusing unrelated pre-existing interface")
    cmd(*prefix, "ip", "address", "replace", addr, "dev", name)
    cmd(*prefix, "ip", "link", "set", name, "mtu", str(mtu), "up")


def nft(text, ns=None):
    """Load nftables rule text from stdin, in namespace `ns` if given."""
    prefix = ["ip", "netns", "exec", ns] if ns else []
    cmd(*prefix, "/usr/sbin/nft", "-f", "-", input=text)


def reset_table(name):
    """nft text that empties table `inet name` whether or not it exists, inside the same
    transaction as whatever follows. Never "list, then delete if present": two writers
    (the supervisor and an app launch) could both see it absent and both add, and nft
    appends, which doubled every kill-switch rule."""
    return "add table inet %s\ndelete table inet %s\n" % (name, name)


def replace_table(body, ns=None):
    """Atomically replace the `inet cypherpunk_vpn` table with `body`."""
    nft(reset_table("cypherpunk_vpn") + body, ns)


class TableWatch:
    """Kill-switch drift watchdog. Remembers each managed nftables table exactly as the
    supervisor built it and restores it whenever another process deletes or alters it
    (`nft list` output is valid `nft -f` input). Storm guard: more than `limit` restores
    in `window` seconds raises, and the supervisor then stops the data plane (fail
    closed) rather than fight forever. The byte meter changes by design: not watched."""

    def __init__(self, targets, limit=10, window=60):
        self.expected = {}
        for name, ns in targets:
            listing = self.listing(name, ns)
            if listing is not None:
                self.expected[(name, ns)] = listing
        self.limit, self.window, self.restores = limit, window, []
        # Why each table was last restored (absent, altered, or what `nft list` said), so
        # a log line can tell a real deletion from a failed listing.
        self.reasons = {}
        self._stderr = ""

    def listing(self, name, ns=None):
        """The table as `nft list` prints it (in namespace `ns`), or None if absent."""
        prefix = ["ip", "netns", "exec", ns] if ns else []
        r = cmd(*prefix, "/usr/sbin/nft", "list", "table", "inet", name, check=False)
        err = getattr(r, "stderr", "")
        self._stderr = "" if r.returncode == 0 or not isinstance(err, str) else err.strip()
        return r.stdout if r.returncode == 0 else None

    def check(self, now=None):
        """Restore every drifted table; returns the (table, namespace) pairs restored."""
        now = time.monotonic() if now is None else now
        restored = []
        for (name, ns), expected in self.expected.items():
            current = self.listing(name, ns)
            if current == expected:
                continue
            if current is None:
                # nft prints "Error: ..." then the command and a ^^^ marker: keep the error.
                lines = [x.strip() for x in self._stderr.splitlines() if x.strip()]
                first = next((x for x in lines if x.startswith("Error")), lines[0] if lines else "no output")
                self.reasons[(name, ns)] = "absent (%s)" % first[:160]
            else:
                changed = sum(1 for a, b in zip(current.splitlines(), expected.splitlines(), strict=False) if a != b)
                self.reasons[(name, ns)] = "altered (%d lines differ, %d vs %d lines)" % (
                    changed + abs(len(current.splitlines()) - len(expected.splitlines())),
                    len(current.splitlines()),
                    len(expected.splitlines()),
                )
            self.restores = [t for t in self.restores if now - t < self.window] + [now]
            if len(self.restores) > self.limit:
                raise RuntimeError("the kill switch keeps being altered by another process")
            # Never conditional on the listing: a failed `nft list` would otherwise append a copy.
            nft(reset_table(name) + expected, ns)
            restored.append((name, ns))
        return restored


def app_firewall(ns):
    """Kill switch inside the protected namespace: only the tunnel and its DNS may leave."""
    replace_table(
        """table inet cypherpunk_vpn {
 chain output { type filter hook output priority -100; policy drop;
  oifname "lo" accept
  ip daddr != 10.77.0.1 udp dport {53,853} drop
  ip daddr != 10.77.0.1 tcp dport {53,853} drop
  meta nfproto ipv4 oifname "cpvpn0" accept
 }
}\n""",
        ns,
    )


def whole_firewall(profile, service_uid=None, front_uid=None):
    """Whole-device kill switch: drop everything except the tunnel, the carrier to the first hop and loopback.
    Behind an I2P front the carrier never leaves the host: only the I2P router's own user
    may (and the front table keeps even it away from the entry's address)."""
    host, port = profile["network"]["relay_endpoint"].rsplit(":", 1)
    carrier_allow = ""
    if profile.get("front"):
        if front_uid in (None, 0, service_uid):
            raise RuntimeError("the I2P router needs its own unprivileged user")
        carrier_allow += "  meta skuid %d meta l4proto {tcp, udp} accept\n" % int(front_uid)
    elif service_uid is not None:
        for proto in ["udp", "tcp"]:
            carrier_allow += "  meta skuid %d ip daddr %s %s dport %d accept\n" % (
                int(service_uid),
                ipaddress.IPv4Address(host),
                proto,
                int(port),
            )
    if service_uid is not None:
        carrier_allow += '  meta skuid %d ip daddr 10.78.0.1 udp dport 4433 oifname "cpwg0" accept\n' % int(service_uid)
    replace_table(
        """table inet cypherpunk_vpn {
 chain output { type filter hook output priority -100; policy drop;
  oifname "lo" accept
  meta skuid 0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
"""
        + carrier_allow
        + """
  ip daddr != 10.77.0.1 udp dport {53,853} drop
  ip daddr != 10.77.0.1 tcp dport {53,853} drop
  meta nfproto ipv4 oifname "cpvpn0" accept
 }
 chain forward { type filter hook forward priority -100; policy drop;
 }
}\n"""
    )


def first_hop_rules(profile):
    """nftables chains for the chain's first hop: outer QUIC only over the carrier, the
    carrier (WireGuard, 41194) only from the local cloak over loopback, and the public
    port redirected to the cloak's unprivileged listener (8443), for packets addressed to
    this host only (traffic passing through is never captured)."""
    public = int(profile["network"]["relay_endpoint"].rsplit(":", 1)[1])
    if not 1 <= public <= 65535:
        raise ValueError("bad public port")
    return """
 chain input { type filter hook input priority -100; policy accept;
  udp dport 4433 iifname != "cpwg0" drop
  udp dport 41194 iifname != "lo" drop
 }
 chain cloak { type nat hook prerouting priority dstnat;
  fib daddr type local udp dport %d redirect to :8443
  fib daddr type local tcp dport %d redirect to :8443
 }""" % (public, public)


def resolved_managed(target):
    """True when /etc/resolv.conf is systemd-resolved's generated file and resolved is running."""
    try:
        trusted_exe("resolvectl")
    except FileNotFoundError:
        return False
    return (
        str(target).startswith("/run/systemd/resolve/")
        and cmd("systemctl", "is-active", "--quiet", "systemd-resolved.service", check=False).returncode == 0
    )


def route_to(address):
    """The kernel's route to `address`, with an interface name safe to put in rule text."""
    ip = ipaddress.IPv4Address(address)
    row = json.loads(cmd("ip", "-j", "route", "get", str(ip)).stdout)[0]
    if not re.fullmatch(r"[a-zA-Z0-9_.:@-]{1,64}", row["dev"]):
        raise ValueError("unsafe interface")
    return row


IFACE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,15}")
UPSTREAM_TABLE = "cypherpunk_vpn_upstream"


def valid_interface(name):
    """An interface name safe to put in rule text (Linux IFNAMSIZ: at most 15 bytes)."""
    if not IFACE_NAME.fullmatch(name) or name in (".", ".."):
        raise ValueError("invalid interface name")
    return name


def upstream_firewall(endpoint, iface):
    """Upstream entry: packets to the first hop may leave only through `iface` (e.g. an
    existing VPN), so if it drops the first hop is unreachable rather than reached
    directly. A separate table, so its drop is final whatever other tables accept.
    `iface=None` removes it."""
    text = reset_table(UPSTREAM_TABLE)
    if iface:
        host, port = endpoint.rsplit(":", 1)
        addr, pnum, dev = ipaddress.IPv4Address(host), int(port), valid_interface(iface)
        text += (
            "table inet %s {\n chain output { type filter hook output priority -110; policy accept;\n"
            '  ip daddr %s udp dport %d oifname != "%s" drop\n'
            '  ip daddr %s tcp dport %d oifname != "%s" drop\n }\n}\n'
        ) % (UPSTREAM_TABLE, addr, pnum, dev, addr, pnum, dev)
    nft(text)


def upstream_route(iface, gateway=None):
    """How to reach the first hop through `iface`. A point-to-point interface (WireGuard,
    tun) needs no gateway. An Ethernet-like one uses `gateway`, or a gateway the interface
    already routes through in any table; with neither, the connection is refused."""
    if not link_exists(valid_interface(iface)):
        raise RuntimeError("upstream interface %s is down; not reaching the first hop directly" % iface)
    flags = json.loads(cmd("ip", "-j", "link", "show", "dev", iface).stdout)[0]["flags"]
    if "POINTOPOINT" in flags or "NOARP" in flags:
        return dict(dev=iface)
    if gateway:
        return dict(dev=iface, gateway=str(ipaddress.IPv4Address(gateway)))
    rows = json.loads(cmd("ip", "-j", "-4", "route", "show", "table", "all", "dev", iface).stdout)
    for row in rows:
        if row.get("gateway"):
            return dict(dev=iface, gateway=str(ipaddress.IPv4Address(row["gateway"])))
    raise RuntimeError("upstream interface %s has no gateway; set cypherpunk preferences --upstream-gateway" % iface)


FRONT_TABLE = "cypherpunk_vpn_front"
# Whole-device mode moves the default route into the tunnel; the I2P router's own packets
# (which carry that tunnel) keep the underlay through this routing table and rule.
FRONT_ROUTES = 7797


def front_routes(snapshot_default, uid):
    """Policy-route the I2P router's user over the underlay's default route."""
    cmd("ip", "rule", "del", "priority", str(FRONT_ROUTES), check=False)
    cmd("ip", "route", "flush", "table", str(FRONT_ROUTES), check=False)
    if not snapshot_default:
        raise RuntimeError("no underlay default route for the I2P router")
    route = snapshot_default[0]
    args = ["ip", "route", "replace", "default"]
    if route.get("gateway"):
        args += ["via", str(ipaddress.IPv4Address(route["gateway"]))]
    args += ["dev", valid_interface(route["dev"]), "table", str(FRONT_ROUTES)]
    cmd(*args)
    cmd(
        "ip",
        "rule",
        "add",
        "uidrange",
        "%d-%d" % (uid, uid),
        "lookup",
        str(FRONT_ROUTES),
        "priority",
        str(FRONT_ROUTES),
    )


def front_guard(profile):
    """A client behind an I2P front: install (or, without a front, remove) the table that
    keeps every packet of this host away from the entry's own address."""
    text = reset_table(FRONT_TABLE)
    if profile.get("front"):
        from i2p import front_firewall

        text += front_firewall(profile["network"]["relay_endpoint"].rsplit(":", 1)[0])
    nft(text)


def ensure_network(profile, state, whole=False, service_uid=0, upstream=None, upstream_gateway=None, front_uid=None):
    """Build this role's network (TUN, namespace, routes, firewall), snapshotting the prior state once."""
    role = profile["role"]
    n = profile["network"]
    rt = runtime_dir(state)
    snapshot = restore_dir(state, profile) / "network-before.json"
    before = read_json_private(snapshot)
    if before is None or (whole and not before["whole_device"]):
        routes = json.loads(cmd("ip", "-j", "route", "show", "default").stdout)
        # An older client could already have switched from Applications to Whole
        # device. Keep its original routes if the VPN has replaced the default.
        if before is not None and any(route.get("dev") == TUN for route in routes):
            routes = before["default"]
        save(snapshot, dict(default=routes, whole_device=whole))
    if role == "client":
        front = profile.get("front")
        if front and upstream:
            raise RuntimeError("an I2P front and an upstream entry are exclusive: the front already hides the entry")
        # Before anything else: behind a front, nothing here may reach the entry directly.
        front_guard(profile)
        if whole:
            if os.environ.get("SSH_CONNECTION"):
                raise RuntimeError("whole-device activation requires a local console")
            # Firewall is installed before any route change; errors leave traffic blocked.
            whole_firewall(profile, service_uid, front_uid)
        else:
            if cmd("ip", "netns", "list").stdout.split().count(APP) == 0:
                cmd("ip", "netns", "add", APP)
                save(rt / "namespace-owned.json", dict(schema=1, namespace=APP))
            elif not (rt / "namespace-owned.json").exists():
                raise RuntimeError("refusing an unrelated application namespace")
            cmd("ip", "-n", APP, "link", "set", "lo", "up")
            app_firewall(APP)
        ns = None if whole else APP
        relay_ip = n["relay_endpoint"].rsplit(":", 1)[0]
        if front:
            # The cloak reaches the entry only through the local I2P router: no route to it.
            upstream_firewall(n["relay_endpoint"], None)
            r = None
        elif upstream:
            # Upstream entry: the guard goes in before the route, and a missing upstream
            # refuses the connection instead of falling back to the direct path.
            r = upstream_route(upstream, upstream_gateway)
            upstream_firewall(n["relay_endpoint"], upstream)
        else:
            upstream_firewall(n["relay_endpoint"], None)
            r = route_to(relay_ip)
        mtu_rows = json.loads(cmd("ip", "-j", "link", "show", "dev", r["dev"]).stdout) if r else None
        # The carrier rides inside the HTTP/3 cloak's QUIC: a full WireGuard datagram becomes a
        # 1420-byte QUIC UDP payload (cloak::OUTER_MTU), i.e. a 1448-byte IPv4 packet (+8 UDP +20 IP).
        # On a smaller path those packets cannot pass, and the cloak falls back to TLS 1.3 over
        # TCP 443 on its own (cloak::QUIC_FALLBACK_TIMEOUT), whose fixed cells TCP segments to
        # the path: the tunnel runs, never a direct path. Only below IPv4's 576-byte minimum
        # is nothing usable; refuse there, with the kill switch left up (fail closed).
        if mtu_rows and mtu_rows[0]["mtu"] < UNDERLAY_MIN_MTU:
            if mtu_rows[0]["mtu"] < 576:
                raise RuntimeError("underlay MTU %d below IPv4's 576-byte minimum" % mtu_rows[0]["mtu"])
            print(
                "underlay MTU %d is below %d: the camouflage carries the tunnel over TLS/TCP"
                % (mtu_rows[0]["mtu"], UNDERLAY_MIN_MTU),
                file=sys.stderr,
            )
        if r:
            args = ["ip", "route", "replace", relay_ip + "/32"]
            if "gateway" in r:
                args += ["via", r["gateway"]]
            args += ["dev", r["dev"]]
            cmd(*args)
        tun(WG, "10.78.0.2/32", 1340, owner=service_uid)
        cmd("ip", "route", "replace", "10.78.0.1/32", "dev", WG)
        tun(TUN, "10.77.0.2/32", profile["core"]["mtu"], ns, owner=service_uid)
        if front and whole:
            front_routes(json.loads(read_private(snapshot))["default"], front_uid)
        prefix = ["ip", "-n", ns] if ns else ["ip"]
        cmd(*prefix, "route", "replace", "default", "dev", TUN)
        # The resolver file is public data, mounted only into isolated app processes.
        resolver = rt / "resolv.conf"
        resolver.write_text("nameserver 10.77.0.1\noptions timeout:2 attempts:2\n")
        resolver.chmod(0o644)
        if whole:
            target = Path("/etc/resolv.conf").resolve()
            if resolved_managed(target):
                # systemd-resolved owns resolv.conf and would discard a rewrite while
                # still querying the (firewalled) DHCP resolver. Route every name to
                # the exit resolver on the tunnel link instead; resolved drops these
                # link settings itself when cpvpn0 is removed.
                cmd("resolvectl", "dns", TUN, "10.77.0.1")
                cmd("resolvectl", "domain", TUN, "~.")
                cmd("resolvectl", "default-route", TUN, "yes")
            else:
                original = restore_dir(state, profile) / "resolv.before"
                if not original.exists():
                    shutil.copyfile(target, original)
                    original.chmod(0o600)
                target.write_text(resolver.read_text())
    elif role == "middle":
        # A middle relay only forwards the next layer's ciphertext: no TUN, no carrier,
        # no inner routes. Its QUIC listener is authenticated by pinned ML-DSA keys.
        pass
    elif role == "relay":
        tun(WG, "10.78.0.1/32", 1340, owner=service_uid)
        cmd("ip", "route", "replace", "10.78.0.2/32", "dev", WG)
        # Outer QUIC is accepted only on the authenticated WireGuard carrier, and the
        # carrier only from the local cloak, which owns the public port.
        replace_table("table inet cypherpunk_vpn {" + first_hop_rules(profile) + "\n}\n")
    else:
        carrier_first_hop = profile["carrier"] is not None  # single-hop chain: exit terminates WireGuard
        if carrier_first_hop:
            tun(WG, "10.78.0.1/32", 1340, owner=service_uid)
            cmd("ip", "route", "replace", "10.78.0.2/32", "dev", WG)
        tun(TUN, "10.77.0.1/32", profile["core"]["mtu"], owner=service_uid)
        cmd("ip", "route", "replace", "10.77.0.2/32", "dev", TUN)
        endpoint = profile["dns"]["upstream"].rsplit(":", 1)[0]
        # A recursive exit's upstream is its own loopback resolver: find the internet
        # interface by the default route instead (TEST-NET-1, a routing lookup only).
        wan = route_to("192.0.2.1" if profile["dns"].get("recursive") else endpoint)["dev"]
        cmd("/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        # Never forward inner packets into an unrequested management/metadata/LAN destination.
        private = "ip daddr {0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4} drop"
        carrier_input = first_hop_rules(profile) if carrier_first_hop else ""
        replace_table(
            """table inet cypherpunk_vpn {"""
            + carrier_input
            + """
 chain prerouting { type nat hook prerouting priority dstnat;
  iifname "cpvpn0" ip daddr 10.77.0.1 udp dport 53 redirect to :1053
  iifname "cpvpn0" ip daddr 10.77.0.1 tcp dport 53 redirect to :1053
 }
 chain forwarding { type filter hook forward priority -100; policy accept;
  iifname "cpvpn0" ip saddr != 10.77.0.2 drop
  iifname "cpvpn0" """
            + private
            + '''
  iifname "cpvpn0" meta nfproto ipv6 drop
  oifname "cpvpn0" ip daddr != 10.77.0.2 drop
 }
 chain postrouting { type nat hook postrouting priority srcnat;
  ip saddr 10.77.0.2 oifname "'''
            + wan
            + """" masquerade
 }
}\n"""
        )


MIN_GRANT = 65536


class Allowance:
    """Conservative reservations survive crashes; restarting cannot reset the daily budget.

    A grant is reserved durably before the carrier starts. When the carrier stops
    under supervision, the bytes the kernel meter did not count are released, so
    restarts do not consume the allowance. A supervisor crash keeps its grant
    reserved (over-counting, never under-counting).
    """

    def __init__(self, path, limit):
        self.path = path
        self.limit = limit

    @staticmethod
    def today():
        """Today's date in UTC, the budget's accounting day."""
        return dt.datetime.now(dt.timezone.utc).date().isoformat()

    def _load(self, day):
        old = json.loads(read_private(self.path)) if self.path.exists() else dict(day=day, reserved=0)
        if day < old["day"]:
            raise RuntimeError("clock rollback; budget remains closed")
        if day > old["day"]:
            old = dict(day=day, reserved=0)
        return old

    def reserve(self, amount, day=None):
        """Reserve `amount` bytes of today's budget; refuse when it would exceed the limit."""
        day = day or self.today()
        old = self._load(day)
        if old["reserved"] + amount > self.limit:
            raise RuntimeError("daily privacy budget exhausted")
        old["reserved"] += amount
        save(self.path, old)
        return old

    def grant(self, chunk, day=None):
        """Reserve up to `chunk`, never less than the carrier minimum."""
        day = day or self.today()
        old = self._load(day)
        amount = min(chunk, self.limit - old["reserved"])
        if amount < MIN_GRANT:
            raise RuntimeError("daily privacy budget exhausted")
        self.reserve(amount, day)
        return amount, day

    def release(self, amount, day):
        """Return unused bytes of a grant reserved on `day`; a later day already reset."""
        if amount <= 0 or not self.path.exists():
            return
        old = json.loads(read_private(self.path))
        if old["day"] != day:
            return
        old["reserved"] = max(0, old["reserved"] - amount)
        save(self.path, old)


def identity_of(pid):
    """The kernel start time of `pid` (field 22 of /proc/PID/stat), or None; detects PID reuse."""
    try:
        return Path("/proc/" + str(pid) + "/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def stop(proc):
    """Stop a child process: SIGTERM, then SIGKILL after 3 seconds."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def child_guard(parent, uid=0, gid=0):
    """Crash ties child lifetime to supervisor; data-plane executables get no capabilities."""
    import ctypes

    lib = ctypes.CDLL(None)
    if os.getppid() != parent:
        os._exit(1)
    for cap in range(64):
        lib.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP; unsupported IDs are harmless.
    if uid:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    # setuid clears PDEATHSIG, so set and race-check it after changing identity.
    if lib.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(1)
    if lib.prctl(38, 1, 0, 0, 0) != 0:
        os._exit(1)


def service_identity(lab):
    """The unprivileged UID/GID the data plane runs as (the mapped lab user, or `cypherpunk-vpn`)."""
    if lab:
        lab_guard()

        def mapped(path):
            return any(
                int(p[0]) <= 1 < int(p[0]) + int(p[2])
                for p in (row.split() for row in Path(path).read_text().splitlines())
            )

        return (1, 1) if mapped("/proc/self/uid_map") and mapped("/proc/self/gid_map") else (0, 0)
    user = pwd.getpwnam("cypherpunk-vpn")
    if user.pw_uid == 0 or user.pw_gid == 0:
        raise RuntimeError("a dedicated non-root service identity is required")
    return user.pw_uid, user.pw_gid


def owned_public(path, data, uid, gid):
    """Publish a file for the service UID inside a directory that UID can write.

    Root never touches the path after the rename: a compromised data-plane process
    could swap it for a symlink and redirect a path-based chmod/chown onto any file
    (privilege escalation). Mode and owner are set through the descriptor first;
    mode before owner because the unit has no CAP_FOWNER."""
    import secrets

    tmp = path.with_name("." + path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), 0o600)
            os.fchown(f.fileno(), uid, gid)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


# The data-plane executable for each section of the runtime configuration, and the key
# descriptors it receives. The cloak gets only its proof key (and, on the first hop, its
# ECDSA server key): never a WireGuard or layer key.
BINARIES = {
    "core": "cypherpunk-vpn",
    "carrier": "cypherpunk-vpn-wireguard",
    "dns": "cypherpunk-vpn-dns",
    "cloak": "cypherpunk-vpn-cloak",
}
CHILD_KEYS = {"core": ["outer", "middle", "inner", "link"], "carrier": ["wireguard"], "cloak": ["token", "cloak"]}
# The I2P front's router (i2pd) is not ours: an unmodified, separately installed program
# under its own user, configured in a RAM directory only that user can read.
FRONT_USER = "cypherpunk-vpn-i2p"
I2PD_PATHS = ["/usr/sbin/i2pd", "/usr/bin/i2pd"]


def front_identity(lab):
    """The I2P router's own UID/GID: `cypherpunk-vpn-i2p`, or the mapped lab user 2."""
    if lab:
        lab_guard()
        mapped = any(
            int(p[0]) <= 2 < int(p[0]) + int(p[2])
            for p in (row.split() for row in Path("/proc/self/uid_map").read_text().splitlines())
        )
        if not mapped:
            raise RuntimeError("the I2P front lab needs a mapped user 2 (unshare --map-auto)")
        return 2, 2
    user = pwd.getpwnam(FRONT_USER)
    if user.pw_uid == 0 or user.pw_gid == 0:
        raise RuntimeError("a dedicated non-root I2P identity is required")
    return user.pw_uid, user.pw_gid


# Oldest i2pd the front is proven with. 2.49 (Ubuntu 24.04) rejected the private test
# network's router records and never bootstrapped; nothing older is trusted unproven.
I2PD_MINIMUM = (2, 56, 0)


def i2pd_version(binary):
    """The (major, minor, patch) i2pd reports, or None if it does not say."""
    out = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=15).stdout
    m = re.search(r"i2pd version (\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else None


def front_binary(lab):
    """i2pd, at least I2PD_MINIMUM: root-owned and not writable by others (lab: $CPVPN_I2PD)."""
    path = None
    if lab and os.environ.get("CPVPN_I2PD"):
        path = Path(os.environ["CPVPN_I2PD"])
    else:
        for candidate in map(Path, I2PD_PATHS):
            if candidate.exists():
                st = candidate.stat()
                if candidate.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
                    raise RuntimeError("i2pd must be root-owned and not group/world writable")
                path = candidate
                break
    if path is None:
        raise RuntimeError("the I2P front needs i2pd (apt install i2pd; cypherpunk help front)")
    version = i2pd_version(path)
    if version is None or version < I2PD_MINIMUM:
        raise RuntimeError(
            "the I2P front needs i2pd %s or newer (found %s); see cypherpunk help front"
            % (".".join(map(str, I2PD_MINIMUM)), ".".join(map(str, version)) if version else "unknown")
        )
    return path


def prepare_front(profile, key_handles, uid, gid, lab=False):
    """The I2P router's RAM directory (owned by its user): router and tunnel files, and on
    the entry its destination's private keys. Lab only: $CPVPN_LAB_I2P names a private test
    network (JSON: netid, reseed zip, this node's address)."""
    import tempfile

    import i2p

    base = Path("/run/cypherpunk-vpn-runtime-" + str(os.stat("/proc/self/ns/net").st_ino))
    d = Path(tempfile.mkdtemp(prefix="i2p-", dir=base))
    d.chmod(0o700)
    os.chown(d, uid, gid)
    testnet = (
        json.loads(Path(os.environ["CPVPN_LAB_I2P"]).read_text()) if lab and os.environ.get("CPVPN_LAB_I2P") else None
    )
    front = profile["front"]
    if profile["role"] == "client":
        conf = i2p.router_conf(d, verbose=lab, testnet=testnet)
        tunnels = i2p.tunnels_conf(front)
    else:
        host = profile["network"]["relay_endpoint"].rsplit(":", 1)[0]
        conf = i2p.router_conf(d, host=host, port=front["router_port"], verbose=lab, testnet=testnet)
        keys = fd_bytes(key_handles["i2p"])
        i2p.private_identity(keys)
        owned_public(d / "front.dat", keys, uid, gid)
        tunnels = i2p.tunnels_conf(front, d / "front.dat", d)
    owned_public(d / "i2pd.conf", conf.encode(), uid, gid)
    owned_public(d / "tunnels.conf", tunnels.encode(), uid, gid)
    return d


def launch_front(binary, directory, uid, gid, log=None, lab=False):
    """Start i2pd under its own user, without capabilities, tied to the supervisor."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    if lab and os.environ.get("LD_LIBRARY_PATH"):
        env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
    return subprocess.Popen(
        [str(binary), "--datadir", str(directory), "--conf", str(directory / "i2pd.conf"),
         "--tunconf", str(directory / "tunnels.conf")],
        preexec_fn=functools.partial(child_guard, os.getpid(), uid, gid),
        env=env,
        cwd=str(directory),
        stdout=log or subprocess.DEVNULL,
        stderr=log or subprocess.DEVNULL,
    )  # fmt: skip


CLOAK_TOKEN_LABEL = b"cypherpunk-vpn cloak"


# A working carrier always receives real data: the chain's inner QUIC keep-alives every
# 2 s. One that has received none for this long is stuck and is restarted. (Seen in strong
# mode: GotaTun's DAITA can stop releasing the packets Tamaraw holds back, for example
# after the first hop was unreachable at start; a fresh carrier recovers.)
CARRIER_STALL_SECONDS = 12
# The restart threshold is jittered around that mean (roadmap item 13.6): a fixed
# threshold would restart every client's carrier at the same offset after a hop
# fails, and an observer between two hops could correlate the restarts.
CARRIER_STALL_JITTER = 4
# Drawn from the operating system's CSPRNG: the point is that an observer cannot predict
# the next restart moment, which a seedable generator's earlier outputs would let it do.
_JITTER = random.SystemRandom().uniform


class CarrierWatch:
    """Notices a client carrier whose received-byte counter has stopped moving."""

    def __init__(self, limit=CARRIER_STALL_SECONDS, jitter=CARRIER_STALL_JITTER, rng=_JITTER):
        self.limit, self.jitter, self.rng = limit, jitter, rng
        self.pid = self.rx = self.since = None
        self.window = float(limit)

    def stalled(self, pid, rx, now):
        """True when carrier `pid` has received no new bytes for its stall window.
        A new process, or any received byte, starts the clock again and draws a
        fresh window in [limit - jitter, limit + jitter]."""
        if pid != self.pid or rx is None or rx != self.rx:
            self.pid, self.rx, self.since = pid, rx, now
            self.window = self.limit + self.rng(-self.jitter, self.jitter)
            return False
        return now - self.since >= self.window


def verdict_fields(evidence, probe, rt, supervising, now=None):
    """The status fields of the protection verdict: what the cloak and the carrier report
    (counted only while their status files are fresh) and when the probe last got through.
    The kill switch is in force whenever the supervisor runs."""
    now = time.time() if now is None else now
    seen = {}
    for name in ("cloak", "carrier"):
        path = rt / (name + "-status.json")
        try:
            seen[name] = (json.loads(path.read_text()), path.stat().st_mtime)
        except (OSError, ValueError):
            seen[name] = (None, None)
    evidence.observe(now, *seen["cloak"], *seen["carrier"], probe.ok_at if probe else None)
    verdict = evidence.verdict(now, supervising=supervising, kill_switch=True)
    if probe and probe.diagnostics is not None:
        verdict["path_check"] = probe.diagnostics
    return verdict


def carrier_rx(state):
    """The client carrier's received data bytes, decoys excluded (the far end's DAITA keeps
    sending decoys even when this carrier is stuck), or None when unreadable."""
    try:
        c = json.loads((runtime_dir(state) / "carrier-status.json").read_text())
        return int(c["rx_bytes"]) - int(c["rx_decoy_bytes"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def cloak_token(wireguard_key):
    """The cloak's proof key: HMAC-SHA256 of the chain's WireGuard PSK (the last 32 bytes
    of the carrier key), so both ends share it without another secret."""
    if len(wireguard_key) != 64:
        raise ValueError("unexpected carrier key")
    return hmac.new(wireguard_key[32:], CLOAK_TOKEN_LABEL, hashlib.sha256).digest()


def publish_runtime(cfg, directory, uid, gid):
    """Only public files/config enter the service-owned directory. Keys are FD-only."""
    published = json.loads(json.dumps(cfg))
    for lane in ["outer", "middle", "inner"]:
        i = published["core"].get(lane)
        if not i:
            continue
        for field in ["ca", "cert"]:
            source = Path(i[field])
            target = directory / source.name
            owned_public(target, read_private(source), uid, gid)
            i[field] = str(target)
        i["key"] = str(directory / (lane + "-private-key.fd-only"))
    if "carrier" in published:
        i = published["carrier"]["identity"]
        source = Path(i["cert"])
        target = directory / source.name
        owned_public(target, read_private(source), uid, gid)
        i["cert"] = str(target)
        i["key"] = str(directory / "wireguard-private-key.fd-only")
        published["carrier"]["statistics"] = str(directory / "carrier-status.json")
    if "cloak" in published:
        c = published["cloak"]
        if c["cert"]:
            source = Path(c["cert"])
            target = directory / source.name
            owned_public(target, read_private(source), uid, gid)
            c["cert"] = str(target)
        c["statistics"] = str(directory / "cloak-status.json")
    if published.get("dns", {}).get("test_ca"):
        source = Path(published["dns"]["test_ca"])
        target = directory / source.name
        owned_public(target, read_private(source), uid, gid)
        published["dns"]["test_ca"] = str(target)
    if published.get("dns", {}).get("allowlist"):
        source = Path(published["dns"]["allowlist"])
        target = directory / source.name
        owned_public(target, read_private(source), uid, gid)
        published["dns"]["allowlist"] = str(target)
    if published.get("dns", {}).get("blocklist"):
        source = Path(published["dns"]["blocklist"])
        target = directory / source.name
        owned_public(target, read_private(source), uid, gid)
        published["dns"]["blocklist"] = str(target)
    if "resolver" in published:
        import exit_resolver

        owned_public(
            directory / "unbound.conf", exit_resolver.config(published["resolver"]["listen"]).encode(), uid, gid
        )
    for name, value in published.items():
        owned_public(directory / (name + ".runtime.json"), canonical(value), uid, gid)


def prepare_runtime(cfg, bin_dir, state, uid, gid, lab=False):
    """Stage the binaries and config into a root-owned runtime directory the service user can only read."""
    import tempfile

    base = Path("/run/cypherpunk-vpn-runtime-" + str(os.stat("/proc/self/ns/net").st_ino))
    base.mkdir(mode=0o711, exist_ok=True)
    if base.is_symlink() or base.stat().st_uid != 0 or base.stat().st_mode & 0o022:
        raise RuntimeError("unsafe runtime parent")
    base.chmod(0o711)
    executables = base / "bin" if lab else bin_dir
    if lab:
        executables.mkdir(mode=0o755, exist_ok=True)
        executables.chmod(0o755)
        # Only what this device runs: a middle relay never stages the cloak or WireGuard.
        for name in [BINARIES[section] for section in cfg if section in BINARIES]:
            src = bin_dir / name
            tmp = executables / (name + ".tmp")
            shutil.copyfile(src, tmp)
            tmp.chmod(0o755)
            os.replace(tmp, executables / name)
    else:
        for name in [BINARIES[section] for section in cfg if section in BINARIES]:
            path = executables / name
            if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                raise RuntimeError("installed binaries must be root-owned and not group/world writable")
    directory = Path(tempfile.mkdtemp(prefix="device-", dir=base))
    directory.chmod(0o700)
    os.chown(directory, uid, gid)
    publish_runtime(cfg, directory, uid, gid)
    for section in ["carrier", "cloak"]:
        if section in cfg:
            link = runtime_dir(state) / (section + "-status.json")
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(directory / (section + "-status.json"))
    return executables, directory


def carrier_meter(profile, grant):
    """Install the nftables quota that meters carrier bytes against today's grant."""
    port = profile["carrier"]["listen_port"]
    text = (
        reset_table("cypherpunk_vpn_meter")
        + """table inet cypherpunk_vpn_meter {
 quota carrier { over """
        + str(grant)
        + """ bytes; }
 chain output { type filter hook output priority -110; policy accept;
  udp sport """
        + str(port)
        + """ quota name "carrier" drop
  udp sport """
        + str(port)
        + """ limit rate over 2 mbytes/second burst 1 mbytes drop
 }
 chain input { type filter hook input priority -110; policy accept;
  udp dport """
        + str(port)
        + """ quota name "carrier" drop
 }
}\n"""
    )
    nft(text)


class ServerFees:
    """A server's monthly cap (tools/fee_guard.py) and egress lock (tools/server_egress.py):
    only VPN traffic leaves, a kernel quota stops it at what is left of the month, and the
    meter keeps the month's total across restarts and reboots. A production server without
    a cap refuses to start: a free account must never be billed."""

    CHECK_SECONDS = 5
    # Security updates, daily: the egress lock admits no update timer, so the supervisor
    # runs unattended-upgrade itself (Debian/Ubuntu default: the security origins only) in
    # a counted window. Skipped on a capped server, a shared host (its own business) and an
    # image host (a Fly.io Machine's root resets: its image is rebuilt instead).
    UPDATE_EVERY = 86400
    UPDATE_TIMEOUT = 1800
    # A failed update tries again in an hour, not at once: each attempt holds apt's lock
    # and opens the window, and an immediate retry kept both near-permanently in use.
    UPDATE_RETRY = 3600
    UPDATE_UNIT = "cypherpunk-vpn-security-update"
    # apt's download sandbox and the system resolver: root's updates go through both.
    UPDATE_HELPERS = ("_apt", "systemd-resolve", "systemd-resolved")

    def __init__(self, profile, cfg, state, service_uid, lab=False, front_uid=None):
        import fee_guard
        import server_egress

        self.fg, self.se = fee_guard, server_egress
        self.profile, self.cfg, self.uid, self.lab = profile, cfg, service_uid, lab
        # The I2P router a server's front runs under its own user: it must be let out too.
        self.front_uid = front_uid
        self.cap_path, usage = fee_guard.paths(state)
        self.maintenance_path = self.cap_path.with_name("maintenance-until")
        self.last_update_path = self.cap_path.with_name("last-update")
        self.update_proc = None
        self.update_started = 0.0
        self.update_retry_at = 0.0
        self.image = Path("/opt/cypherpunk-vpn/IMAGE").exists()
        self.shared = not lab and retention.SHARED_MARKER.exists()
        self.kind, self.cap = fee_guard.read_cap(self.cap_path)
        if self.kind == "missing" and not lab:
            raise RuntimeError(
                "no monthly cap on this server, so its account could be billed: set one with "
                "cypherpunk cloud cap NAME (or --unlimited for a host whose traffic you pay nothing for)"
            )
        self.meter = fee_guard.Meter(usage, source=self.vpn_counter if self.shared else None)
        self.installed = None  # (month, cap) the kernel quota was set for
        self.maintenance = False
        self.next_check = 0.0
        self.row = None

    def vpn_counter(self):
        """The VPN's own bytes (a shared host's meter source), from the quota table's counter."""
        r = cmd("/usr/sbin/nft", "-j", "list", "counter", "inet", self.se.QUOTA_TABLE, "vpn", check=False)
        if r.returncode:
            return {}
        raw = json.loads(r.stdout)
        return {"vpn": next(x["counter"]["bytes"] for x in raw["nftables"] if "counter" in x)}

    def in_maintenance(self, now):
        """Whether an update window is open: our own security update, or cypherpunk cloud host update."""
        if self.update_proc is not None:
            return True
        try:
            return now < float(self.maintenance_path.read_text().strip())
        except (OSError, ValueError):
            return False

    def egress_text(self):
        """The egress table as nft input, replacing any earlier one."""
        return reset_table(self.se.EGRESS_TABLE) + self.se.egress_rules(
            self.profile,
            self.cfg,
            self.uid,
            extra_uids=[self.front_uid] if self.front_uid else (),
            maintenance=self.maintenance,
            lab_transit=self.lab,
            maintenance_uids=self.update_helper_uids() if self.maintenance else (),
        )

    def update_helper_uids(self):
        """The users root's updates depend on, as present on this host."""
        import pwd

        found = []
        for name in self.UPDATE_HELPERS:
            try:
                found.append(pwd.getpwnam(name).pw_uid)
            except KeyError:
                pass
        return sorted(set(found))

    def install(self, now=None):
        """Lock egress (dedicated hosts) and set the quota; before any child starts."""
        now = time.time() if now is None else now
        self.maintenance = self.in_maintenance(now)
        if not self.shared:
            nft(self.egress_text())
        self.tick(now, force=True)

    def last_update(self):
        """When security updates last finished (epoch seconds; 0 if never)."""
        try:
            return self.last_update_path.stat().st_mtime
        except OSError:
            return 0.0

    def security_update(self, now, used):
        """Start the daily security update when due; collect it when done."""
        if self.update_proc is not None:
            done = self.update_proc.poll() is not None
            if not done and now - self.update_started > self.UPDATE_TIMEOUT:
                self.update_proc.kill()
                self.update_proc.wait()
                # The transient unit runs on its own: stop it, so nothing outlives the window.
                run_unit = shutil.which("systemctl")
                if run_unit:
                    subprocess.run([run_unit, "stop", self.UPDATE_UNIT + ".service"], capture_output=True, timeout=30)
                done = True
            if done:
                if self.update_proc.returncode == 0:
                    self.last_update_path.write_text(dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
                else:
                    self.update_retry_at = now + self.UPDATE_RETRY
                self.update_proc = None
            return
        exe = shutil.which("unattended-upgrade")
        capped = self.cap is not None and used >= self.cap
        if self.lab or self.shared or self.image or capped or not exe or now - self.last_update() < self.UPDATE_EVERY:
            return
        if now < self.update_retry_at:
            return
        # tick() opens the window (and tells the table watch) as soon as this process
        # exists; the download waits two seconds for it. Downloads give up rather than hang.
        self.update_started = now
        apt_update = (
            "sleep 2 && apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 "
            "-o Acquire::https::Timeout=30 update -qq && " + shlex.quote(exe)
        )
        # In its own transient unit: this service's sandbox (RestrictSUIDSGID, its
        # capability set) stops dpkg setting a setuid file, so a sudo update never installed.
        # The unit's own limit ends it before the window does.
        argv = ["/bin/sh", "-c", apt_update]
        systemd_run = shutil.which("systemd-run")
        if systemd_run:
            argv = [systemd_run, "--wait", "--collect", "--quiet", "--unit=" + self.UPDATE_UNIT,
                    "--property=RuntimeMaxSec=%d" % (self.UPDATE_TIMEOUT - 100),
                    "--setenv=DEBIAN_FRONTEND=noninteractive", "--", *argv]  # fmt: skip
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        self.update_proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                                            start_new_session=True)  # fmt: skip

    def quota_present(self):
        """Whether the kernel quota table still exists."""
        return cmd("/usr/sbin/nft", "list", "table", "inet", self.se.QUOTA_TABLE, check=False).returncode == 0

    def tick(self, now=None, force=False, tables=None):
        """Every few seconds: count, follow the cap file and the month, keep the quota and
        the maintenance window current. Returns the status row's `monthly` field."""
        now = time.time() if now is None else now
        if not force and now < self.next_check and self.row is not None:
            return self.row
        self.next_check = now + self.CHECK_SECONDS
        try:
            kind, cap = self.fg.read_cap(self.cap_path)
            # A cap file removed while running never lifts the cap (only a lab runs uncapped).
            if kind != "missing" or self.lab:
                self.kind, self.cap = kind, cap
        except self.fg.FeeGuardError:
            pass  # a malformed edit keeps the cap last read, never none
        used = self.meter.sample()
        key = (self.meter.month, self.cap)
        if force or key != self.installed or not self.quota_present():
            remaining = (1 << 62) if self.cap is None else self.cap - used
            nft(reset_table(self.se.QUOTA_TABLE) + self.se.quota_rules(remaining, self.uid, self.shared))
            self.installed = key
        self.security_update(now, used)
        maintenance = self.in_maintenance(now)
        if maintenance != self.maintenance and not self.shared:
            self.maintenance = maintenance
            nft(self.egress_text())
            if tables is not None:
                tables.expected[(self.se.EGRESS_TABLE, None)] = tables.listing(self.se.EGRESS_TABLE)
        self.row = self.fg.verdict(used, self.cap, now)
        # The kernel quota counts IP packets, the meter interface frames: whichever reaches
        # the cap first, the server is capped (traffic is already being dropped).
        if self.cap is not None and self.quota_spent():
            self.row["capped"] = True
        self.row.update(egress_lock="off (shared host)" if self.shared else "on", maintenance=self.maintenance)
        return self.row

    def quota_spent(self):
        """Whether the kernel quota has dropped traffic for this month already."""
        r = cmd("/usr/sbin/nft", "-j", "list", "quota", "inet", self.se.QUOTA_TABLE, "month", check=False)
        if r.returncode:
            return False
        q = next(x["quota"] for x in json.loads(r.stdout)["nftables"] if "quota" in x)
        return q.get("used", 0) >= q.get("bytes", 1 << 62)


def meter_used():
    """Bytes counted by the kernel carrier quota, or None when it cannot be read."""
    r = cmd("/usr/sbin/nft", "-j", "list", "quota", "inet", "cypherpunk_vpn_meter", "carrier", check=False)
    if r.returncode:
        return None
    for row in json.loads(r.stdout)["nftables"]:
        q = row.get("quota")
        if q:
            return int(q.get("used", 0)), int(q["bytes"])
    return None


def meter_spent():
    """Whether the current grant is used up (or the meter is missing, which counts as used up)."""
    m = meter_used()
    return m is None or m[0] >= m[1]


def remove_meter():
    """Remove the carrier meter table."""
    cmd("/usr/sbin/nft", "delete", "table", "inet", "cypherpunk_vpn_meter", check=False)


def daily_limit(preferences, profile):
    """None means no cap (the default). A preference overrides the enrolled value."""
    if "daily_limit_mib" in preferences:
        v = preferences["daily_limit_mib"]
        return None if v is None else int(v) * 1048576
    return profile["daily_budget_bytes"]


def launch_core(binary, config, ns, log=None, key_fds=None, uid=0, gid=0):
    """Attach the managed TUN as root, then launch the core unprivileged on the underlay."""
    import struct

    with contextlib.ExitStack() as descriptors:
        with contextlib.ExitStack() as namespace:
            if ns is not None:
                current = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                namespace.callback(os.close, current)
                app = os.open("/run/netns/" + ns, os.O_RDONLY | os.O_CLOEXEC)
                namespace.callback(os.close, app)
                os.setns(app, os.CLONE_NEWNET)
                namespace.callback(os.setns, current, os.CLONE_NEWNET)
            fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            descriptors.callback(os.close, fd)
            fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", TUN.encode(), 0x1001))
        extra = []
        inherited = [fd]
        for name, value in (key_fds or {}).items():
            extra += ["--key-fd", name + "=" + str(value)]
            inherited.append(value)
        return subprocess.Popen(
            [binary, "--config", str(config), "--tun-fd", str(fd), *extra],
            pass_fds=inherited,
            preexec_fn=functools.partial(child_guard, os.getpid(), uid, gid),
            stdout=log or subprocess.DEVNULL,
            stderr=log or subprocess.DEVNULL,
        )


@contextlib.contextmanager
def supervisor_locks(state):
    """Exclude other supervisors and route selection in the current network namespace."""
    rt = runtime_dir(state)
    net_lock = "/run/cypherpunk-vpn-" + str(os.stat("/proc/self/ns/net").st_ino) + ".lock"
    with contextlib.ExitStack() as stack:
        for path in (rt / "controller.lock", net_lock):
            lock = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            stack.callback(os.close, lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("The VPN is active or changing chains. Disconnect before switching") from None
        yield rt


def supervise(state, bin_dir, lab=False, whole=None):
    """The supervisor: build the network, start and restart the data plane, enforce the budget, write status."""
    root_guard(lab)
    with supervisor_locks(state) as rt:
        if whole is None:
            whole = read_json_private(state / "preferences.json", {}).get("mode") == "whole-device"
        _supervise(state, bin_dir, lab, whole, rt)


def _supervise(state, bin_dir, lab, whole, rt):
    # Refuse an unpadded chain before anything on the host changes. reset, guard and
    # info still accept it, so the kill switch can always be cleared to re-sign.
    profile = load_profile(state)
    try:
        require_current(profile)
    except ValueError as e:
        raise RuntimeError(str(e)) from None
    # A server never writes a log to disk: refuse to carry traffic on one that would.
    # (Lab servers share the developer's host, whose logging is not theirs to judge.)
    if profile["role"] != "client" and not lab:
        failing = retention.failures()
        if failing and not retention.SHARED_MARKER.exists():
            raise RuntimeError(
                "this server would keep logs on disk (%s); run cypherpunk cloud host setup on it, or rebuild it "
                "with cypherpunk cloud (cypherpunk help retention)" % "; ".join(name for name, _, _ in failing)
            )
    uid, gid = service_identity(lab)
    front_uid, front_gid = front_identity(lab) if profile.get("front") else (None, None)
    save(rt / "controller.json", dict(pid=os.getpid(), identity=identity_of(os.getpid())))
    early = read_json_private(state / "preferences.json", {}) if profile["role"] == "client" else {}
    if whole and not lab:
        import guard_policy

        guard_policy.arm(apply=True, state=state)
    ensure_network(
        profile,
        state,
        whole,
        uid,
        upstream=early.get("upstream_interface"),
        upstream_gateway=early.get("upstream_gateway"),
        front_uid=front_uid,
    )
    cfg = runtime(profile, state)
    # A server sends only VPN traffic and never past its monthly cap (no fees from a
    # free account), from before its data plane first starts.
    fees = None
    if profile["role"] != "client":
        fees = ServerFees(profile, cfg, state, uid, lab, front_uid=front_uid)
        fees.install()
    # Watch every table this role just built: whole device or the app namespace for a
    # client (plus its front and upstream guards), the host and egress tables on a server.
    table_ns = APP if profile["role"] == "client" and not whole else None
    tables = TableWatch(
        [
            ("cypherpunk_vpn", table_ns),
            ("cypherpunk_vpn_front", None),
            (UPSTREAM_TABLE, None),
            ("cypherpunk_vpn_egress", None),
        ]
    )
    last_table_check = 0.0
    firewall_tampered = False
    preferences = json.loads(read_private(state / "preferences.json")) if (state / "preferences.json").exists() else {}
    from keyguard import memory_fd

    # One unlock (Nitrokey PIN+touch, TPM-bound systemd-creds, or explicit plaintext)
    # moves each key into a sealed memfd. No Python copy is kept: rotation reads the
    # key back from its descriptor only for the moment it signs a fresh leaf.
    # A hardware-protected client never holds its long-term identities here
    # (docs/HARDWARE_BOUND_SESSIONS.md): each session gets fresh layer keys, which a
    # short-lived signer process certifies after the key's touch and PIN, and every hop
    # refuses leaves the key did not authorize.
    names = list(managed_identities(cfg))
    key_handles = {}
    session_end = None

    def install_session(signed):
        for lane, key in signed["keys"].items():
            if lane in key_handles:
                os.close(key_handles[lane])
            key_handles[lane] = memory_fd(key)
            leaf = rt / (lane + "-active-cert.der")  # supervisor: RAM-only runtime dir
            atomic(leaf, signed["leaves"][lane])
            cfg["core"][lane]["cert"] = str(leaf)
        return signed["not_after"]

    if profile["role"] == "client" and json.loads(read_private(state / "protection.json"))["mode"] == "nitrokey":
        signed = sign_session(cfg["core"], state, carry=[n for n in names if n not in LAYER_KEYS])
        key_handles.update({name: memory_fd(value) for name, value in signed.pop("carry").items()})
        session_end = install_session(signed)
        del signed
    else:
        key_handles.update({name: memory_fd(value) for name, value in load_keys(state, names).items()})
    if "cloak" in cfg:
        key_handles["token"] = memory_fd(cloak_token(fd_bytes(key_handles["wireguard"])))
        if cfg["cloak"]["role"] == "server":
            # A fresh self-signed certificate for the pinned key, in root-only RAM.
            cert = rt / "cloak-cert.der"
            atomic(cert, cloak_certificate(fd_bytes(key_handles["cloak"]), cfg["cloak"]["cover_name"]))
            cfg["cloak"]["cert"] = str(cert)
    if session_end is None:
        refresh_leaves(
            cfg["core"],
            state,
            {n: fd_bytes(key_handles[n]) for n in LAYER_KEYS if n in key_handles},
            out_dir=rt,
        )
    bin_dir, device_dir = prepare_runtime(cfg, bin_dir, state, uid, gid, lab)
    front_dir = front_exe = None
    if "front" in cfg:
        front_exe = front_binary(lab)
        front_dir = prepare_front(profile, key_handles, front_uid, front_gid, lab)
    for name in [n for n in cfg if n in BINARIES]:
        binary = bin_dir / BINARIES[name]
        fds = {r: v for r, v in key_handles.items() if r in CHILD_KEYS.get(name, [])}
        args = [str(binary), "--config", str(device_dir / (name + ".runtime.json")), "--check"]
        for r, value in fds.items():
            args += ["--key-fd", r + "=" + str(value)]
        parent = os.getpid()
        subprocess.run(
            args,
            check=True,
            pass_fds=list(fds.values()),
            preexec_fn=functools.partial(child_guard, parent, uid, gid),
            capture_output=True,
            timeout=15,
        )
    quit_requested = False
    rotate_requested = False

    def quit_handler(*_):
        nonlocal quit_requested
        quit_requested = True

    for signum in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(signum, quit_handler)

    def rotate_handler(*_):
        nonlocal rotate_requested
        rotate_requested = True

    signal.signal(signal.SIGHUP, rotate_handler)
    children = {}
    last_launch = {}
    backoff = {}
    last_refresh = time.monotonic()
    retry_session = 0.0
    stop_reason = "disconnected"
    # The verdict a client's status carries (the GUI's "Connected"): fresh cloak and carrier
    # status plus a probe answered through the whole chain (tools/protection.py).
    probe = evidence = None
    if profile["role"] == "client":
        import protection

        evidence = protection.Evidence()
        probe = protection.PathProbe(None if whole else "/run/netns/" + APP)
        probe.start()
        # A chain that stops answering (a server stopped, reclaimed, locked after a reboot,
        # out of credits) is made obvious: a desktop notice and a line in `cypherpunk status`.
        import chain_watch

        chain_notice = chain_watch.ChainWatch(chain_watch.desktop_notify)
    last_meter = 0
    # The optional daily cap is client-only: a server never stores byte counts.
    allowance = Allowance(
        state / "allowance.json", daily_limit(preferences, profile) if profile["role"] == "client" else None
    )
    active_grant = None
    budget_blocked = False
    budget_retry = 0

    def settle_grant():
        # Called only after the carrier has stopped: refund what the kernel did not count.
        nonlocal active_grant
        if active_grant is None:
            return
        amount, day = active_grant
        active_grant = None
        m = meter_used()
        if m is not None:
            allowance.release(amount - min(m[0], amount), day)

    if "carrier" in cfg and allowance.limit is None:
        remove_meter()
    watch = CarrierWatch()
    try:
        while not quit_requested:
            if time.monotonic() - last_table_check >= 2:
                last_table_check = time.monotonic()
                try:
                    for name, ns in tables.check():
                        print(
                            "kill switch table %s restored%s: was %s"
                            % (name, " in " + ns if ns else "", tables.reasons.get((name, ns), "?")),
                            flush=True,
                        )
                except RuntimeError:
                    # Fail closed: no data plane while the kill switch cannot be held.
                    firewall_tampered = True
                    for proc in children.values():
                        stop(proc)
            if firewall_tampered:
                save(rt / "status.json", dict(schema=1, state="blocked", kill_switch=True, reason="firewall_tampering"))
                time.sleep(1)
                continue
            monthly = fees.tick(tables=tables) if fees is not None else None
            if monthly is not None and monthly["capped"]:
                # The kernel quota already drops; stopping the data plane makes the state
                # plain to every hop and to status. It resumes on the 1st (UTC) or when
                # the cap is raised.
                for proc in children.values():
                    stop(proc)
                children.clear()
                save(rt / "status.json", dict(schema=1, state="capped", kill_switch=True, role=profile["role"],
                                              scope="server", reason="monthly_cap", monthly=monthly))  # fmt: skip
                time.sleep(1)
                continue
            if (
                profile["role"] == "client"
                and "carrier" in children
                and children["carrier"].poll() is None
                and watch.stalled(children["carrier"].pid, carrier_rx(state), time.monotonic())
            ):
                stop(children["carrier"])
            if (
                "carrier" in children
                and children["carrier"].poll() is None
                and active_grant is not None
                and time.monotonic() - last_meter >= 1
            ):
                if meter_spent():
                    stop(children["carrier"])
                last_meter = time.monotonic()
            # A hardware session is renewed an hour before it ends, with a fresh PIN and
            # touch; if nobody answers, the leaves run out and every hop refuses them.
            renew = session_end is not None and time.time() >= session_end - 3600 and time.monotonic() >= retry_session
            if renew or (session_end is None and time.monotonic() - last_refresh >= 21600) or rotate_requested:
                renewed = True
                if session_end is not None:
                    try:
                        session_end = install_session(sign_session(cfg["core"], state))
                    except Exception as e:  # no answer at the key: the current leaves stay
                        print("hardware session not renewed: %s" % e, file=sys.stderr)
                        retry_session = time.monotonic() + 300
                        renewed = False
                else:
                    refresh_leaves(
                        cfg["core"],
                        state,
                        {n: fd_bytes(key_handles[n]) for n in LAYER_KEYS if n in key_handles},
                        out_dir=rt,
                    )
                if renewed:
                    publish_runtime(cfg, device_dir, uid, gid)
                    if "core" in children:
                        stop(children["core"])
                    last_refresh = time.monotonic()
                rotate_requested = False
            current_preferences = (
                json.loads(read_private(state / "preferences.json")) if (state / "preferences.json").exists() else {}
            )
            new_limit = daily_limit(current_preferences, profile)
            if new_limit != allowance.limit and "carrier" in cfg:
                # Switching between capped and uncapped needs a fresh carrier so the
                # carrier's own byte check and the kernel meter agree with the policy.
                allowance.limit = new_limit
                budget_blocked = False
                if "carrier" in children:
                    stop(children["carrier"])
            allowance.limit = new_limit
            for name in cfg:
                proc = children.get(name)
                if proc and proc.poll() is None:
                    continue
                if proc:
                    stop(proc)
                    # A child that ran stably (e.g. a carrier ending a metered grant) restarts promptly.
                    if time.monotonic() - last_launch.get(name, 0) > 30:
                        backoff[name] = 0.5
                if name == "carrier":
                    settle_grant()
                if time.monotonic() - last_launch.get(name, -1000) < backoff.get(name, 1):
                    continue
                if name == "carrier":
                    if allowance.limit is None:
                        remove_meter()
                        cfg[name]["byte_budget"] = None
                        budget_blocked = False
                    else:
                        if budget_blocked and time.monotonic() < budget_retry:
                            continue
                        try:
                            amount, day = allowance.grant(profile["carrier"]["byte_budget"])
                        except RuntimeError:
                            # Fail closed but stay alive: the guard holds, no carrier runs,
                            # and the next UTC day (or a raised limit) resumes service.
                            budget_blocked = True
                            budget_retry = time.monotonic() + 30
                            children.pop(name, None)
                            continue
                        budget_blocked = False
                        active_grant = (amount, day)
                        cfg[name]["byte_budget"] = amount
                        carrier_meter(profile, amount)
                    publish_runtime(cfg, device_dir, uid, gid)
                binary = str(bin_dir / BINARIES.get(name, ""))
                path = device_dir / (name + ".runtime.json")
                log = (rt / (name + ".lab.log")).open("a") if lab else None  # lab only; RAM like everything else
                fds = {r: v for r, v in key_handles.items() if r in CHILD_KEYS.get(name, [])}
                if name == "front":
                    children[name] = launch_front(front_exe, front_dir, front_uid, front_gid, log, lab)
                elif name == "resolver":
                    import exit_resolver

                    # Unbound, unmodified, as the service user, in the foreground, tied to
                    # the supervisor like every other child.
                    children[name] = subprocess.Popen(
                        [exit_resolver.unbound_path(), "-d", "-c", str(device_dir / "unbound.conf")],
                        preexec_fn=functools.partial(child_guard, os.getpid(), uid, gid),
                        stdout=log or subprocess.DEVNULL,
                        stderr=log or subprocess.DEVNULL,
                    )
                elif name == "core" and profile["role"] in ("client", "exit"):
                    ns = APP if profile["role"] == "client" and not whole else None
                    children[name] = launch_core(binary, path, ns, log, fds, uid, gid)
                else:
                    args = [binary, "--config", str(path)]
                    for r, value in fds.items():
                        args += ["--key-fd", r + "=" + str(value)]
                    parent = os.getpid()
                    children[name] = subprocess.Popen(
                        args,
                        pass_fds=list(fds.values()),
                        preexec_fn=functools.partial(child_guard, parent, uid, gid),
                        stdout=log or subprocess.DEVNULL,
                        stderr=log or subprocess.DEVNULL,
                    )
                if log:
                    log.close()
                last_launch[name] = time.monotonic()
                backoff[name] = min(backoff.get(name, 0.5) * 2, 10)
            if not quit_requested:
                row = dict(
                    schema=1,
                    state="blocked" if budget_blocked else "supervising",
                    kill_switch=True,
                    role=profile["role"],
                    scope=("whole-device" if whole else "applications") if profile["role"] == "client" else "server",
                    daily_limit_bytes=allowance.limit,
                    children={
                        k: dict(pid=v.pid, identity=identity_of(v.pid), alive=v.poll() is None)
                        for k, v in children.items()
                    },
                )
                if budget_blocked:
                    row["reason"] = "privacy_budget"
                if monthly is not None:
                    row["monthly"] = monthly
                if evidence is not None:
                    row.update(verdict_fields(evidence, probe, rt, supervising=not budget_blocked))
                    if not budget_blocked:
                        row.update(chain_notice.observe(time.time(), row))
                save(rt / "status.json", row)
            time.sleep(0.25)
    finally:
        if probe is not None:
            probe.stop.set()
        for p in children.values():
            stop(p)
        settle_grant()
        final = dict(schema=1, state="blocked", kill_switch=True, reason=stop_reason)
        if evidence is not None:
            final.update(protection="blocked", lifecycle="blocked", evidence=None, since=round(time.time(), 3))
        save(rt / "status.json", final)
        # Persistent nftables, TUN and namespace are deliberately retained on exit/crash.
        for fd in key_handles.values():
            os.close(fd)
        shutil.rmtree(device_dir, ignore_errors=True)
        if front_dir:
            shutil.rmtree(front_dir, ignore_errors=True)


def control_signal(state, signum):
    """Send `signum` to the live supervisor, refusing if its recorded PID now belongs to another process."""
    info = json.loads(read_private(runtime_dir(state) / "controller.json"))
    if identity_of(info["pid"]) != info["identity"]:
        raise RuntimeError("stale controller PID; refusing to signal unrelated process")
    os.kill(info["pid"], signum)


def _supervisor_gone(pid, identity):
    """True when `pid` no longer runs as `identity`: gone, or already dead and only
    waiting to be reaped (a zombie's /proc entry survives until its parent waits)."""
    try:
        data = Path("/proc/" + str(pid) + "/stat").read_text()
    except OSError:
        return True
    rest = data.rsplit(")", 1)[1].split()
    return rest[0] == "Z" or rest[19] != identity


def stop_supervisor(state, timeout=10):
    """SIGTERM the live supervisor for `state` and confirm it exits.

    Returns True when a supervisor was running and stopped within `timeout`
    seconds, False when none was (no record, or a stale PID from an earlier
    run). A supervisor that ignores SIGTERM is an error, not a success: the
    kill switch would stay held by a half-stopped controller. Disconnect is
    idempotent; rotate keeps using `control_signal`, where a stale PID stays
    an error."""
    record = runtime_dir(state, create=False) / "controller.json"
    try:
        info = json.loads(read_private(record))
    except (OSError, ValueError):
        return False
    try:
        pid, identity = int(info["pid"]), info["identity"]
    except (KeyError, TypeError, ValueError):
        return False
    if _supervisor_gone(pid, identity):
        return False
    deadline = time.monotonic() + timeout
    os.kill(pid, signal.SIGTERM)
    while time.monotonic() < deadline:
        if _supervisor_gone(pid, identity):
            return True
        time.sleep(0.1)
    raise RuntimeError("the supervisor did not stop within %d s" % timeout)


def fd_bytes(fd):
    """The whole contents of a sealed memfd."""
    return os.pread(fd, os.fstat(fd).st_size, 0)


def managed_identities(cfg):
    """The keys this profile's data-plane processes need, by role: certificate
    identities, plus the paced-link keys of a server in a multi-hop chain."""
    out = {r: cfg["core"][r] for r in ["outer", "middle", "inner"] if cfg["core"].get(r)}
    if cfg["core"].get("link_out") or cfg["core"].get("link_in"):
        out["link"] = {}  # per-hop shaping: the sealed link keys, no certificate
    if "carrier" in cfg:
        out["wireguard"] = cfg["carrier"]["identity"]
    if cfg.get("cloak", {}).get("role") == "server":
        out["cloak"] = cfg["cloak"]
    if "router_port" in cfg.get("front", {}):
        out["i2p"] = {}  # the entry's I2P destination keys
    return out


# Host resolver endpoints reachable over Unix sockets, which a network namespace does
# not isolate: nss-resolve (systemd-resolved varlink), nscd and avahi/mDNS.
RESOLVER_DIRS = ["/run/systemd/resolve", "/run/nscd", "/run/avahi-daemon"]
# The D-Bus system bus also reaches systemd-resolved (org.freedesktop.resolve1).
SYSTEM_BUS_SOCKETS = ["/run/dbus/system_bus_socket"]


def isolate_resolvers(resolver):
    """In the app's private mount namespace, hide every host resolver path so the
    only way to resolve a name is plain DNS to the tunnel resolver (10.77.0.1)."""
    for d in RESOLVER_DIRS:
        if Path(d).is_dir():
            cmd("mount", "-t", "tmpfs", "-o", "size=64k,mode=0755,nosuid,nodev,noexec", "tmpfs", d)
    for sock in SYSTEM_BUS_SOCKETS:
        if Path(sock).exists():
            cmd("mount", "--bind", "/dev/null", sock)
    # /etc/resolv.conf often links into /run/systemd/resolve, now an empty tmpfs.
    target = Path("/etc/resolv.conf").resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text("")
    cmd("mount", "--bind", str(resolver), str(target))


def run_app(state, argv, uid, gid, lab=False):
    """Run `argv` as `uid`/`gid` inside the protected namespace, with the host resolver sockets hidden."""
    root_guard(lab)
    if not argv:
        raise ValueError("application command required")
    if not lab and (uid <= 0 or gid <= 0):
        raise ValueError("non-root application UID/GID required")
    # Guard is recreated before every launch, even when the controller is stopped.
    app_firewall(APP)
    ns = os.open("/run/netns/" + APP, os.O_RDONLY | os.O_CLOEXEC)
    os.setns(ns, os.CLONE_NEWNET)
    os.close(ns)
    if {name for _, name in socket.if_nameindex()} != {"lo", TUN}:
        raise RuntimeError("application namespace has an escape interface")
    os.unshare(os.CLONE_NEWNS)
    cmd("mount", "--make-rprivate", "/")
    isolate_resolvers(runtime_dir(state) / "resolv.conf")
    if not lab:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    for key in list(os.environ):
        if key.lower().endswith("_proxy"):
            del os.environ[key]
    os.environ["MOZ_NO_REMOTE"] = "1"
    os.environ["MOZ_DBUS_REMOTE"] = "0"
    os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/nonexistent-cypherpunk-vpn-bus"
    import ctypes

    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError("cannot set no_new_privs")
    os.execvp(argv[0], argv)


def reset(state, lab=False):
    """Remove the kill switch and restore the saved routes; refuses while the supervisor or protected apps run."""
    root_guard(lab)
    if not lab:
        import guard_policy

        if Path(state).resolve() != guard_policy.STATE:
            raise ValueError("a different state cannot reset the installed device's networking")
    rt = runtime_dir(state)
    profile = load_profile(state)
    keep = restore_dir(state, profile)
    info = rt / "controller.json"
    if info.exists():
        value = json.loads(read_private(info))
        if identity_of(value["pid"]) == value["identity"]:
            raise RuntimeError("disconnect the live controller before explicitly unlocking")
    if (rt / "namespace-owned.json").exists():
        if cmd("ip", "netns", "pids", APP, check=False).stdout.strip():
            raise RuntimeError("protected applications still running; refusing to dismantle their guard")
        cmd("ip", "netns", "del", APP, check=False)
    # A server's snapshot is RAM-only; after a reboot there is nothing to restore.
    before = (
        json.loads(read_private(keep / "network-before.json"))
        if (keep / "network-before.json").exists()
        else dict(default=[], whole_device=False)
    )
    resolver_backup = keep / "resolv.before"
    if (
        before["whole_device"]
        or resolver_backup.exists()
        or (
            profile["role"] == "client"
            and any(route.get("dev") == TUN for route in json.loads(cmd("ip", "-j", "route", "show", "default").stdout))
        )
    ):
        # Remove VPN default first while its firewall still blocks direct traffic.
        cmd("ip", "route", "del", "default", "dev", TUN, check=False)
        for route in before["default"]:
            args = ["ip", "route", "replace", "default"]
            if route.get("gateway"):
                args += ["via", route["gateway"]]
            args += ["dev", route["dev"]]
            if "metric" in route:
                args += ["metric", str(route["metric"])]
            cmd(*args)
        if resolver_backup.exists():
            Path("/etc/resolv.conf").resolve().write_bytes(read_private(resolver_backup))
    if not lab:
        import guard_policy

        if Path(state).resolve() != guard_policy.STATE:
            raise ValueError("a different state cannot disarm the installed device's guard")
        preferences = read_json_private(state / "preferences.json", {})
        preferences["mode"] = "applications"
        save(state / "preferences.json", preferences)
        guard_policy.disarm(state)
    for name in [WG, TUN]:
        if link_exists(name):
            row = json.loads(cmd("ip", "-j", "link", "show", "dev", name).stdout)[0]
            if row.get("ifalias") == "cypherpunk-vpn-managed":
                cmd("ip", "link", "del", name)
    for name in ["cypherpunk_vpn", "cypherpunk_vpn_meter", UPSTREAM_TABLE, FRONT_TABLE]:
        cmd("/usr/sbin/nft", "delete", "table", "inet", name, check=False)
    cmd("ip", "rule", "del", "priority", str(FRONT_ROUTES), check=False)
    cmd("ip", "route", "flush", "table", str(FRONT_ROUTES), check=False)
    resolver_backup.unlink(missing_ok=True)
    (keep / "network-before.json").unlink(missing_ok=True)
    save(rt / "status.json", dict(schema=1, state="unlocked", kill_switch=False, explicit_cleartext_permission=True))


def harden_process():
    """No core files, private umask, and non-dumpable: blocks same-UID ptrace and
    /proc/<pid>/mem reads of the keys this controller unseals."""
    import ctypes

    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError("cannot make controller non-dumpable")  # PR_SET_DUMPABLE


DEVICE_VAULT = Path("/etc/cypherpunk-vpn/vault")


def device_vault(vault):
    """The Nitrokey vault holding this device's key-sealing credential. The VPN service
    runs as root and reads it, so it must be root-owned and private; by default it is
    /etc/cypherpunk-vpn/vault, created here on first use (FIDO2 PIN + touch)."""
    if vault is None:
        if os.geteuid() != 0:
            raise ValueError("--vault is required when not running as root")
        vault = DEVICE_VAULT
    vault = Path(vault)
    if not vault.exists():
        from keyguard import enroll as create_vault

        vault.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        print("Creating this device's Nitrokey vault in %s: enter the PIN, then touch the key." % vault, flush=True)
        create_vault(vault)
    m = vault.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
        raise ValueError(
            "the vault %s must be a private directory owned by this user (the VPN service reads it as root); "
            "omit --vault to use %s" % (vault, DEVICE_VAULT)
        )
    return vault


def hand_to_invoker(path):
    """Give a public file written under sudo to the user who ran sudo, readable by them."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() == 0 and uid and gid:
        os.chown(path, int(uid), int(gid))
    os.chmod(path, 0o644)


def refusal_detail(e):
    """Only the controller's own refusals carry a message; anything else is reported by type
    alone, so no library error text (paths, arguments) is echoed. A locked server's refusal
    says how to unlock it (found on the live exit, 20 Nov 2026: it said only "Locked")."""
    from managed_profile import Locked

    return str(e)[:200] if type(e) in (RuntimeError, ValueError, Locked) else ""


def pipe_only(args):
    """Secret output (servers' data keys) goes to a pipe as JSON, never to a terminal."""
    if not getattr(args, "json", False) or sys.stdout.isatty():
        raise SystemExit("this prints secret data keys: run it with --json and send its output to a pipe")


def operator_from(args):
    """The operator for unlock-key/unwrap: the Nitrokey vault, or a lab's software keys."""
    if bool(args.vault) == bool(args.software_operator):
        raise SystemExit("give exactly one of --vault or --software-operator")
    return HardwareOperator(args.vault) if args.vault else SoftwareOperator(args.software_operator.resolve())


def emit(args, message, **data):
    """Print one command result: human text, or a single JSON object with --json."""
    if getattr(args, "json", False):
        print(json.dumps(dict(ok=True, action=args.action, message=message, **data), sort_keys=True, default=str))
    else:
        print(message)


# A Nitrokey PIN the service waits for is a systemd password request with this id
# (keyguard.pinentry runs systemd-ask-password --id=cypherpunk-vpn:fido2-pin).
ASK_DIR = Path("/run/systemd/ask-password")
PIN_REQUEST_ID = "cypherpunk-vpn:fido2-pin"


def pin_pending(ask_dir=None):
    """Whether the VPN service is waiting for its Nitrokey PIN right now."""
    d = ASK_DIR if ask_dir is None else ask_dir
    try:
        files = sorted(d.glob("ask.*"))
    except OSError:
        return False
    for f in files:
        try:
            if "Id=" + PIN_REQUEST_ID in f.read_text(errors="replace").splitlines():
                return True
        except OSError:
            continue
    return False


def service_active():
    """Whether cypherpunk-vpn.service is active (starting or running)."""
    return cmd("systemctl", "is-active", "--quiet", "cypherpunk-vpn.service", check=False).returncode == 0


def wait_for_pin_request(seconds=60, *, already_running=None, progress=None):
    """`cypherpunk connect` returns once the service has started; its PIN request follows a
    moment later. Wait for it while the service is active, so `connect && unlock`
    never finds nothing and exits silently."""
    deadline = time.monotonic() + seconds
    next_notice = deadline - seconds + 10
    while not pin_pending() and time.monotonic() < deadline and service_active():
        if already_running is not None and already_running():
            return False
        if progress is not None and time.monotonic() >= next_notice:
            progress("The service is still preparing the tunnel. Waiting for the Nitrokey PIN prompt.")
            next_notice += 10
        time.sleep(0.5)
    return pin_pending()


def pending_pin_request(ask_dir=None):
    """(socket path, ask file) of the service's pending PIN request, or None. Requests
    whose deadline (NotAfter, microseconds of CLOCK_MONOTONIC) has passed are skipped."""
    d = ASK_DIR if ask_dir is None else ask_dir
    try:
        files = sorted(d.glob("ask.*"))
    except OSError:
        return None
    now_us = int(time.monotonic() * 1e6)
    for f in files:
        try:
            fields = dict(line.split("=", 1) for line in f.read_text(errors="replace").splitlines() if "=" in line)
        except OSError:
            continue
        if fields.get("Id") != PIN_REQUEST_ID or not fields.get("Socket"):
            continue
        not_after = int(fields.get("NotAfter", "0") or 0)
        if not_after and not_after < now_us:
            continue
        return Path(fields["Socket"]), f
    return None


def answer_pin_request(request, pin):
    """Answer a systemd password request: one datagram, "+" and the PIN, to its socket
    (systemd's password agent protocol; the PIN is not cached anywhere)."""
    sock_path, _ = request
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.sendto(b"+" + pin.encode(), str(sock_path))
    finally:
        s.close()


def wait_for_unlock(state, request, submitted_ns, progress, seconds=90):
    """Wait for fresh supervisor status after the service receives the PIN."""
    status_path = runtime_dir(state, create=False) / "status.json"
    deadline = time.monotonic() + seconds
    next_notice = time.monotonic()
    last_wait = None
    while time.monotonic() < deadline:
        pending = pending_pin_request()
        if pending and pending != request:
            raise RuntimeError("The VPN requested a new Nitrokey PIN. Check sudo cypherpunk status before retrying")
        try:
            fresh = status_path.stat(follow_symlinks=False).st_mtime_ns >= submitted_ns
        except FileNotFoundError:
            fresh = False
        if fresh and not pending:
            status = read_status(state) or {}
            if status.get("state") == "supervising":
                return status
            if status.get("state") in ("blocked", "capped"):
                raise RuntimeError(
                    "The VPN reported it is blocked during unlock. Run sudo cypherpunk status for details"
                )
        waiting = (
            "Waiting for the VPN service to read the PIN."
            if pending
            else "Waiting for the Nitrokey and VPN service. Touch the key if it flashes."
        )
        now = time.monotonic()
        if waiting != last_wait or now >= next_notice:
            progress(waiting)
            last_wait, next_notice = waiting, now + 10
        time.sleep(0.5)
    raise RuntimeError("Unlock could not be confirmed. Run sudo cypherpunk status to check the service")


def recently_supervising(state):
    """Recognize an already unlocked supervisor through its live status writes."""
    path = runtime_dir(state, create=False) / "status.json"
    try:
        modified = path.stat(follow_symlinks=False).st_mtime
    except FileNotFoundError:
        return False
    return 0 <= time.time() - modified <= 3 and (read_status(state) or {}).get("state") == "supervising"


def status_for_display(state):
    """Prefer a live PIN request over status left by an earlier supervisor."""
    if pin_pending():
        return dict(state="waiting for the Nitrokey PIN", next="sudo cypherpunk unlock")
    status = read_status(state) or dict(state="not running")
    if status.get("state") == "supervising" and not recently_supervising(state):
        return dict(
            state="unknown", detail="The supervisor has stopped reporting fresh status", next="sudo cypherpunk status"
        )
    return status


def read_json_private(path, default=None):
    """Load a private JSON file, or return `default` when it does not exist."""
    return json.loads(read_private(path)) if path.exists() else default


def chain_of(profile):
    """Ordered (name, public endpoint) hops of an enrolled chain, as the client sees them."""
    n = profile["network"]
    hops = profile["hops"]
    if hops == 1:
        return [("exit", n["exit_endpoint"])]
    chain = [("relay", n["relay_endpoint"])]
    if hops == 3:
        chain.append(("middle", n["middle_endpoint"]))
    return chain + [("exit", n["exit_endpoint"])]


def device_info(state):
    """Non-secret summary of this device: role, chain, protection, preferences and status."""
    info = dict(state=str(state), enrolled=(state / "profile.json").exists())
    request_doc = read_json_private(state / "request.json")
    if request_doc:
        info["role"] = request_doc["role"]
    protection = read_json_private(state / "protection.json")
    if protection:
        info["protection"] = protection["mode"]
        info["creds_key"] = protection.get("creds_key")
        if protection["mode"] == "operator":
            info["locked"] = server_locked(state)
    if info["enrolled"]:
        import guard_policy
        from saved_chains import describe_hops, inventory, labels

        profile = load_profile(state)
        preferences = read_json_private(state / "preferences.json", {})
        info.update(
            role=profile["role"],
            hops=profile["hops"],
            padded=profile["core"].get("cells") is True,
            # None: this device runs no carrier (a middle relay, or the exit of a longer chain).
            camouflaged=bool(profile.get("cloak")) if profile["carrier"] else None,
            chain=describe_hops(profile, labels(state), inventory()),
            defense=(profile["carrier"] or {}).get("defense"),
            rate=(profile["carrier"] or {}).get("rate", "metered") if profile["carrier"] else None,
            mode=preferences.get("mode", "applications"),
            upstream_interface=preferences.get("upstream_interface"),
            upstream_gateway=preferences.get("upstream_gateway"),
            daily_limit_bytes=daily_limit(preferences, profile) if profile["role"] == "client" else None,
        )
        if profile["role"] == "client" and state.resolve() == guard_policy.STATE:
            info["whole_device_guard"] = guard_policy.MARKER.exists() or guard_policy.MARKER.is_symlink()
    info["status"] = status_for_display(state)
    return info


def describe(info):
    """Human-readable lines for `info`: one `name: value` pair per line, chain as a path."""
    lines = ["enrolled: " + ("yes" if info["enrolled"] else "no"), "state: " + info["state"]]
    for key in ["role", "hops", "protection", "creds_key", "mode", "defense", "rate", "upstream_interface"]:
        if info.get(key) is not None:
            lines.append("%s: %s" % (key, info[key]))
    if info.get("chain"):
        lines.append("chain: " + " -> ".join(["this device"] + [h["hop"] + " " + h["endpoint"] for h in info["chain"]]))
    if "daily_limit_bytes" in info:
        limit = info["daily_limit_bytes"]
        lines.append("daily limit: " + ("none" if limit is None else "%d MiB" % (limit // (1 << 20))))
    lines.append("status: " + info["status"].get("state", "unknown"))
    if info["status"].get("protection"):
        lines.append("protection: %s (%s)" % (info["status"]["protection"], info["status"].get("lifecycle")))
    return "\n".join(lines)


# HFSTS1 bits 19:16, the ME operation mode. HAP (set by me_cleaner -S) is not visible here.
ME_MODES = {
    0: "normal",
    2: "debug",
    3: "soft temporary disable",
    4: "security override (jumper)",
    5: "security override (message)",
}


def firmware_coprocessor(sysfs=Path("/sys"), cpuinfo=Path("/proc/cpuinfo")):
    """What always-on management coprocessor this machine has, read-only (README, "Three
    tiers"): the Intel ME version and operating mode from the MEI driver, or AMD's PSP.
    Informational: cypherpunk never changes firmware."""
    mei = sysfs / "class/mei/mei0"
    try:
        vendor = next(
            (ln.split(":", 1)[1].strip() for ln in cpuinfo.read_text().splitlines() if ln.startswith("vendor_id")),
            "",
        )
    except OSError:
        vendor = ""
    if (mei / "fw_ver").exists():
        try:
            ver = (mei / "fw_ver").read_text().split()[0].split(":", 1)[-1]
            hfsts1 = int((mei / "fw_status").read_text().split()[0], 16)
        except (OSError, ValueError, IndexError):
            return "Intel ME present (unreadable)"
        mode = ME_MODES.get(hfsts1 >> 16 & 0xF, "mode %d" % (hfsts1 >> 16 & 0xF))
        major = int(ver.split(".")[0]) if ver.split(".")[0].isdigit() else 0
        cleaner = "me_cleaner recognises it" if major <= 11 else "too new for me_cleaner (it lists ME up to 11.x)"
        advice = "; tier 3 wants it neutralized or AMD/ARM hardware" if mode == "normal" else ""
        return "Intel ME %s, %s; %s%s" % (ver, mode, cleaner, advice)
    if vendor == "AuthenticAMD":
        return "AMD PSP (no network stack, unlike Intel ME): fine for tier 3"
    if vendor == "GenuineIntel":
        return "Intel CPU, ME interface not visible (driver not loaded, or disabled)"
    return "no x86 management coprocessor found"


def doctor(state, check_egress=False):
    """Self-checks: (name, ok, detail) for installation, keys, firewall, resolver and units."""
    checks = []

    def check(name, ok, detail):
        checks.append(dict(check=name, ok=bool(ok), detail=detail))

    import preflight

    for finding in preflight.inspect_host()["findings"]:
        check(
            "host: " + finding["code"],
            finding["severity"] != "blocker",
            finding["severity"] + ": " + finding["message"],
        )

    def probe(*args):
        """Run a read-only command; None when the tool itself is missing (reported separately)."""
        try:
            return cmd(*args, check=False)
        except FileNotFoundError:
            return None

    check("running as root", os.geteuid() == 0, "privileged checks need root" if os.geteuid() else "yes")
    for exe in ["ip", "nft", "mount", "systemctl"]:
        try:
            check("trusted " + exe, True, trusted_exe(exe))
        except FileNotFoundError:
            check("trusted " + exe, False, "not found in system directories")
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401

        check("post-quantum crypto library", True, "ML-DSA and ML-KEM available")
    except ImportError:
        check("post-quantum crypto library", False, "install the hash-locked environment")
    check("management coprocessor (informational)", True, firmware_coprocessor())
    try:
        info = device_info(state)
    except (OSError, ValueError, PermissionError) as e:
        check("enrollment readable", False, type(e).__name__)
        return checks
    check("device keys generated", "role" in info, info.get("role", "run `cypherpunk request` first"))
    check(
        "enrolled in a chain",
        info["enrolled"],
        "%s hop(s)" % info.get("hops") if info["enrolled"] else "run `cypherpunk enroll`",
    )
    if info["enrolled"] and info.get("role") != "client":
        if retention.SHARED_MARKER.exists():
            check("no retained data", False, "shared host: its logging belongs to its other workloads")
        else:
            for name, ok, detail in retention.checks():
                check(name, ok, detail)
    if info["enrolled"]:
        check(
            "constant-cell padding",
            info.get("padded"),
            "every hop pads to one size"
            if info.get("padded")
            else "re-sign: cypherpunk cloud chain --apply, then enroll --replace",
        )
    if info["enrolled"] and info.get("camouflaged") is not None:
        check(
            "HTTP/3 camouflage",
            info["camouflaged"],
            "the link to the first hop looks like HTTP/3 on UDP 443, not WireGuard"
            if info["camouflaged"]
            else "re-sign: cypherpunk cloud chain --apply, then enroll --replace",
        )
    status = info.get("status") or {}
    if str(status.get("detail", "")).startswith("no answer through the chain"):
        # tools/chain_watch.py: a server stopped, reclaimed, locked or unreachable.
        check(
            "chain answering", False, "%s; next: %s" % (status["detail"], status.get("next", "cypherpunk cloud health"))
        )
    if info.get("protection") == "systemd-creds":
        from keyguard import tpm2_usable

        tpm = tpm2_usable()
        check(
            "keys bound to TPM2",
            info.get("creds_key") == "host+tpm2",
            "sealed with " + str(info.get("creds_key")) + ("; TPM2 usable now" if tpm else "; no usable TPM2"),
        )
    elif info.get("protection") == "operator":
        check(
            "keys unlocked by the operator",
            not info.get("locked"),
            "sealed to the operator's Nitrokey; "
            + ("LOCKED since boot: run cypherpunk cloud unlock NAME on the operator's computer" if info.get("locked")
               else "unlocked until the next reboot"),
        )  # fmt: skip
    elif info.get("protection"):
        # Bug 9a: a host whose systemd cannot seal with systemd-creds falls back to
        # plain keys, so say what that means and what to do about it, not just "none".
        check(
            "key protection",
            info["protection"] != "none",
            "plain files, root-readable: this host cannot seal keys with systemd-creds "
            "(systemd 250+ needed); use an encrypted disk or a newer host"
            if info["protection"] == "none"
            else info["protection"],
        )
    listed = probe("nft", "list", "tables") if os.geteuid() == 0 else None
    tables = listed.stdout if listed else ""
    if info.get("role") == "client" and info.get("mode") == "whole-device":
        check("whole-device kill switch table", "cypherpunk_vpn" in tables, "inet cypherpunk_vpn")
    if info.get("upstream_interface"):
        iface = info["upstream_interface"]
        up = probe("ip", "link", "show", "dev", iface)
        check(
            "upstream entry interface up",
            up and up.returncode == 0,
            iface + " (the first hop is reached only through it)",
        )
        if os.geteuid() == 0 and info.get("status", {}).get("state") == "supervising":
            check("upstream entry guard", UPSTREAM_TABLE in tables, "inet " + UPSTREAM_TABLE)
    elif info.get("role") == "client":
        check("upstream entry", True, "off: the first hop sees this network's address (cypherpunk help privacy)")
    for unit in ["cypherpunk-vpn.service", "cypherpunk-vpn-guard.service"]:
        r = probe("systemctl", "is-enabled", unit)
        check(
            unit + " installed",
            r is not None and (r.returncode == 0 or r.stdout.strip() in ("disabled", "static")),
            "systemctl not found" if r is None else r.stdout.strip() or "missing",
        )
    check(
        "resolver isolation",
        True,
        "hidden from protected apps: "
        + (", ".join(d for d in RESOLVER_DIRS + SYSTEM_BUS_SOCKETS if Path(d).exists()) or "none present"),
    )
    if check_egress:
        r = probe("curl", "-s", "--max-time", "8", "https://checkip.amazonaws.com")
        check(
            "address the first hop sees (outside the tunnel)",
            r is not None and r.returncode == 0,
            "curl not found" if r is None else r.stdout.strip() or "unavailable",
        )
    return checks


def build_parser():
    """The controller's command line; also walked by the documentation gate."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--state",
        type=Path,
        default=Path("/etc/cypherpunk-vpn/enrolled"),
        help="enrollment directory (root-owned, mode 0700)",
    )
    p.add_argument(
        "--bin-dir", type=Path, default=Path("/usr/local/bin"), help="directory holding the cypherpunk-vpn binaries"
    )
    p.add_argument("--lab", action="store_true", help="tests only; requires an unprivileged user namespace")
    p.add_argument("--json", action="store_true", help="print one JSON object per command (used by the cypherpunk CLI)")
    s = p.add_subparsers(dest="action", required=True)
    import preflight
    import setup_cli

    preflight.add_arguments(s.add_parser("preflight", help="check host requirements without changing the system"))
    setup_cli.add_arguments(
        s.add_parser("setup", help="check resumable client setup or review an exact hardware repair")
    )
    rq = s.add_parser("request", help="generate this device's keys locally; prints the public request")
    rq.add_argument("--existing", action="store_true", help="export the public request without generating new keys")
    rq.add_argument(
        "--role",
        choices=["client", "relay", "middle", "exit"],
        help="what this device will be in the chain",
    )
    rq.add_argument(
        "--protect",
        choices=["nitrokey", "systemd-creds", "operator", "none"],
        help="how the private keys are sealed at rest (operator: a server without a TPM, whose keys only the "
        "operator's Nitrokey unlocks, after every reboot)",
    )
    rq.add_argument("--unlock-key", type=Path, help="with --protect operator: the operator's unlock public key file")
    rq.add_argument(
        "--insecure-plaintext-keys",
        action="store_true",
        help="allow --protect none outside --lab: private keys stored as plain files (tests and throwaway devices only)",
    )
    rq.add_argument(
        "--vault",
        type=Path,
        help="Nitrokey vault (nitrokey protection; default /etc/cypherpunk-vpn/vault, created if missing)",
    )
    rq.add_argument("--out", type=Path, required=True, help="public request file to copy to the operator")
    uk = s.add_parser(
        "unlock-key", help="operator: create the unlock key for servers without a TPM (once; PIN + touch)"
    )
    uk.add_argument("--vault", type=Path, help="Nitrokey vault (the operator's)")
    uk.add_argument("--software-operator", type=Path, help="LAB ONLY: plaintext operator keys in this directory")
    uw = s.add_parser("unwrap", help="operator: unwrap servers' data keys (PIN + touch); output only to a pipe")
    uw.add_argument("--vault", type=Path, help="Nitrokey vault (the operator's)")
    uw.add_argument("--software-operator", type=Path, help="LAB ONLY: plaintext operator keys in this directory")
    uw.add_argument(
        "--request", action="append", required=True,
        help="NAME=PATH: your own copy of the server's request (its role and identities bind the unwrap)",
    )  # fmt: skip
    uw.add_argument(
        "--wrapped", action="append", default=[],
        help="NAME=PATH: the server's current unlock record (its protection.json), if not the request's own",
    )  # fmt: skip
    s.add_parser("server-unlock", help="server: accept the operator's data key on stdin, held in RAM until reboot")
    sk = s.add_parser(
        "state-key", help="operator: the OpenTofu state key, sealed in the vault (PIN + touch); pipe only"
    )
    sk.add_argument("--vault", type=Path, help="Nitrokey vault (the operator's)")
    sk.add_argument("--software-operator", type=Path, help="LAB ONLY: plaintext operator keys in this directory")
    init = s.add_parser("init", help="operator: sign a chain from the devices' public requests")
    init.add_argument("--out", type=Path, required=True, help="new directory for the signed bundles")
    init.add_argument(
        "--hops", type=int, choices=[1, 2, 3], default=2, help="1: client-exit; 2: +entry relay; 3: +middle relay"
    )
    init.add_argument("--relay", help="entry relay public endpoint IP:PORT, normally port 443 (2-3 hops)")
    init.add_argument("--middle", help="middle relay public QUIC endpoint IP:PORT (3 hops)")
    init.add_argument(
        "--exit", required=True, help="exit public QUIC endpoint (2-3 hops), or its port-443 endpoint (1 hop)"
    )
    init.add_argument(
        "--cover-name", help="server name the first hop's HTTP/3 camouflage presents (default: none sent)"
    )
    init.add_argument(
        "--request", action="append", required=True, help="ROLE=PATH for the client and every server in the chain"
    )
    init.add_argument(
        "--link-transport",
        choices=["udp", "tcp"],
        default="udp",
        help="how the paced links between servers travel (tcp: for a next hop reachable only over TCP, "
        "such as an IPv6-only exit)",
    )
    init.add_argument(
        "--emit-unlock", action="store_true",
        help="also unwrap the data keys of operator-unlocked servers with the same touch, printed to a pipe only",
    )  # fmt: skip
    signer = init.add_mutually_exclusive_group(required=True)
    signer.add_argument("--vault", type=Path, help="Nitrokey vault: hardware-signed operator (production)")
    signer.add_argument("--software-operator", type=Path, help="LAB ONLY: plaintext operator keys in this directory")
    init.add_argument(
        "--pq-vault",
        type=Path,
        help="with --vault: the vault of a second key's ML-DSA-44 credential (keyguard enroll-pq-signer), "
        "added as a third operator signature half",
    )
    init.add_argument(
        "--rate",
        choices=["auto", *RATE_CLASSES],
        default="auto",
        help="the constant-rate stream's class (default auto: the fastest the allowance fits)",
    )
    init.add_argument("--allowance-gib", type=int, help="the smallest hop's monthly outbound allowance, GiB")
    init.add_argument(
        "--hours-per-day", type=float, default=8, help="hours connected per day, for the cost (default 8)"
    )
    init.add_argument("--accept-cost", action="store_true", help="sign a class even if it exceeds the allowance")
    init.add_argument(
        "--standby-exit",
        action="append",
        default=[],
        help="NAME=IP:PORT: a standby exit (2-3 hops); give its request as --request NAME=FILE",
    )
    init.add_argument(
        "--front",
        choices=["i2p"],
        help="reach the entry through I2P: its provider sees I2P routers, never your address (cypherpunk help front)",
    )
    init.add_argument(
        "--front-hops",
        type=int,
        choices=[1, 2, 3],
        default=2,
        help="I2P hops each way between you and the entry (1: one router sees both ends; default 2: none does)",
    )
    init.add_argument(
        "--rotate-seconds",
        default="900,3600",
        help="MIN,MAX: with standby exits, rotate among the live ones at a random time in this window",
    )
    init.add_argument(
        "--daily-limit-mib", type=int, default=None, help="optional fail-closed daily carrier cap; default none"
    )
    init.add_argument(
        "--dns-blocklist",
        type=Path,
        default=None,
        help="optional domain blocklist (plain, .domain, *.domain, hosts or ||domain^ lines) signed into the exit bundle",
    )
    init.add_argument(
        "--dns-allowlist",
        type=Path,
        default=None,
        help="optional allowlist file (same formats) signed into the exit bundle: never blocked, even by a CNAME check",
    )
    init.add_argument(
        "--dns-recursive",
        action="store_true",
        help="the exit resolves with its own Unbound (DNSSEC, QNAME minimisation) instead of a public DoT resolver",
    )
    imp = s.add_parser("enroll", help="verify and install this device's signed bundle")
    imp.add_argument("bundle", type=Path, help="the .cpvpn bundle the operator produced for this device")
    imp.add_argument("--operator-key", type=Path, required=True, help="operator public key, obtained out of band")
    imp.add_argument(
        "--replace", action="store_true", help="switch this device to a new chain (keeps its keys; disconnect first)"
    )
    c = s.add_parser("connect", help="run the supervisor in the foreground (used by cypherpunk-vpn.service)")
    c.add_argument("--whole-device", action="store_true", help="route the whole device for this run")
    c.add_argument("--app-only", action="store_true", help="protect only `run` applications for this run")
    s.add_parser("disconnect", help="stop the supervisor; the kill switch stays in place")
    s.add_parser("status", help="runtime status written by the supervisor")
    s.add_parser("info", help="non-secret summary: role, chain, protection, preferences, status")
    s.add_parser("hops", help="the enrolled chain, hop by hop")
    chains = s.add_parser("chains", help="list, import and select saved signed client chains")
    chain_commands = chains.add_subparsers(dest="chain_action", required=True)
    chain_commands.add_parser("list")
    saved_import = chain_commands.add_parser("import")
    saved_import.add_argument("name")
    saved_import.add_argument("bundle", type=Path)
    select = chain_commands.add_parser("select")
    select.add_argument("name")
    select.add_argument("--allow-unsaved-current", action="store_true")
    location = chain_commands.add_parser("location").add_subparsers(dest="location_action", required=True)
    location_set = location.add_parser("set")
    location_set.add_argument("hop", choices=["entry", "relay", "middle", "exit"])
    location_set.add_argument("--country", required=True)
    location_set.add_argument("--city")
    location_set.add_argument("--chain", help="label a hop in a saved chain instead of the current chain")
    doc = s.add_parser("doctor", help="self-checks for installation, keys, firewall, resolver and units")
    doc.add_argument("--check-egress", action="store_true", help="also show the public address seen outside the tunnel")
    s.add_parser("rotate", help="rotate the short-lived session certificates now")
    s.add_parser("guard", help="(re)apply the boot-time kill switch (used by cypherpunk-vpn-guard.service)")
    pref = s.add_parser("preferences", help="change saved connection preferences")
    pref.add_argument("--mode", choices=["applications", "whole-device"], help="what the tunnel protects by default")
    cap = pref.add_mutually_exclusive_group()
    cap.add_argument("--daily-limit-mib", type=int, help="fail-closed daily cap, 1..10240 MiB (client only)")
    cap.add_argument("--no-daily-limit", action="store_true", help="remove the daily cap (default)")
    up = pref.add_mutually_exclusive_group()
    up.add_argument(
        "--upstream-interface", help="reach the first hop only through this interface (e.g. an existing VPN)"
    )
    up.add_argument("--no-upstream", action="store_true", help="reach the first hop over the normal route (default)")
    pref.add_argument(
        "--upstream-gateway", help="next hop on an Ethernet-like upstream interface (point-to-point ones need none)"
    )
    unlock = s.add_parser("unlock", help="answer a pending Nitrokey PIN prompt from the VPN service (e.g. after boot)")
    unlock.add_argument("--if-needed", action="store_true", help="skip the prompt if the service is already unlocked")
    reset_cmd = s.add_parser("reset", help="remove the kill switch and restore cleartext networking")
    reset_cmd.add_argument(
        "--allow-cleartext", action="store_true", required=True, help="required: confirms traffic may leave unprotected"
    )
    r = s.add_parser("run", help="run one command inside the protected network namespace")
    r.add_argument(
        "--uid",
        type=int,
        default=int(os.environ.get("SUDO_UID", "0")),
        help="user to run as (default: the sudo caller)",
    )
    r.add_argument(
        "--gid",
        type=int,
        default=int(os.environ.get("SUDO_GID", "0")),
        help="group to run as (default: the sudo caller)",
    )
    r.add_argument("command", nargs=argparse.REMAINDER, help="the command, after --")
    mx = s.add_parser("mix", help="the mix lane: a Katzenpost mixnet client inside the protected namespace")
    mx.add_argument("mix_action", choices=["setup", "start", "status", "fetch", "stop"], help="what to do")
    mx.add_argument("url", nargs="?", help="fetch: an absolute http(s) URL")
    mx.add_argument("--config", type=Path, help="setup: the directory holding the mixnet's client.toml")
    mx.add_argument("--method", choices=["GET", "HEAD"], default="GET", help="fetch: the request method")
    for flag, env in [("--uid", "SUDO_UID"), ("--gid", "SUDO_GID")]:
        mx.add_argument(
            flag,
            type=int,
            default=int(os.environ.get(env, "0")),
            help="start/fetch: the %s to run as (default: the sudo caller's)" % flag[2:],
        )
    return p


def mix_command(a):
    """cypherpunk mix: install a mixnet configuration, run its client inside the protected
    namespace (so the mixnet sees the chain's exit), fetch through it, stop it."""
    import mix

    state = a.state.resolve()
    rt = runtime_dir(state)
    record = rt / "mix.json"
    tool = Path(__file__).resolve().parent / "mix.py"

    def running():
        if not record.exists():
            return None
        value = json.loads(read_private(record))
        return value if identity_of(value["pid"]) == value["identity"] else None

    if a.mix_action == "setup":
        if not a.config:
            raise ValueError("setup needs --config DIR (the mixnet's client.toml)")
        mix.setup(a.config, state / "mix")
        emit(a, "Mixnet configuration installed; start it with cypherpunk mix start.", configured=True)
    elif a.mix_action == "start":
        if running():
            emit(a, "The mix lane is already running.", running=True)
            return
        if not (state / "mix" / "client.toml").exists():
            raise RuntimeError("no mixnet configuration: cypherpunk mix setup --config DIR")
        mix.binaries()
        # The client runs as the user: give it a copy of the (public) configuration.
        work = Path("/run/cypherpunk-vpn-mix-%d" % a.uid)
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(mode=0o700)
        for name in mix.CONFIG_FILES:
            shutil.copy(state / "mix" / name, work / name)
            if a.uid:
                os.chown(work / name, a.uid, a.gid)
        if a.uid:
            os.chown(work, a.uid, a.gid)
        pid = os.fork()
        if pid == 0:
            os.setsid()
            devnull = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(devnull, fd)
            try:
                run_app(state, [sys.executable, str(tool), "serve", "--config", str(work)], a.uid, a.gid, a.lab)
            finally:
                os._exit(1)
        time.sleep(0.5)
        save(record, dict(pid=pid, identity=identity_of(pid)))
        emit(a, "Mix lane started inside the protected namespace (proxy 127.0.0.1:41199 there).", running=True)
    elif a.mix_action == "status":
        r = running()
        ready = (
            r is not None
            and cmd("ip", "netns", "exec", APP, sys.executable, str(tool), "ready", check=False).returncode == 0
        )
        emit(a, "Mix lane: %s." % ("ready" if ready else "starting" if r else "stopped"), running=bool(r), ready=ready)
    elif a.mix_action == "stop":
        r = running()
        if r:
            os.killpg(r["pid"], signal.SIGTERM)
        if record.exists():
            record.unlink()
        emit(a, "Mix lane stopped.", running=False)
    else:
        if not a.url:
            raise ValueError("fetch needs a URL")
        if not running():
            raise RuntimeError("the mix lane is not running: cypherpunk mix start")
        run_app(state, [sys.executable, str(tool), "fetch", a.url, "--method", a.method], a.uid, a.gid, a.lab)


def main():
    """Command-line entry point: harden the process, parse arguments, run one action."""
    harden_process()
    a = build_parser().parse_args()
    # One PIN per command (keyguard.one_pin), except for the long-running supervisor and app
    # launcher, whose hardware prompts run in their own short-lived signer processes.
    from keyguard import one_pin

    scope = contextlib.nullcontext() if a.action in ("connect", "run") else one_pin()
    with scope:
        if a.action in ("request", "enroll", "preferences", "reset", "chains") or (a.action == "setup" and a.apply):
            from controller_mutation import locked

            with locked(a.state):
                dispatch(a)
        else:
            dispatch(a)


def dispatch(a):
    """Execute already parsed controller arguments; callers retain their mutation lock."""
    if a.action in ("preflight", "setup"):
        import setup_cli

        try:
            result = setup_cli.preflight_result(a) if a.action == "preflight" else setup_cli.setup(a)
        except (setup_cli.RequestError, setup_cli.ConfirmationRequired) as error:
            # These exception classes carry fixed public messages, never raw tool output.
            result = dict(ok=False, action=a.action, error=type(error).__name__, message=str(error))
        setup_cli.print_result(a, result)
        if not result["ok"]:
            raise SystemExit(1)
        return
    if a.action == "request":
        if a.existing:
            root_guard(a.lab)
            if a.role or a.protect or a.vault or a.unlock_key or a.insecure_plaintext_keys:
                raise ValueError("--existing only exports the current public request")
            from controller_request import public_request

            saved = public_request(a.state.resolve())
            if saved is None:
                raise RuntimeError("This device has no public client request yet")
            with a.out.open("x", encoding="ascii") as output:
                output.write(saved["text"])
            hand_to_invoker(a.out)
            emit(a, "Public request exported. Give this file to the operator.", request=str(a.out))
            return
        if not a.role or not a.protect:
            raise ValueError("Generating a request requires --role and --protect")
        if a.protect == "none" and not (a.lab or a.insecure_plaintext_keys):
            raise SystemExit(
                "refusing --protect none: the private keys would be plain files anyone with root or the disk can "
                "read. Use --protect nitrokey or systemd-creds; for a test device add --insecure-plaintext-keys."
            )
        vault = device_vault(a.vault) if a.protect == "nitrokey" else a.vault
        if not a.lab:
            import sealing

            try:
                sealing.check_server_protection(a.role, a.protect, a.unlock_key)
            except ValueError as e:
                raise SystemExit("refusing: " + str(e)) from None
        unlock_public = a.unlock_key.read_bytes() if a.unlock_key else None
        req = request(a.role, a.state.resolve(), a.protect, vault, unlock_public=unlock_public)
        a.out.write_bytes(canonical(req))
        hand_to_invoker(a.out)
        emit(
            a,
            "Keys generated and protected on this device (%s). Copy only %s to the operator." % (a.protect, a.out),
            role=a.role,
            protection=a.protect,
            request=str(a.out),
        )
        return
    if a.action == "init":
        # The constant-rate stream costs bandwidth around the clock it runs: sign a chain
        # only against a stated allowance, or with the cost explicitly accepted.
        if a.allowance_gib is None and not a.accept_cost:
            links = 2 if a.hops > 1 else 1
            cls = "metered" if a.rate == "auto" else a.rate
            raise SystemExit(
                "no --allowance-gib: the %s stream costs each relay about %d GiB/month of outbound traffic at "
                "%g h/day connected, %d GiB/month around the clock. Give the smallest hop's monthly allowance "
                "(--allowance-gib N; cypherpunk cloud does this for you) or pass --accept-cost."
                % (cls, rate_cost_gib(cls, a.hours_per_day, links), a.hours_per_day, rate_cost_gib(cls, 24, links))
            )
        requests = {}
        for item in a.request:
            role, path = item.split("=", 1)
            requests[role] = Path(path).read_bytes()
        # A relay sends the stream on two links (client side and next hop).
        links = 2 if a.hops > 1 else 1
        rate, why = choose_rate(a.rate, a.allowance_gib, a.hours_per_day, a.accept_cost, links)
        if a.front and a.rate == "auto" and rate not in FRONT_RATES:
            rate, why = FRONT_RATES[-1], "the fastest class an I2P stream carries"
        standby = [tuple(x.split("=", 1)) for x in a.standby_exit]
        if any(len(x) != 2 for x in standby):
            raise ValueError("--standby-exit takes NAME=IP:PORT")
        rotate = tuple(int(x) for x in a.rotate_seconds.split(","))
        if a.pq_vault and not a.vault:
            raise ValueError("--pq-vault needs --vault (it adds to a hardware operator)")
        signer_impl = (
            HardwareOperator(a.vault, a.pq_vault) if a.vault else SoftwareOperator(a.software_operator.resolve())
        )
        if a.emit_unlock:
            pipe_only(a)
            signer_impl.pending_unwrap = unlock_items(requests)
        dns_arg = (
            dict(
                upstream="1.1.1.1:853",
                server_name="one.one.one.one",
                blocklist=a.dns_blocklist.read_bytes() if a.dns_blocklist else None,
                allowlist=a.dns_allowlist.read_bytes() if a.dns_allowlist else None,
                recursive=a.dns_recursive or None,
            )
            if a.dns_blocklist or a.dns_allowlist or a.dns_recursive
            else None
        )
        operator = create(
            a.out.resolve(),
            requests,
            a.relay,
            a.exit,
            signer_impl,
            daily_mib=a.daily_limit_mib,
            dns=dns_arg,
            hops=a.hops,
            middle=a.middle,
            cover_name=a.cover_name,
            rate=rate,
            alternates=standby,
            rotate=rotate,
            front=a.front,
            front_hops=a.front_hops,
            link_transport=a.link_transport,
        )
        emit(
            a,
            "Signed %d-hop chain written to %s (operator %s), rate %s: %s; about %d GiB/month per hop at %g h/day."
            % (a.hops, a.out, operator[:16], rate, why, rate_cost_gib(rate, a.hours_per_day, links), a.hours_per_day),
            operator_sha256=operator,
            out=str(a.out),
            hops=a.hops,
            rate=rate,
            rate_reason=why,
            monthly_gib_per_hop=round(rate_cost_gib(rate, a.hours_per_day, links)),
            **(dict(unlock={k: v.hex() for k, v in (signer_impl.unwrapped or {}).items()}) if a.emit_unlock else {}),
        )
        return
    if a.action == "unlock-key":
        op = operator_from(a)
        public = op.create_unlock_key()
        emit(
            a,
            "The operator's unlock key exists (%s...). Servers without a TPM lock their keys to it."
            % hashlib.sha256(public).hexdigest()[:16],
            unlock_public_sha256=hashlib.sha256(public).hexdigest(),
            path=str(
                (a.vault or a.software_operator) / ("operator-unlock.pub" if a.vault else "offline/operator-unlock.pub")
            ),
        )
        return
    if a.action == "unwrap":
        pipe_only(a)
        items = {}
        for item in a.request:
            name, path = item.split("=", 1)
            r = json.loads(Path(path).read_bytes())
            items[name] = [r.get("unlock"), r["role"], r["certificates"]]
        for item in a.wrapped:
            name, path = item.split("=", 1)
            if name not in items:
                raise SystemExit("--wrapped %s has no --request %s" % (name, name))
            items[name][0] = json.loads(Path(path).read_bytes())["unlock"]
        missing = [n for n, v in items.items() if not v[0]]
        if missing:
            raise SystemExit("no unlock record for: " + ", ".join(missing))
        keys = operator_from(a).unwrap({n: tuple(v) for n, v in items.items()})
        emit(a, "unwrapped %d data key(s)" % len(keys), unlock={k: v.hex() for k, v in keys.items()})
        return
    if a.action == "state-key":
        pipe_only(a)
        emit(a, "OpenTofu state key released to this pipe", key=operator_from(a).state_key().hex())
        return
    if a.action == "server-unlock":
        root_guard(False)
        text = sys.stdin.read(200).strip()
        try:
            data_key = bytes.fromhex(text)
        except ValueError:
            raise SystemExit("expected the data key as hex on stdin") from None
        names = server_unlock(a.state.resolve(), data_key)
        emit(a, "Unlocked %d key(s) until the next reboot." % len(names), unlocked=names)
        return
    if a.action == "enroll":
        rt_info = runtime_dir(a.state, create=False) / "controller.json"
        if a.replace and rt_info.exists():
            info = json.loads(read_private(rt_info))
            if identity_of(info["pid"]) == info["identity"]:
                raise RuntimeError("disconnect before switching chains")
        p = enroll(a.bundle, a.operator_key, a.state.resolve(), replace=a.replace)
        emit(
            a,
            "Enrollment verified (%d-hop chain, role %s). No network settings changed." % (p["hops"], p["role"]),
            hops=p["hops"],
            role=p["role"],
        )
        return
    if a.action == "connect":
        if a.whole_device and a.app_only:
            raise ValueError("choose one connection mode")
        whole = True if a.whole_device else False if a.app_only else None
        supervise(a.state.resolve(), a.bin_dir.resolve(), a.lab, whole)
    elif a.action == "chains":
        from saved_chains import import_bundle, list_chains, select_chain, set_label

        root_guard(a.lab)
        state = a.state.resolve()
        if a.chain_action == "import":
            import_bundle(state, a.name, a.bundle)
            emit(a, "Signed chain saved.")
        elif a.chain_action == "select":
            select_chain(state, a.name, a.allow_unsaved_current)
            emit(a, "Signed chain selected. Use Connect when ready.")
        else:
            listing = list_chains(state)
            if a.chain_action == "list":
                lines = ["Current enrollment"] + [
                    "%s %s %s" % (hop["hop"], hop["endpoint"], hop["country"] or "Unknown")
                    for hop in listing["current"]
                ]
                for row in listing["saved"]:
                    suffix = " (current)" if row.get("active") else "" if row["available"] else " (unavailable)"
                    lines.append(row["name"] + suffix)
                    lines += [
                        "  %s %s" % (hop["hop"], ", ".join(x for x in (hop["city"], hop["country"]) if x) or "Unknown")
                        for hop in row.get("hops", [])
                    ]
                emit(a, "\n".join(lines), **listing)
            else:
                hops = listing["current"]
                if a.chain:
                    hops = next(
                        (row["hops"] for row in listing["saved"] if row["name"] == a.chain and row["available"]), None
                    )
                    if hops is None:
                        raise ValueError("Choose an available saved chain")
                endpoint = next(
                    (hop["endpoint"] for hop in hops if hop["hop"] == ("relay" if a.hop == "entry" else a.hop)), None
                )
                if a.hop == "entry" and len(hops) == 1:
                    endpoint = hops[0]["endpoint"]
                if endpoint is None:
                    raise ValueError("This chain has no such hop")
                set_label(state, endpoint, a.country, a.city)
                emit(a, "Local location label saved.")
    elif a.action == "disconnect":
        root_guard(a.lab)
        # Live regression (bug 8): `disconnect` reported success whenever the service
        # was inactive, but never stopped a supervisor running in the foreground
        # (`connect --foreground`). Stop whatever is actually running, and confirm.
        stopped = stop_supervisor(a.state)
        emit(
            a,
            "Supervisor stopped; the kill switch stays in place."
            if stopped
            else "No supervisor is running; the kill switch stays in place.",
            stopped=stopped,
        )
    elif a.action == "rotate":
        root_guard(a.lab)
        control_signal(a.state, signal.SIGHUP)
        emit(a, "Certificate rotation requested.")
    elif a.action == "preferences":
        root_guard(a.lab)
        old = json.loads(read_private(a.state / "preferences.json")) if (a.state / "preferences.json").exists() else {}
        if a.mode:
            if a.mode == "whole-device" and not a.lab:
                import guard_policy

                guard_policy.arm(state=a.state)
            old["mode"] = a.mode
        # A "defense" key left by an older release is ignored: every chain runs the stream.
        old.pop("defense", None)
        if a.daily_limit_mib is not None:
            if load_profile(a.state)["role"] != "client":
                raise ValueError("the daily cap is client-only: servers store no byte counts")
            if not 1 <= a.daily_limit_mib <= 10240:
                raise ValueError("daily limit must be 1..10240 MiB")
            old["daily_limit_mib"] = a.daily_limit_mib
        if a.no_daily_limit:
            old["daily_limit_mib"] = None
        if a.upstream_interface is not None or a.no_upstream:
            if load_profile(a.state)["role"] != "client":
                raise ValueError("upstream entry is client-only: servers are reached, they do not enter")
            old["upstream_interface"] = None if a.no_upstream else valid_interface(a.upstream_interface)
            old["upstream_gateway"] = (
                str(ipaddress.IPv4Address(a.upstream_gateway)) if a.upstream_gateway and not a.no_upstream else None
            )
        elif a.upstream_gateway:
            raise ValueError("--upstream-gateway goes with --upstream-interface")
        save(a.state / "preferences.json", old)
        emit(a, "Preferences saved.", preferences=old)
    elif a.action == "guard":
        root_guard(a.lab)
        profile = load_profile(a.state)
        pref = json.loads(read_private(a.state / "preferences.json")) if (a.state / "preferences.json").exists() else {}
        if profile["role"] == "client" and pref.get("mode") == "whole-device":
            try:
                uid, _ = service_identity(a.lab)
            except KeyError:
                uid = None
            whole_firewall(profile, uid)
        emit(a, "Guard checked.")
    elif a.action == "unlock":
        root_guard(False)
        from keyguard import pinentry, terminal_pinentry

        def progress(message):
            print(message, file=sys.stderr, flush=True)

        progress("Looking for the VPN service's Nitrokey PIN request…")
        already_running = (lambda: recently_supervising(a.state)) if a.if_needed else None
        if not wait_for_pin_request(already_running=already_running, progress=progress):
            if already_running is not None and already_running() and not pin_pending():
                emit(a, "The VPN service is already unlocked.", unlocked=True, status=read_status(a.state))
                return
            if a.if_needed:
                raise RuntimeError(
                    "The VPN did not reach a PIN prompt or an unlocked state. Run sudo cypherpunk status"
                )
            raise RuntimeError("no Nitrokey PIN request is pending; start the service first: sudo cypherpunk connect")
        pin_request = pending_pin_request()
        if pin_request is None:
            raise RuntimeError("the PIN request expired; start the service again: sudo cypherpunk connect")
        pin = terminal_pinentry() if sys.stdin.isatty() else pinentry()
        submitted_ns = time.time_ns()
        try:
            answer_pin_request(pin_request, pin)
        except OSError:
            raise RuntimeError(
                "The PIN request ended before the answer could be sent. Run sudo cypherpunk status"
            ) from None
        finally:
            del pin
        progress("PIN submitted. Touch the Nitrokey when it flashes.")
        status = wait_for_unlock(a.state, pin_request, submitted_ns, progress)
        message = (
            "Nitrokey unlocked. VPN protection is active."
            if status.get("protection") == "protected"
            else "Nitrokey unlocked. Run sudo cypherpunk status to check tunnel protection."
        )
        emit(a, message, unlocked=True, status=status)
    elif a.action == "status":
        # While the service waits for its PIN, say so: the status file is either not
        # written yet or left over from an earlier run (e.g. "blocked, disconnected").
        status = status_for_display(a.state)
        emit(a, json.dumps(status, sort_keys=True), status=status)
    elif a.action == "info":
        info = device_info(a.state.resolve())
        emit(a, describe(info), info=info)
    elif a.action == "hops":
        info = device_info(a.state.resolve())
        chain = info.get("chain") or []
        text = (
            " -> ".join(["client"] + ["%s (%s)" % (h["hop"], h["endpoint"]) for h in chain])
            if chain
            else "not enrolled"
        )
        emit(a, text, hops=info.get("hops"), chain=chain)
    elif a.action == "doctor":
        checks = doctor(a.state.resolve(), a.check_egress)
        text = "\n".join(("ok   " if c["ok"] else "FAIL ") + c["check"] + ": " + c["detail"] for c in checks)
        emit(a, text, checks=checks, healthy=all(c["ok"] for c in checks))
    elif a.action == "reset":
        root_guard(a.lab)
        with supervisor_locks(a.state.resolve()):
            reset(a.state.resolve(), a.lab)
        emit(a, "Guard removed; cleartext networking restored.")
    elif a.action == "mix":
        mix_command(a)
    elif a.action == "run":
        run_app(a.state.resolve(), a.command[1:] if a.command[:1] == ["--"] else a.command, a.uid, a.gid, a.lab)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        if "--lab" in sys.argv:
            try:
                lab_guard()
            except RuntimeError:
                pass
            else:
                import traceback

                traceback.print_exc()
                if isinstance(e, subprocess.CalledProcessError):
                    print(e.stderr, file=sys.stderr)
        detail = refusal_detail(e)
        if "--json" in sys.argv:
            print(json.dumps(dict(ok=False, error=type(e).__name__, message=detail or None)))
        print(
            "Managed operation stopped: "
            + type(e).__name__
            + (" (" + detail + ")" if detail else "")
            + ". Existing kill-switch rules are retained.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None  # details are deliberately not printed outside the lab

#!/usr/bin/env python3
"""Managed Linux VPN: one enrollment import, persistent firewall, isolated DNS and supervision.

No commands in this file are run on the host by the test suite: integration tests
enter a new unprivileged user/mount/network namespace first. Whole-device mode
is opt-in and is never automatically selected over an existing VPN.
"""

import argparse
import datetime as dt
import fcntl
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

from keyguard import atomic, read_private, trusted_exe
import retention
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
    request,
    load_keys,
    HardwareOperator,
    SoftwareOperator,
)

APP = "avpn-app"
# Smallest underlay link MTU the HTTP/3 cloak can use: a 1420-byte QUIC UDP payload in an IPv4+UDP packet.
UNDERLAY_MIN_MTU = 1448
TUN = "avpn0"
WG = "avwg0"


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


def runtime_dir(state, create=True):
    """RAM-only (tmpfs) home for everything written while running: status, PIDs,
    locks, rotated leaves, resolver file and namespace marker. Servers persist nothing
    at runtime, so a powered-off or seized server holds no record of its sessions.

    Read-only queries pass ``create=False``: they get the path without creating it,
    and an existing directory is still checked before anything inside it is trusted."""
    import hashlib

    d = Path("/run/advanced-vpn") / ("state-" + hashlib.sha256(str(Path(state).resolve()).encode()).hexdigest()[:16])
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
        cmd(*prefix, "ip", "link", "set", name, "alias", "advanced-vpn-managed")
    else:
        row = json.loads(cmd(*prefix, "ip", "-j", "link", "show", "dev", name).stdout)[0]
        if row.get("ifalias") != "advanced-vpn-managed":
            raise RuntimeError("refusing unrelated pre-existing interface")
    cmd(*prefix, "ip", "address", "replace", addr, "dev", name)
    cmd(*prefix, "ip", "link", "set", name, "mtu", str(mtu), "up")


def nft(text, ns=None):
    """Load nftables rule text from stdin, in namespace `ns` if given."""
    prefix = ["ip", "netns", "exec", ns] if ns else []
    cmd(*prefix, "/usr/sbin/nft", "-f", "-", input=text)


def replace_table(body, ns=None):
    """Atomically replace the `inet advanced_vpn` table with `body`."""
    prefix = ["ip", "netns", "exec", ns] if ns else []
    exists = cmd(*prefix, "/usr/sbin/nft", "list", "table", "inet", "advanced_vpn", check=False).returncode == 0
    nft(("delete table inet advanced_vpn\n" if exists else "") + body, ns)


def app_firewall(ns):
    """Kill switch inside the protected namespace: only the tunnel and its DNS may leave."""
    replace_table(
        """table inet advanced_vpn {
 chain output { type filter hook output priority -100; policy drop;
  oifname "lo" accept
  ip daddr != 10.77.0.1 udp dport {53,853} drop
  ip daddr != 10.77.0.1 tcp dport {53,853} drop
  meta nfproto ipv4 oifname "avpn0" accept
 }
}\n""",
        ns,
    )


def whole_firewall(profile, service_uid=None):
    """Whole-device kill switch: drop everything except the tunnel, the carrier to the first hop and loopback."""
    host, port = profile["network"]["relay_endpoint"].rsplit(":", 1)
    carrier_allow = (
        ""
        if service_uid is None
        else (
            "  meta skuid "
            + str(service_uid)
            + " ip daddr "
            + host
            + " udp dport "
            + str(int(port))
            + " accept\n  meta skuid "
            + str(service_uid)
            + " ip daddr "
            + host
            + " tcp dport "
            + str(int(port))
            + " accept\n  meta skuid "
            + str(service_uid)
            + ' ip daddr 10.78.0.1 udp dport 4433 oifname "avwg0" accept\n'
        )
    )
    replace_table(
        """table inet advanced_vpn {
 chain output { type filter hook output priority -100; policy drop;
  oifname "lo" accept
  meta skuid 0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
"""
        + carrier_allow
        + """
  ip daddr != 10.77.0.1 udp dport {53,853} drop
  ip daddr != 10.77.0.1 tcp dport {53,853} drop
  meta nfproto ipv4 oifname "avpn0" accept
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
  udp dport 4433 iifname != "avwg0" drop
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
UPSTREAM_TABLE = "advanced_vpn_upstream"


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
    exists = cmd("/usr/sbin/nft", "list", "table", "inet", UPSTREAM_TABLE, check=False).returncode == 0
    text = "delete table inet %s\n" % UPSTREAM_TABLE if exists else ""
    if iface:
        host, port = endpoint.rsplit(":", 1)
        addr, pnum, dev = ipaddress.IPv4Address(host), int(port), valid_interface(iface)
        text += (
            "table inet %s {\n chain output { type filter hook output priority -110; policy accept;\n"
            '  ip daddr %s udp dport %d oifname != "%s" drop\n'
            '  ip daddr %s tcp dport %d oifname != "%s" drop\n }\n}\n'
        ) % (UPSTREAM_TABLE, addr, pnum, dev, addr, pnum, dev)
    if text:
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
    raise RuntimeError("upstream interface %s has no gateway; set avpn preferences --upstream-gateway" % iface)


def ensure_network(profile, state, whole=False, service_uid=0, upstream=None, upstream_gateway=None):
    """Build this role's network (TUN, namespace, routes, firewall), snapshotting the prior state once."""
    role = profile["role"]
    n = profile["network"]
    rt = runtime_dir(state)
    snapshot = restore_dir(state, profile) / "network-before.json"
    if not snapshot.exists():
        save(snapshot, dict(default=json.loads(cmd("ip", "-j", "route", "show", "default").stdout), whole_device=whole))
    if role == "client":
        if whole:
            if os.environ.get("SSH_CONNECTION"):
                raise RuntimeError("whole-device activation requires a local console")
            # Firewall is installed before any route change; errors leave traffic blocked.
            whole_firewall(profile, service_uid)
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
        if upstream:
            # Upstream entry: the guard goes in before the route, and a missing upstream
            # refuses the connection instead of falling back to the direct path.
            r = upstream_route(upstream, upstream_gateway)
            upstream_firewall(n["relay_endpoint"], upstream)
        else:
            upstream_firewall(n["relay_endpoint"], None)
            r = route_to(relay_ip)
        mtu_rows = json.loads(cmd("ip", "-j", "link", "show", "dev", r["dev"]).stdout)
        # The carrier rides inside the HTTP/3 cloak's QUIC: a full WireGuard datagram becomes a
        # 1420-byte QUIC UDP payload (cloak::OUTER_MTU), i.e. a 1448-byte IPv4 packet (+8 UDP +20 IP).
        # Below that the cloak cannot send full packets, so refuse rather than black-hole them; the
        # kill switch stays up (fail closed), as the caller's cleanup leaves it in place.
        if mtu_rows[0]["mtu"] < UNDERLAY_MIN_MTU:
            raise RuntimeError(
                "underlay MTU below the camouflage minimum (%d); the first hop is unreachable here" % UNDERLAY_MIN_MTU
            )
        args = ["ip", "route", "replace", relay_ip + "/32"]
        if "gateway" in r:
            args += ["via", r["gateway"]]
        args += ["dev", r["dev"]]
        cmd(*args)
        tun(WG, "10.78.0.2/32", 1340, owner=service_uid)
        cmd("ip", "route", "replace", "10.78.0.1/32", "dev", WG)
        tun(TUN, "10.77.0.2/32", profile["core"]["mtu"], ns, owner=service_uid)
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
                # link settings itself when avpn0 is removed.
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
        replace_table("table inet advanced_vpn {" + first_hop_rules(profile) + "\n}\n")
    else:
        carrier_first_hop = profile["carrier"] is not None  # single-hop chain: exit terminates WireGuard
        if carrier_first_hop:
            tun(WG, "10.78.0.1/32", 1340, owner=service_uid)
            cmd("ip", "route", "replace", "10.78.0.2/32", "dev", WG)
        tun(TUN, "10.77.0.1/32", profile["core"]["mtu"], owner=service_uid)
        cmd("ip", "route", "replace", "10.77.0.2/32", "dev", TUN)
        endpoint = profile["dns"]["upstream"].rsplit(":", 1)[0]
        wan = route_to(endpoint)["dev"]
        cmd("/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        # Never forward inner packets into an unrequested management/metadata/LAN destination.
        private = "ip daddr {0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4} drop"
        carrier_input = first_hop_rules(profile) if carrier_first_hop else ""
        replace_table(
            """table inet advanced_vpn {"""
            + carrier_input
            + """
 chain prerouting { type nat hook prerouting priority dstnat;
  iifname "avpn0" ip daddr 10.77.0.1 udp dport 53 redirect to :1053
  iifname "avpn0" ip daddr 10.77.0.1 tcp dport 53 redirect to :1053
 }
 chain forwarding { type filter hook forward priority -100; policy accept;
  iifname "avpn0" ip saddr != 10.77.0.2 drop
  iifname "avpn0" """
            + private
            + '''
  iifname "avpn0" meta nfproto ipv6 drop
  oifname "avpn0" ip daddr != 10.77.0.2 drop
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
    """The unprivileged UID/GID the data plane runs as (the mapped lab user, or `advanced-vpn`)."""
    if lab:
        lab_guard()

        def mapped(path):
            return any(
                int(p[0]) <= 1 < int(p[0]) + int(p[2])
                for p in (row.split() for row in Path(path).read_text().splitlines())
            )

        return (1, 1) if mapped("/proc/self/uid_map") and mapped("/proc/self/gid_map") else (0, 0)
    user = pwd.getpwnam("advanced-vpn")
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
    "core": "advanced-vpn",
    "carrier": "advanced-vpn-wireguard",
    "dns": "advanced-vpn-dns",
    "cloak": "advanced-vpn-cloak",
}
CHILD_KEYS = {"core": ["outer", "middle", "inner"], "carrier": ["wireguard"], "cloak": ["token", "cloak"]}
CLOAK_TOKEN_LABEL = b"advanced-vpn cloak"


# A working carrier always receives real data: the chain's inner QUIC keep-alives every
# 2 s. One that has received none for this long is stuck and is restarted. (Seen in strong
# mode: GotaTun's DAITA can stop releasing the packets Tamaraw holds back, for example
# after the first hop was unreachable at start; a fresh carrier recovers.)
CARRIER_STALL_SECONDS = 12


class CarrierWatch:
    """Notices a client carrier whose received-byte counter has stopped moving."""

    def __init__(self, limit=CARRIER_STALL_SECONDS):
        self.limit = limit
        self.pid = self.rx = self.since = None

    def stalled(self, pid, rx, now):
        """True when carrier `pid` has received no new bytes for `limit` seconds.
        A new process, or any received byte, starts the clock again."""
        if pid != self.pid or rx is None or rx != self.rx:
            self.pid, self.rx, self.since = pid, rx, now
            return False
        return now - self.since >= self.limit


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
    if published.get("dns", {}).get("blocklist"):
        source = Path(published["dns"]["blocklist"])
        target = directory / source.name
        owned_public(target, read_private(source), uid, gid)
        published["dns"]["blocklist"] = str(target)
    for name, value in published.items():
        owned_public(directory / (name + ".runtime.json"), canonical(value), uid, gid)


def prepare_runtime(cfg, bin_dir, state, uid, gid, lab=False):
    """Stage the binaries and config into a root-owned runtime directory the service user can only read."""
    import tempfile

    base = Path("/run/advanced-vpn-runtime-" + str(os.stat("/proc/self/ns/net").st_ino))
    base.mkdir(mode=0o711, exist_ok=True)
    if base.is_symlink() or base.stat().st_uid != 0 or base.stat().st_mode & 0o022:
        raise RuntimeError("unsafe runtime parent")
    base.chmod(0o711)
    executables = base / "bin" if lab else bin_dir
    if lab:
        executables.mkdir(mode=0o755, exist_ok=True)
        executables.chmod(0o755)
        # Only what this device runs: a middle relay never stages the cloak or WireGuard.
        for name in [BINARIES[section] for section in cfg]:
            src = bin_dir / name
            tmp = executables / (name + ".tmp")
            shutil.copyfile(src, tmp)
            tmp.chmod(0o755)
            os.replace(tmp, executables / name)
    else:
        for name in [BINARIES[section] for section in cfg]:
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
    exists = cmd("/usr/sbin/nft", "list", "table", "inet", "advanced_vpn_meter", check=False).returncode == 0
    text = (
        ("delete table inet advanced_vpn_meter\n" if exists else "")
        + """table inet advanced_vpn_meter {
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


def meter_used():
    """Bytes counted by the kernel carrier quota, or None when it cannot be read."""
    r = cmd("/usr/sbin/nft", "-j", "list", "quota", "inet", "advanced_vpn_meter", "carrier", check=False)
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
    cmd("/usr/sbin/nft", "delete", "table", "inet", "advanced_vpn_meter", check=False)


def daily_limit(preferences, profile):
    """None means no cap (the default). A preference overrides the enrolled value."""
    if "daily_limit_mib" in preferences:
        v = preferences["daily_limit_mib"]
        return None if v is None else int(v) * 1048576
    return profile["daily_budget_bytes"]


def launch_client(binary, config, ns, log=None, key_fds=None, uid=0, gid=0):
    """Attach TUN in app namespace, return to underlay; no application gets an underlay FD."""
    import struct

    current = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    app = os.open("/run/netns/" + ns, os.O_RDONLY | os.O_CLOEXEC)
    os.setns(app, 0)
    os.close(app)
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", TUN.encode(), 0x1001))
    os.setns(current, 0)
    os.close(current)
    parent = os.getpid()
    extra = []
    inherited = [fd]
    for name, value in (key_fds or {}).items():
        extra += ["--key-fd", name + "=" + str(value)]
        inherited.append(value)
    try:
        return subprocess.Popen(
            [binary, "--config", str(config), "--tun-fd", str(fd), *extra],
            pass_fds=inherited,
            preexec_fn=functools.partial(child_guard, parent, uid, gid),
            stdout=log or subprocess.DEVNULL,
            stderr=log or subprocess.DEVNULL,
        )
    finally:
        os.close(fd)


def supervise(state, bin_dir, lab=False, whole=False):
    """The supervisor: build the network, start and restart the data plane, enforce the budget, write status."""
    root_guard(lab)
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
                "this server would keep logs on disk (%s); run avpn cloud host setup on it, or rebuild it "
                "with avpn cloud (avpn help retention)" % "; ".join(name for name, _, _ in failing)
            )
    uid, gid = service_identity(lab)
    rt = runtime_dir(state)
    lock = os.open(rt / "controller.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    global_lock = os.open(
        "/run/advanced-vpn-" + str(os.stat("/proc/self/ns/net").st_ino) + ".lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        0o600,
    )
    fcntl.flock(global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    save(rt / "controller.json", dict(pid=os.getpid(), identity=identity_of(os.getpid())))
    early = read_json_private(state / "preferences.json", {}) if profile["role"] == "client" else {}
    ensure_network(
        profile,
        state,
        whole,
        uid,
        upstream=early.get("upstream_interface"),
        upstream_gateway=early.get("upstream_gateway"),
    )
    cfg = runtime(profile, state)
    preferences = json.loads(read_private(state / "preferences.json")) if (state / "preferences.json").exists() else {}
    from keyguard import memory_fd

    # One unlock (Nitrokey PIN+touch, TPM-bound systemd-creds, or explicit plaintext)
    # moves each key into a sealed memfd. No Python copy is kept: rotation reads the
    # key back from its descriptor only for the moment it signs a fresh leaf.
    key_handles = {name: memory_fd(value) for name, value in load_keys(state, list(managed_identities(cfg))).items()}
    if "cloak" in cfg:
        key_handles["token"] = memory_fd(cloak_token(fd_bytes(key_handles["wireguard"])))
        if cfg["cloak"]["role"] == "server":
            # A fresh self-signed certificate for the pinned key, in root-only RAM.
            cert = rt / "cloak-cert.der"
            atomic(cert, cloak_certificate(fd_bytes(key_handles["cloak"]), cfg["cloak"]["cover_name"]))
            cfg["cloak"]["cert"] = str(cert)
    refresh_leaves(
        cfg["core"],
        state,
        {n: fd_bytes(key_handles[n]) for n in ["outer", "middle", "inner"] if n in key_handles},
        out_dir=rt,
    )
    bin_dir, device_dir = prepare_runtime(cfg, bin_dir, state, uid, gid, lab)
    for name in cfg:
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
    stop_reason = "disconnected"
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
            if time.monotonic() - last_refresh >= 21600 or rotate_requested:
                refresh_leaves(
                    cfg["core"],
                    state,
                    {n: fd_bytes(key_handles[n]) for n in ["outer", "middle", "inner"] if n in key_handles},
                    out_dir=rt,
                )
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
                binary = str(bin_dir / BINARIES[name])
                path = device_dir / (name + ".runtime.json")
                log = (rt / (name + ".lab.log")).open("a") if lab else None  # lab only; RAM like everything else
                fds = {r: v for r, v in key_handles.items() if r in CHILD_KEYS.get(name, [])}
                if name == "core" and profile["role"] == "client" and not whole:
                    children[name] = launch_client(binary, path, APP, log, fds, uid, gid)
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
                    daily_limit_bytes=allowance.limit,
                    children={
                        k: dict(pid=v.pid, identity=identity_of(v.pid), alive=v.poll() is None)
                        for k, v in children.items()
                    },
                )
                if budget_blocked:
                    row["reason"] = "privacy_budget"
                save(rt / "status.json", row)
            time.sleep(0.25)
    finally:
        for p in children.values():
            stop(p)
        settle_grant()
        save(rt / "status.json", dict(schema=1, state="blocked", kill_switch=True, reason=stop_reason))
        # Persistent nftables, TUN and namespace are deliberately retained on exit/crash.
        os.close(lock)
        os.close(global_lock)
        for fd in key_handles.values():
            os.close(fd)
        shutil.rmtree(device_dir, ignore_errors=True)


def control_signal(state, signum):
    """Send `signum` to the live supervisor, refusing if its recorded PID now belongs to another process."""
    info = json.loads(read_private(runtime_dir(state) / "controller.json"))
    if identity_of(info["pid"]) != info["identity"]:
        raise RuntimeError("stale controller PID; refusing to signal unrelated process")
    os.kill(info["pid"], signum)


def fd_bytes(fd):
    """The whole contents of a sealed memfd."""
    return os.pread(fd, os.fstat(fd).st_size, 0)


def managed_identities(cfg):
    """The certificate identities this profile's data-plane processes present, by role."""
    out = {r: cfg["core"][r] for r in ["outer", "middle", "inner"] if cfg["core"].get(r)}
    if "carrier" in cfg:
        out["wireguard"] = cfg["carrier"]["identity"]
    if cfg.get("cloak", {}).get("role") == "server":
        out["cloak"] = cfg["cloak"]
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
    os.setns(ns, 0)
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
    os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/nonexistent-advanced-vpn-bus"
    import ctypes

    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError("cannot set no_new_privs")
    os.execvp(argv[0], argv)


def reset(state, lab=False):
    """Remove the kill switch and restore the saved routes; refuses while the supervisor or protected apps run."""
    root_guard(lab)
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
    if before["whole_device"]:
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
        if (keep / "resolv.before").exists():
            Path("/etc/resolv.conf").resolve().write_bytes(read_private(keep / "resolv.before"))
    for name in [WG, TUN]:
        if link_exists(name):
            row = json.loads(cmd("ip", "-j", "link", "show", "dev", name).stdout)[0]
            if row.get("ifalias") == "advanced-vpn-managed":
                cmd("ip", "link", "del", name)
    for name in ["advanced_vpn", "advanced_vpn_meter", UPSTREAM_TABLE]:
        cmd("/usr/sbin/nft", "delete", "table", "inet", name, check=False)
    save(rt / "status.json", dict(schema=1, state="unlocked", kill_switch=False, explicit_cleartext_permission=True))


def harden_process():
    """No core files, private umask, and non-dumpable: blocks same-UID ptrace and
    /proc/<pid>/mem reads of the keys this controller unseals."""
    import ctypes

    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError("cannot make controller non-dumpable")  # PR_SET_DUMPABLE


DEVICE_VAULT = Path("/etc/advanced-vpn/vault")


def device_vault(vault):
    """The Nitrokey vault holding this device's key-sealing credential. The VPN service
    runs as root and reads it, so it must be root-owned and private; by default it is
    /etc/advanced-vpn/vault, created here on first use (FIDO2 PIN + touch)."""
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


def emit(args, message, **data):
    """Print one command result: human text, or a single JSON object with --json."""
    if getattr(args, "json", False):
        print(json.dumps(dict(ok=True, action=args.action, message=message, **data), sort_keys=True, default=str))
    else:
        print(message)


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
    if info["enrolled"]:
        profile = load_profile(state)
        preferences = read_json_private(state / "preferences.json", {})
        info.update(
            role=profile["role"],
            hops=profile["hops"],
            padded=profile["core"].get("cells") is True,
            # None: this device runs no carrier (a middle relay, or the exit of a longer chain).
            camouflaged=bool(profile.get("cloak")) if profile["carrier"] else None,
            chain=[dict(hop=name, endpoint=endpoint) for name, endpoint in chain_of(profile)],
            defense=(profile["carrier"] or {}).get("defense"),
            rate=(profile["carrier"] or {}).get("rate", "metered") if profile["carrier"] else None,
            mode=preferences.get("mode", "applications"),
            upstream_interface=preferences.get("upstream_interface"),
            daily_limit_bytes=daily_limit(preferences, profile) if profile["role"] == "client" else None,
        )
    status_file = runtime_dir(state, create=False) / "status.json"
    info["status"] = read_json_private(status_file, dict(state="not running"))
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
    return "\n".join(lines)


def doctor(state, check_egress=False):
    """Self-checks: (name, ok, detail) for installation, keys, firewall, resolver and units."""
    checks = []

    def check(name, ok, detail):
        checks.append(dict(check=name, ok=bool(ok), detail=detail))

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
    try:
        info = device_info(state)
    except (OSError, ValueError, PermissionError) as e:
        check("enrollment readable", False, type(e).__name__)
        return checks
    check("device keys generated", "role" in info, info.get("role", "run `avpn request` first"))
    check(
        "enrolled in a chain",
        info["enrolled"],
        "%s hop(s)" % info.get("hops") if info["enrolled"] else "run `avpn enroll`",
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
            else "re-sign: avpn cloud chain --apply, then enroll --replace",
        )
    if info["enrolled"] and info.get("camouflaged") is not None:
        check(
            "HTTP/3 camouflage",
            info["camouflaged"],
            "the link to the first hop looks like HTTP/3 on UDP 443, not WireGuard"
            if info["camouflaged"]
            else "re-sign: avpn cloud chain --apply, then enroll --replace",
        )
    if info.get("protection") == "systemd-creds":
        from keyguard import tpm2_usable

        tpm = tpm2_usable()
        check(
            "keys bound to TPM2",
            info.get("creds_key") == "host+tpm2",
            "sealed with " + str(info.get("creds_key")) + ("; TPM2 usable now" if tpm else "; no usable TPM2"),
        )
    elif info.get("protection"):
        check("key protection", info["protection"] != "none", info["protection"])
    listed = probe("nft", "list", "tables") if os.geteuid() == 0 else None
    tables = listed.stdout if listed else ""
    if info.get("role") == "client" and info.get("mode") == "whole-device":
        check("whole-device kill switch table", "advanced_vpn" in tables, "inet advanced_vpn")
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
        check("upstream entry", True, "off: the first hop sees this network's address (avpn help privacy)")
    for unit in ["advanced-vpn.service", "advanced-vpn-guard.service"]:
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
        default=Path("/etc/advanced-vpn/enrolled"),
        help="enrollment directory (root-owned, mode 0700)",
    )
    p.add_argument(
        "--bin-dir", type=Path, default=Path("/usr/local/bin"), help="directory holding the advanced-vpn binaries"
    )
    p.add_argument("--lab", action="store_true", help="tests only; requires an unprivileged user namespace")
    p.add_argument("--json", action="store_true", help="print one JSON object per command (used by the avpn CLI)")
    s = p.add_subparsers(dest="action", required=True)
    rq = s.add_parser("request", help="generate this device's keys locally; prints the public request")
    rq.add_argument(
        "--role",
        choices=["client", "relay", "middle", "exit"],
        required=True,
        help="what this device will be in the chain",
    )
    rq.add_argument(
        "--protect",
        choices=["nitrokey", "systemd-creds", "none"],
        required=True,
        help="how the private keys are sealed at rest",
    )
    rq.add_argument(
        "--vault",
        type=Path,
        help="Nitrokey vault (nitrokey protection; default /etc/advanced-vpn/vault, created if missing)",
    )
    rq.add_argument("--out", type=Path, required=True, help="public request file to copy to the operator")
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
    signer = init.add_mutually_exclusive_group(required=True)
    signer.add_argument("--vault", type=Path, help="Nitrokey vault: hardware-signed operator (production)")
    signer.add_argument("--software-operator", type=Path, help="LAB ONLY: plaintext operator keys in this directory")
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
        "--daily-limit-mib", type=int, default=None, help="optional fail-closed daily carrier cap; default none"
    )
    init.add_argument(
        "--dns-blocklist",
        type=Path,
        default=None,
        help="optional domain blocklist file (one domain per line) signed into the exit bundle",
    )
    imp = s.add_parser("enroll", help="verify and install this device's signed bundle")
    imp.add_argument("bundle", type=Path, help="the .avpn bundle the operator produced for this device")
    imp.add_argument("--operator-key", type=Path, required=True, help="operator public key, obtained out of band")
    imp.add_argument(
        "--replace", action="store_true", help="switch this device to a new chain (keeps its keys; disconnect first)"
    )
    c = s.add_parser("connect", help="run the supervisor in the foreground (used by advanced-vpn.service)")
    c.add_argument("--whole-device", action="store_true", help="route the whole device for this run")
    c.add_argument("--app-only", action="store_true", help="protect only `run` applications for this run")
    s.add_parser("disconnect", help="stop the supervisor; the kill switch stays in place")
    s.add_parser("status", help="runtime status written by the supervisor")
    s.add_parser("info", help="non-secret summary: role, chain, protection, preferences, status")
    s.add_parser("hops", help="the enrolled chain, hop by hop")
    doc = s.add_parser("doctor", help="self-checks for installation, keys, firewall, resolver and units")
    doc.add_argument("--check-egress", action="store_true", help="also show the public address seen outside the tunnel")
    s.add_parser("rotate", help="rotate the short-lived session certificates now")
    s.add_parser("guard", help="(re)apply the boot-time kill switch (used by advanced-vpn-guard.service)")
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
    s.add_parser("unlock", help="answer a pending Nitrokey PIN prompt from the VPN service (e.g. after boot)")
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
    return p


def main():
    """Command-line entry point: harden the process, parse arguments, run one action."""
    harden_process()
    a = build_parser().parse_args()
    if a.action == "request":
        vault = device_vault(a.vault) if a.protect == "nitrokey" else a.vault
        req = request(a.role, a.state.resolve(), a.protect, vault)
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
        requests = {}
        for item in a.request:
            role, path = item.split("=", 1)
            requests[role] = Path(path).read_bytes()
        rate, why = choose_rate(a.rate, a.allowance_gib, a.hours_per_day, a.accept_cost)
        signer_impl = HardwareOperator(a.vault) if a.vault else SoftwareOperator(a.software_operator.resolve())
        dns_arg = (
            dict(upstream="9.9.9.9:853", server_name="dns.quad9.net", blocklist=a.dns_blocklist.read_bytes())
            if a.dns_blocklist
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
        )
        emit(
            a,
            "Signed %d-hop chain written to %s (operator %s), rate %s: %s; about %d GiB/month per hop at %g h/day."
            % (a.hops, a.out, operator[:16], rate, why, rate_cost_gib(rate, a.hours_per_day), a.hours_per_day),
            operator_sha256=operator,
            out=str(a.out),
            hops=a.hops,
            rate=rate,
            rate_reason=why,
            monthly_gib_per_hop=round(rate_cost_gib(rate, a.hours_per_day)),
        )
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
        preferences = (
            json.loads(read_private(a.state / "preferences.json")) if (a.state / "preferences.json").exists() else {}
        )
        if a.whole_device and a.app_only:
            raise ValueError("choose one connection mode")
        whole = a.whole_device or (not a.app_only and preferences.get("mode") == "whole-device")
        supervise(a.state.resolve(), a.bin_dir.resolve(), a.lab, whole)
    elif a.action == "disconnect":
        root_guard(a.lab)
        control_signal(a.state, signal.SIGTERM)
        emit(a, "Disconnect requested; the kill switch stays in place.")
    elif a.action == "rotate":
        root_guard(a.lab)
        control_signal(a.state, signal.SIGHUP)
        emit(a, "Certificate rotation requested.")
    elif a.action == "preferences":
        root_guard(a.lab)
        old = json.loads(read_private(a.state / "preferences.json")) if (a.state / "preferences.json").exists() else {}
        if a.mode:
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
        os.execv(trusted_exe("systemd-tty-ask-password-agent"), ["systemd-tty-ask-password-agent", "--query"])
    elif a.action == "status":
        status = read_json_private(runtime_dir(a.state, create=False) / "status.json", dict(state="not running"))
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
        reset(a.state.resolve(), a.lab)
        emit(a, "Guard removed; cleartext networking restored.")
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
        # Only the controller's own refusals carry a message; anything else is reported
        # by type alone, so no library error text (paths, arguments) is echoed.
        detail = str(e)[:200] if type(e) in (RuntimeError, ValueError) else ""
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

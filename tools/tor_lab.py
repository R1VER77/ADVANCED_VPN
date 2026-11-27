"""Tor-over-the-tunnel leak-direction harness (D021) and ephemeral isolated browser launcher.

Closes two endpoint-correlation blind spots:
1. D021 (docs/DECISIONS.md): proves that running Tor inside the VPN namespace cannot fall
   back to direct WAN egress if the tunnel interface drops (zero direct-uplink packets).
2. Ephemeral browser isolation: provides a disposable 0700 browser profile directory with
   hardened anti-fingerprinting preferences and overwrite-before-unlink teardown so cookies,
   caches, and storage never link sessions across fresh shared-access VPN credits.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading


IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")

FIREFOX_HARDENED_PREFS = """\
// Ephemeral Cypherpunk VPN isolated session profile (wiped on exit)
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.offline.enable", false);
user_pref("browser.privatebrowsing.autostart", true);
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("media.peerconnection.enabled", false);
user_pref("dom.battery.enabled", false);
user_pref("geo.enabled", false);
user_pref("beacon.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
"""


def validate_iface(name: str) -> str:
    """Validate a Linux network interface name against strict safe characters."""
    if not isinstance(name, str) or not IFACE_RE.match(name):
        raise ValueError(f"invalid network interface name: {name!r}")
    return name


def tor_namespace_nft_rules(
    tunnel_iface: str = "cpvpn0",
    tor_uid: int | None = None,
    socks_port: int = 9050,
    dns_server: str | None = None,
) -> str:
    """Generate fail-closed inet nftables rules for Tor running inside the VPN namespace.

    Guarantees:
    - Loopback is limited to local Tor SOCKS/control ports (no arbitrary local exfiltration).
    - All non-loopback Tor egress MUST leave through `tunnel_iface` (never direct WAN).
    - Any packet attempting to leave via a non-tunnel interface is counted and dropped.
    """
    iface = validate_iface(tunnel_iface)
    if not (1024 <= int(socks_port) <= 65535):
        raise ValueError("socks_port must be an unprivileged port (1024..65535)")
    if tor_uid is not None and int(tor_uid) <= 0:
        raise ValueError("tor_uid must be an unprivileged UID (> 0)")
    uid_clause = f"meta skuid {int(tor_uid)} " if tor_uid is not None else ""
    dns_rule = ""
    if dns_server is not None:
        ip = ipaddress.ip_address(dns_server)
        proto = "ip" if ip.version == 4 else "ip6"
        dns_rule = f'  oifname "{iface}" {proto} daddr {ip} udp dport 53 accept\n'
    return (
        "table inet cpvpn_tor_guard {\n"
        " counter tor_tunnel_packets {}\n"
        " counter tor_direct_drops {}\n"
        " chain output { type filter hook output priority -150; policy drop;\n"
        "  ct state invalid drop\n"
        '  oifname "lo" ip daddr 127.0.0.1 tcp dport ' + str(int(socks_port)) + " accept\n"
        '  oifname "lo" ct state established,related accept\n'
        + dns_rule
        + f'  {uid_clause}oifname "{iface}" counter name tor_tunnel_packets accept\n'
        + f'  {uid_clause}oifname != "{iface}" counter name tor_direct_drops drop\n'
        "  counter name tor_direct_drops drop\n"
        " }\n"
        " chain forward { type filter hook forward priority -150; policy drop; }\n"
        "}\n"
    )


class EphemeralBrowserProfile:
    """Disposable 0700 browser profile directory that wipes all session state on exit."""

    def __init__(self, browser: str = "firefox", base_dir: Path | None = None, socks_proxy: str | None = None):
        if browser not in ("firefox", "chromium"):
            raise ValueError(f"unsupported browser: {browser!r}")
        self.browser = browser
        self.base_dir = base_dir
        self.socks_proxy = socks_proxy
        self.root: Path | None = None
        self.profile_dir: Path | None = None

    def __enter__(self) -> "EphemeralBrowserProfile":
        parent = str(self.base_dir) if self.base_dir is not None else None
        self.root = Path(tempfile.mkdtemp(prefix="cpvpn-ephemeral-", dir=parent))
        os.chmod(self.root, 0o700)
        self.profile_dir = self.root / "profile"
        self.profile_dir.mkdir(mode=0o700)
        (self.root / "home").mkdir(mode=0o700)
        (self.root / "config").mkdir(mode=0o700)
        (self.root / "cache").mkdir(mode=0o700)
        (self.root / "tmp").mkdir(mode=0o700)
        if self.browser == "firefox":
            prefs = FIREFOX_HARDENED_PREFS
            if self.socks_proxy:
                host, port = self.socks_proxy.rsplit(":", 1)
                prefs += (
                    'user_pref("network.proxy.type", 1);\n'
                    f'user_pref("network.proxy.socks", "{host}");\n'
                    f'user_pref("network.proxy.socks_port", {int(port)});\n'
                    'user_pref("network.proxy.socks_version", 5);\n'
                    'user_pref("network.proxy.socks_remote_dns", true);\n'
                )
            (self.profile_dir / "user.js").write_text(prefs, encoding="utf-8")
            os.chmod(self.profile_dir / "user.js", 0o600)
        return self

    def env(self, base_env: dict[str, str] | None = None) -> dict[str, str]:
        """Return an isolated environment rooted inside the ephemeral profile directory."""
        if self.root is None:
            raise RuntimeError("EphemeralBrowserProfile must be entered before building env")
        merged = dict(os.environ if base_env is None else base_env)
        merged["HOME"] = str(self.root / "home")
        merged["XDG_CONFIG_HOME"] = str(self.root / "config")
        merged["XDG_CACHE_HOME"] = str(self.root / "cache")
        merged["TMPDIR"] = str(self.root / "tmp")
        # Strip host telemetry/session tokens that could correlate sessions.
        for key in ("MOZ_CRASHREPORTER_URL", "CHROME_USER_DATA_DIR"):
            merged.pop(key, None)
        return merged

    def argv(self, binary: str, url: str = "about:blank") -> list[str]:
        """Build isolated browser launch argv pointing at the disposable profile."""
        if self.profile_dir is None:
            raise RuntimeError("EphemeralBrowserProfile must be entered before building argv")
        if self.browser == "firefox":
            return [binary, "--no-remote", "--new-instance", "--profile", str(self.profile_dir), url]
        cmd = [
            binary,
            f"--user-data-dir={self.profile_dir}",
            "--incognito",
            "--disable-background-networking",
            "--disable-sync",
            "--no-first-run",
        ]
        if self.socks_proxy:
            cmd.append(f"--proxy-server=socks5://{self.socks_proxy}")
            cmd.append("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1")
        cmd.append(url)
        return cmd

    def wipe(self) -> None:
        """Overwrite disposable browser state files with zeros and remove the directory tree."""
        if self.root is None or not self.root.exists():
            return
        # Overwrite small regular files (cookies, sqlite WAL, prefs) before unlinking.
        for path in self.root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                try:
                    size = path.stat().st_size
                    if 0 < size <= 4 * 1024 * 1024:
                        with open(path, "r+b") as handle:
                            handle.write(b"\x00" * size)
                            handle.flush()
                except OSError:
                    pass
        shutil.rmtree(self.root, ignore_errors=True)
        self.root = None
        self.profile_dir = None

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.wipe()


def run_tor_leak_direction_probe(tunnel_iface: str = "cpvpn0") -> dict:
    """Prove inside a live Linux network namespace that Tor traffic uses ONLY the tunnel.

    Creates two veth pairs:
    - `cpvpn0` (10.200.1.2/24 <-> 10.200.1.1/24): simulated encrypted VPN tunnel
    - `wan0`   (10.200.2.2/24 <-> 10.200.2.1/24): simulated direct ISP uplink

    Applies `tor_namespace_nft_rules(tunnel_iface)` via nftables, sends UDP probes toward
    both the tunnel peer and the direct WAN peer, and verifies:
    - tunnel_received == probes_sent (100% tunnel delivery)
    - direct_wan_received == 0 (0 direct-uplink packets leaked)
    """
    iface = validate_iface(tunnel_iface)
    ip_bin = shutil.which("ip") or "/usr/sbin/ip"
    nft_bin = shutil.which("nft") or "/usr/sbin/nft"

    def run_checked(*args: str, stdin_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            list(args),
            input=stdin_text,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )

    # Setup simulated tunnel and direct WAN veth pairs inside the current netns.
    # Peer ends (`tunpeer`, `wanpeer`) carry NO local IP so the kernel routes packets
    # genuinely out `cpvpn0` / `wan0` through the nftables `output` hook rather than `lo`.
    run_checked(ip_bin, "link", "set", "lo", "up")
    run_checked(ip_bin, "link", "add", iface, "type", "veth", "peer", "name", "tunpeer")
    run_checked(ip_bin, "link", "add", "wan0", "type", "veth", "peer", "name", "wanpeer")
    run_checked(ip_bin, "addr", "add", "10.200.1.2/24", "dev", iface)
    run_checked(ip_bin, "addr", "add", "10.200.2.2/24", "dev", "wan0")
    for dev in (iface, "tunpeer", "wan0", "wanpeer"):
        run_checked(ip_bin, "link", "set", dev, "up")
    import json

    tun_mac = json.loads(run_checked(ip_bin, "-j", "link", "show", "dev", "tunpeer").stdout)[0]["address"]
    wan_mac = json.loads(run_checked(ip_bin, "-j", "link", "show", "dev", "wanpeer").stdout)[0]["address"]
    run_checked(ip_bin, "neigh", "replace", "10.200.1.1", "lladdr", tun_mac, "dev", iface, "nud", "permanent")
    run_checked(ip_bin, "neigh", "replace", "10.200.2.1", "lladdr", wan_mac, "dev", "wan0", "nud", "permanent")

    rules = tor_namespace_nft_rules(tunnel_iface=iface)
    run_checked(nft_bin, "-f", "-", stdin_text=rules)

    tun_got: list[bytes] = []
    wan_got: list[bytes] = []

    sock_tun = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock_tun.bind(("tunpeer", 0))
    sock_tun.settimeout(0.1)
    sock_wan = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock_wan.bind(("wanpeer", 0))
    sock_wan.settimeout(0.1)

    def drain_veth(sock: socket.socket, marker: bytes, bucket: list[bytes], stop: threading.Event):
        try:
            while not stop.is_set():
                try:
                    frame = sock.recv(2048)
                    if marker in frame:
                        bucket.append(frame)
                except socket.timeout:
                    continue
        finally:
            sock.close()

    stop = threading.Event()
    t_tun = threading.Thread(target=drain_veth, args=(sock_tun, b"tor-guard-cell-", tun_got, stop), daemon=True)
    t_wan = threading.Thread(target=drain_veth, args=(sock_wan, b"direct-leak-attempt-", wan_got, stop), daemon=True)
    t_tun.start()
    t_wan.start()

    probes = 5
    direct_errors = 0
    try:
        # 1. Tunnel egress probes (must traverse cpvpn0 and reach tunpeer).
        s_tun = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(probes):
            s_tun.sendto(f"tor-guard-cell-{i}".encode(), ("10.200.1.1", 9001))
        s_tun.close()

        # 2. Direct WAN fallback probes (must be dropped by cpvpn_tor_guard before wanpeer).
        s_wan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(probes):
            try:
                s_wan.sendto(f"direct-leak-attempt-{i}".encode(), ("10.200.2.1", 9002))
            except OSError:
                direct_errors += 1
        s_wan.close()

        # Wait briefly for raw peer capture threads to drain.
        threading.Event().wait(0.25)
    finally:
        stop.set()
        t_tun.join(timeout=2)
        t_wan.join(timeout=2)

    counters = run_checked(nft_bin, "list", "table", "inet", "cpvpn_tor_guard").stdout
    tun_counter = re.search(r"counter tor_tunnel_packets \{[^}]*packets (\d+)", counters)
    drop_counter = re.search(r"counter tor_direct_drops \{[^}]*packets (\d+)", counters)
    tun_pkts = int(tun_counter.group(1)) if tun_counter else 0
    drop_pkts = int(drop_counter.group(1)) if drop_counter else 0
    return {
        "ok": len(tun_got) == probes and len(wan_got) == 0 and tun_pkts >= probes and drop_pkts >= probes,
        "probes_sent": probes,
        "tunnel_received": len(tun_got),
        "direct_wan_received": len(wan_got),
        "direct_send_errors": direct_errors,
        "nft_tunnel_counter_packets": tun_pkts,
        "nft_direct_drop_counter_packets": drop_pkts,
        "nft_table_present": "tor_direct_drops" in counters and "tor_tunnel_packets" in counters,
    }


if __name__ == "__main__":
    import json
    import sys

    result = run_tor_leak_direction_probe()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ok"] else 1)

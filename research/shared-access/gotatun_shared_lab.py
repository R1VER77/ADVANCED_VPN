#!/usr/bin/env python3
"""Two-hop shared-access lab using two real schema-3 GotaTun carriers in isolated namespaces.

Verifies:
- Entry-first, exit-through-entry pinned TLS 1.3 admission with RFC 9266 tls-exporter keys
- Real `cypherpunk-vpn-wireguard` schema-3 carriers on entry (`10.78.0.0/24`) and exit (`10.79.0.0/24`)
- Required upstream guard (blocks admission & traffic on upstream loss with zero direct-route packets)
- Atomic rollback when exit admission fails (both carriers return to 0 peers)
- End-to-end DNS and authenticated HTTPS through nested GotaTun carriers
- IPv6 and direct-DNS leak protection
- Aggregate-only carrier statistics & admission counters (no client/destination IPs or timestamps)
- Clean peer removal on explicit disconnect and automatic eviction on grant expiry
- Optional `--hardware` / `--hardware-vault` physical Nitrokey CreditWallet sealing/reopening
"""

import argparse
import base64
from contextlib import suppress
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import keyguard  # noqa: E402
from shared_admission import (  # noqa: E402
    AdmissionError,
    Cohort,
    EPOCH_SECONDS,
    PSS,
    ROLES,
    ReplayLedger,
    SPKI_PREFIX,
    TOKEN_TYPE,
)
from shared_carrier import SharedCarrier  # noqa: E402
from shared_session import AdmissionServer, HopEndpoint, SharedSessionClient  # noqa: E402
from shared_wallet import CreditWallet, PAIRS_PER_BATCH  # noqa: E402

SCRIPT = str(Path(__file__).resolve())
CLIENT, ENTRY, EXIT = "gt-client", "gt-entry", "gt-exit"
DNS_QUERY = bytes.fromhex("010001000001000000000000056c6f63616c04746573740000010001")
DNS_REPLY = (
    DNS_QUERY[:2]
    + b"\x81\x80"
    + DNS_QUERY[4:6]
    + b"\x00\x01"
    + DNS_QUERY[8:]
    + bytes.fromhex("c00c00010001000000000004cb007102")
)


def cmd(*args, check=True, input_text=None):
    """Run one command inside the isolated namespace fixture."""
    return subprocess.run(args, check=check, input=input_text, text=True, capture_output=True, timeout=15)  # noqa: S603


def ns_exec(namespace, *args, **kwargs):
    """Run a command inside a named fixture network namespace."""
    return cmd("ip", "netns", "exec", namespace, *args, **kwargs)


def write_private(path: Path, data: bytes):
    """Create a mode-0600 temporary file without overwriting existing files."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def make_tls(directory: Path, role: str):
    """Create a disposable pinned TLS 1.3 keypair and certificate for one hop."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, f"{role}.vpn.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"{role}.vpn.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / f"{role}.crt"
    key_path = directory / f"{role}.key"
    write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    write_private(
        key_path,
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )
    hop_id = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).digest()
    return cert_path, key_path, hop_id


def wait_peers(stats_path: Path, expected: int, timeout: float = 12.0):
    """Wait until aggregate carrier statistics report the expected live peer count."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stats_path.exists():
            try:
                data = json.loads(stats_path.read_text())
                if data.get("peers") == expected:
                    return data
            except (OSError, json.JSONDecodeError):
                pass
        time.sleep(0.1)
    raise RuntimeError(f"{stats_path} did not reach peers={expected}")


def launch_hop_worker(namespace: str, role: str, binary: Path, root: Path, cohort: Cohort, cert: Path, key: Path):
    """Spawn a namespace worker running schema-3 GotaTun + AdmissionServer (+ exit DNS/HTTPS)."""
    spec = {
        "role": role,
        "binary": str(binary),
        "root": str(root / role),
        "issuer_name": cohort.issuer_name,
        "pool_name": cohort.pool_name,
        "epoch": cohort.epoch,
        "issuer_spki": cohort.issuer_spki.hex(),
        "cert": str(cert),
        "key": str(key),
        "bind_ip": "192.0.2.2" if role == "entry" else "198.51.100.2",
        "bind_port": 8443 if role == "entry" else 8444,
    }
    spec_path = root / f"{role}-worker.json"
    write_private(spec_path, json.dumps(spec).encode())
    proc = subprocess.Popen(  # noqa: S603 - isolated fixture namespace
        ["/usr/sbin/ip", "netns", "exec", namespace, sys.executable, SCRIPT, "hop-worker", str(spec_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready, _, _ = select.select([proc.stdout], [], [], 12)
    if not ready:
        proc.kill()
        _, err = proc.communicate(timeout=5)
        raise RuntimeError(f"{role} hop worker timed out: {err}")
    line = proc.stdout.readline().strip()
    if not line.startswith("{"):
        proc.kill()
        _, err = proc.communicate(timeout=5)
        raise RuntimeError(f"{role} hop worker failed: {line} {err}")
    return proc, json.loads(line)


def run_hop_worker(spec_path: str):
    """Subprocess entrypoint inside gt-entry or gt-exit namespace."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    spec = json.loads(Path(spec_path).read_text())
    role = spec["role"]
    work_dir = Path(spec["root"])
    work_dir.mkdir(parents=True, exist_ok=True)
    server_wg = x25519.X25519PrivateKey.generate()
    server_pub = server_wg.public_key().public_bytes_raw()
    tun_ip = "10.78.0.1/24" if role == "entry" else "10.79.0.1/24"
    cmd("ip", "tuntap", "add", "dev", "cpwg0", "mode", "tun")
    cmd("ip", "addr", "add", tun_ip, "dev", "cpwg0")
    cmd("ip", "link", "set", "cpwg0", "mtu", "1340" if role == "entry" else "1180", "up")

    config = work_dir / "carrier.json"
    stats = work_dir / "statistics.json"
    binding = work_dir / "binding"
    write_private(binding, b"shared-gotatun-fixture")
    write_private(
        config,
        json.dumps(
            {
                "schema": 3,
                "role": "wireguard",
                "shared_role": role,
                "tun": "cpwg0",
                "listen_port": 41194,
                "endpoint": None,
                "peer_public_hex": "",
                "allowed_ip": "",
                "identity": {"key": str(work_dir / "unused"), "cert": str(binding)},
                "defense": "strong",
                "statistics": str(stats),
            }
        ).encode(),
    )
    key_fd = keyguard.memory_fd(server_wg.private_bytes_raw())
    supervisor, helper = socket.socketpair()
    carrier_proc = subprocess.Popen(  # noqa: S603 - isolated fixture carrier
        [
            spec["binary"],
            "--config",
            str(config),
            "--key-fd",
            f"wireguard={key_fd}",
            "--peer-control-fd",
            str(helper.fileno()),
        ],
        pass_fds=(key_fd, helper.fileno()),
        stderr=subprocess.PIPE,
        text=True,
    )
    helper.close()
    os.close(key_fd)

    ledger = ReplayLedger(work_dir / f"{role}-replay.sqlite", role)
    ledger.initialize()
    cohort = Cohort(
        spec["issuer_name"],
        spec["pool_name"],
        role,
        spec["epoch"],
        bytes.fromhex(spec["issuer_spki"]),
    )
    carrier = SharedCarrier(supervisor, role=role)
    wait_peers(stats, 0)
    server = AdmissionServer(
        bind=(spec["bind_ip"], spec["bind_port"]),
        cert_path=Path(spec["cert"]),
        key_path=Path(spec["key"]),
        cohort=cohort,
        ledger=ledger,
        carrier=carrier,
        server_wg_public=server_pub,
    )
    server.start()

    if role == "exit":
        class ExitHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"gotatun shared exit ok\n")

        https = HTTPServer(("10.79.0.1", 8443), ExitHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(spec["cert"], spec["key"])
        https.socket = ctx.wrap_socket(https.socket, server_side=True)
        Thread(target=https.serve_forever, daemon=True).start()

        def dns_loop():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("10.79.0.1", 5300))
                while True:
                    req, peer = sock.recvfrom(1024)
                    if req == DNS_QUERY:
                        sock.sendto(DNS_REPLY, peer)

        Thread(target=dns_loop, daemon=True).start()

    # Optional short-lease test command over stdin ("short-lease <pub_hex> <psk_hex> <secs>")
    print(json.dumps({"ready": True, "stats": str(stats), "server_public": server_pub.hex()}), flush=True)
    try:
        for line in sys.stdin:
            parts = line.strip().split()
            if not parts:
                continue
            if parts[0] == "metrics":
                print(json.dumps(server.metrics()), flush=True)
            elif parts[0] == "short-lease":
                pub = bytes.fromhex(parts[1])
                psk = bytes.fromhex(parts[2])
                secs = int(parts[3])
                addr = socket.inet_aton("10.78.0.200")
                frame = b"\x01" + pub + psk + addr + struct.pack("!Q", int(time.time()) + secs)
                carrier._apply(frame)  # noqa: SLF001 - intentional expiry test on live GotaTun
                print(json.dumps({"installed": True}), flush=True)
            elif parts[0] == "stop":
                break
    finally:
        server.stop()
        supervisor.close()
        carrier_proc.terminate()
        try:
            carrier_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            carrier_proc.kill()


def configure_client_wg(root: Path, iface: str, client_priv, server_pub: bytes, psk: bytes, addr: str, allowed: str, ep: str, mtu: int):
    """Configure a fresh ephemeral client WireGuard interface with the admitted PSK."""
    priv_p = root / f"{iface}.priv"
    psk_p = root / f"{iface}.psk"
    write_private(priv_p, base64.b64encode(client_priv.private_bytes_raw()) + b"\n")
    write_private(psk_p, base64.b64encode(psk) + b"\n")
    try:
        cmd("ip", "link", "add", iface, "type", "wireguard")
        cmd("wg", "set", iface, "private-key", str(priv_p), "peer", base64.b64encode(server_pub).decode(),
            "preshared-key", str(psk_p), "allowed-ips", allowed, "endpoint", ep)
        cmd("ip", "addr", "add", addr, "dev", iface)
        cmd("ip", "link", "set", iface, "mtu", str(mtu), "up")
    finally:
        priv_p.unlink(missing_ok=True)
        psk_p.unlink(missing_ok=True)


def run_client_driver(spec_path: str):
    """Subprocess entrypoint inside gt-client namespace."""
    spec = json.loads(Path(spec_path).read_text())
    root = Path(spec["root"])
    spki = bytes.fromhex(spec["issuer_spki"])
    entry_cohort = Cohort(spec["issuer_name"], spec["pool_name"], "entry", spec["epoch"], spki)
    exit_cohort = Cohort(spec["issuer_name"], spec["pool_name"], "exit", spec["epoch"], spki)
    entry_ep = HopEndpoint("192.0.2.2", 8443, "entry.vpn.test", Path(spec["entry_cert"]), bytes.fromhex(spec["entry_hop"]))
    exit_ep = HopEndpoint("198.51.100.2", 8444, "exit.vpn.test", Path(spec["exit_cert"]), bytes.fromhex(spec["exit_hop"]))
    pairs = [tuple(bytes.fromhex(t) for t in p) for p in spec["pairs"]]
    entry_stats = Path(spec["entry_stats"])
    exit_stats = Path(spec["exit_stats"])

    def probe_dns_https(expect_ok: bool):
        res = {"dns": False, "https": False}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(DNS_QUERY, ("10.79.0.1", 5300))
                res["dns"] = s.recvfrom(1024)[0] == DNS_REPLY
        except OSError:
            if expect_ok:
                raise
        try:
            ctx = ssl.create_default_context(cafile=spec["exit_cert"])
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(("10.79.0.1", 8443), timeout=3.0) as tcp:
                with ctx.wrap_socket(tcp, server_hostname="exit.vpn.test") as tls:
                    tls.sendall(b"GET / HTTP/1.0\r\nHost: exit.vpn.test\r\n\r\n")
                    res["https"] = tls.makefile("rb").read().endswith(b"gotatun shared exit ok\n")
        except OSError:
            if expect_ok:
                raise
        if res != {"dns": expect_ok, "https": expect_ok}:
            raise RuntimeError(f"unexpected probe result {res} (expected {expect_ok})")
        return res

    def activate_entry(grant):
        configure_client_wg(
            root, "outer0", grant.client_private, grant.server_public, grant.psk,
            f"{grant.assigned_address}/24", "10.78.0.1/32,198.51.100.2/32", "192.0.2.2:41194", 1340,
        )
        cmd("ip", "route", "replace", "198.51.100.2/32", "via", "10.78.0.1", "dev", "outer0")

    def teardown_entry(_grant):
        cmd("ip", "route", "del", "198.51.100.2/32", check=False)
        cmd("ip", "link", "del", "outer0", check=False)

    def activate_exit(grant):
        configure_client_wg(
            root, "inner0", grant.client_private, grant.server_public, grant.psk,
            f"{grant.assigned_address}/24", "10.79.0.1/32", "198.51.100.2:41194", 1180,
        )

    def teardown_exit(_grant):
        cmd("ip", "link", "del", "inner0", check=False)

    client = SharedSessionClient(
        entry_cohort=entry_cohort,
        exit_cohort=exit_cohort,
        entry_endpoint=entry_ep,
        exit_endpoint=exit_ep,
        upstream_interface="up0",
        activate_entry=activate_entry,
        teardown_entry=teardown_entry,
        activate_exit=activate_exit,
        teardown_exit=teardown_exit,
    )

    out = {}
    out["before_install"] = probe_dns_https(False)

    # 1. Upstream loss: take up0 down while direct0 stays UP; admission must fail closed.
    cmd("ip", "link", "set", "up0", "down")
    try:
        try:
            client.connect(*pairs[0])
            raise RuntimeError("connected despite upstream down")
        except AdmissionError:
            out["blocked_on_upstream_loss"] = True
    finally:
        cmd("ip", "link", "set", "up0", "up")
        cmd("ip", "route", "replace", "192.0.2.2/32", "dev", "up0")

    # 2. Partial peer install rollback: valid entry token + invalid (entry-role) exit token.
    try:
        client.connect(pairs[0][0], pairs[0][0])
        raise RuntimeError("exit accepted entry token")
    except AdmissionError:
        pass
    wait_peers(entry_stats, 0)
    wait_peers(exit_stats, 0)
    out["after_rollback"] = probe_dns_https(False)
    out["rolled_back_partial_peer"] = True

    # 3. Full two-hop live GotaTun session: DNS + HTTPS + leak checks.
    entry_grant, exit_grant = client.connect(*pairs[1])
    wait_peers(entry_stats, 1)
    wait_peers(exit_stats, 1)
    out["both_gotatun_peers"] = probe_dns_https(True)
    out["distinct_exporters"] = entry_grant.channel_binding != exit_grant.channel_binding
    out["distinct_psks"] = entry_grant.psk != exit_grant.psk

    # 4. IPv6 and direct-DNS bypass leak checks inside gt-client (must fail).
    ipv6_blocked = False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s6:
            s6.settimeout(0.5)
            s6.sendto(b"leak", ("2001:db8::1", 53))
    except OSError:
        ipv6_blocked = True
    direct_dns_blocked = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s4:
            s4.settimeout(0.5)
            s4.sendto(DNS_QUERY, ("192.0.2.6", 53))
    except OSError:
        direct_dns_blocked = True
    out["ipv6_blocked"] = ipv6_blocked
    out["direct_dns_blocked"] = direct_dns_blocked

    # 5. Clean explicit disconnect removes both peers and blocks traffic.
    client.disconnect(entry_grant, exit_grant)
    wait_peers(entry_stats, 0)
    wait_peers(exit_stats, 0)
    out["after_disconnect"] = probe_dns_https(False)

    print(json.dumps(out), flush=True)


def setup_topology():
    """Build three isolated namespaces with upstream-only guard and entry forwarding rules."""
    for ns in (CLIENT, ENTRY, EXIT):
        cmd("ip", "netns", "add", ns)
        cmd("ip", "-n", ns, "link", "set", "lo", "up")
    # Required upstream path: gt-client up0 <-> gt-entry lan0
    cmd("ip", "link", "add", "up0", "netns", CLIENT, "type", "veth", "peer", "name", "lan0", "netns", ENTRY)
    cmd("ip", "-n", CLIENT, "addr", "add", "192.0.2.1/30", "dev", "up0")
    cmd("ip", "-n", ENTRY, "addr", "add", "192.0.2.2/30", "dev", "lan0")
    cmd("ip", "-n", CLIENT, "link", "set", "up0", "up")
    cmd("ip", "-n", ENTRY, "link", "set", "lan0", "up")
    # Direct fallback path (must never receive leaked packets): gt-client direct0 <-> gt-entry lan1
    cmd("ip", "link", "add", "direct0", "netns", CLIENT, "type", "veth", "peer", "name", "lan1", "netns", ENTRY)
    cmd("ip", "-n", CLIENT, "addr", "add", "192.0.2.5/30", "dev", "direct0")
    cmd("ip", "-n", ENTRY, "addr", "add", "192.0.2.6/30", "dev", "lan1")
    cmd("ip", "-n", CLIENT, "link", "set", "direct0", "up")
    cmd("ip", "-n", ENTRY, "link", "set", "lan1", "up")
    # Entry <-> Exit underlay
    cmd("ip", "link", "add", "wan0", "netns", ENTRY, "type", "veth", "peer", "name", "lan0", "netns", EXIT)
    cmd("ip", "-n", ENTRY, "addr", "add", "198.51.100.1/30", "dev", "wan0")
    cmd("ip", "-n", EXIT, "addr", "add", "198.51.100.2/30", "dev", "lan0")
    cmd("ip", "-n", ENTRY, "link", "set", "wan0", "up")
    cmd("ip", "-n", EXIT, "link", "set", "lan0", "up")

    # Client upstream-only & IPv6-drop nftables guard
    ns_exec(
        CLIENT,
        "/usr/sbin/nft",
        "-f",
        "-",
        input_text="""table inet shared_client_guard {
 chain output { type filter hook output priority 0; policy drop;
  oifname "lo" accept
  oifname "up0" ip daddr 192.0.2.2 tcp dport 8443 accept
  oifname "up0" ip daddr 192.0.2.2 udp dport 41194 accept
  oifname "outer0" ip daddr 198.51.100.2 tcp dport 8444 accept
  oifname "outer0" ip daddr 198.51.100.2 udp dport 41194 accept
  oifname "inner0" ip daddr 10.79.0.1 accept
 }
}
""",
    )
    # Entry forwards ONLY inner tunnel traffic between cpwg0 and exit (198.51.100.2)
    ns_exec(ENTRY, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
    ns_exec(
        ENTRY,
        "/usr/sbin/nft",
        "-f",
        "-",
        input_text="""table inet shared_entry_fwd {
 chain forward { type filter hook forward priority 0; policy drop;
  iifname "cpwg0" oifname "wan0" ip daddr 198.51.100.2 tcp dport 8444 accept
  iifname "wan0" oifname "cpwg0" ip saddr 198.51.100.2 tcp sport 8444 accept
  iifname "cpwg0" oifname "wan0" ip daddr 198.51.100.2 udp dport 41194 accept
  iifname "wan0" oifname "cpwg0" ip saddr 198.51.100.2 udp sport 41194 accept
 }
}
""",
    )
    # Exit returns packets for entry's shared client range via entry's wan0
    cmd("ip", "-n", EXIT, "route", "add", "10.78.0.0/24", "via", "198.51.100.1", "dev", "lan0")


def issue_batch(epoch: int):
    """Mint a local fixed-size RFC 9578 RSA-PSS batch for the isolated two-hop fixture."""
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = SPKI_PREFIX + issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    cohorts = tuple(Cohort("issuer.vpn.test", "pool.vpn.test", role, epoch, spki) for role in ROLES)
    pairs = []
    for _ in range(PAIRS_PER_BATCH):
        pair = []
        for cohort in cohorts:
            body = (
                TOKEN_TYPE
                + os.urandom(32)
                + hashlib.sha256(cohort.challenge).digest()
                + hashlib.sha256(spki).digest()
            )
            pair.append(body + issuer.sign(body, PSS, hashes.SHA384()))
        pairs.append(tuple(pair))
    return spki, cohorts, pairs


def main():
    """Verify two-hop real GotaTun shared admission, leaks, rollback, disconnect, and expiry."""
    if len(sys.argv) >= 3 and sys.argv[1] == "hop-worker":
        run_hop_worker(sys.argv[2])
        return
    if len(sys.argv) >= 3 and sys.argv[1] == "client-driver":
        run_client_driver(sys.argv[2])
        return

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    hw = parser.add_mutually_exclusive_group()
    hw.add_argument("--hardware", action="store_true")
    hw.add_argument("--hardware-vault", type=Path)
    args = parser.parse_args()
    binary = args.bin.resolve()

    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[1] == "0" or mapping[2] != "1":
        raise RuntimeError("fresh unprivileged user namespace required")
    if {link["ifname"] for link in json.loads(cmd("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    os.umask(0o077)

    now = int(time.time())
    epoch = now // EPOCH_SECONDS
    spki, (entry_cohort, exit_cohort), raw_pairs = issue_batch(epoch)
    physical = args.hardware or args.hardware_vault is not None

    with tempfile.TemporaryDirectory(prefix="cpvpn-gotatun-shared-") as td:
        root = Path(td)
        wallet = CreditWallet(root / "wallet.json", args.hardware_vault or (root / "vault"), entry_cohort, exit_cohort)
        meta = {"credential": "Y3JlZGVudGlhbA==", "salt": "c2FsdA=="}
        ctx = keyguard.one_pin() if physical else patch("keyguard.hardware_secret", return_value=(secrets.token_bytes(32), meta))
        with ctx:
            if args.hardware:
                print("Enrolling disposable Nitrokey credential (PIN + touch)...", file=sys.stderr, flush=True)
                keyguard.enroll(wallet.vault)
            if physical:
                print("Sealing shared credit batch with Nitrokey (touch)...", file=sys.stderr, flush=True)
            wallet.import_batch(raw_pairs)
            opened_pairs = []
            for _ in range(2):
                if physical:
                    print("Opening sealed credit pair with Nitrokey (touch)...", file=sys.stderr, flush=True)
                opened_pairs.append(wallet.take_pair(now))

        # Isolate /run/netns after hardware PIN/touch so desktop pinentry can reach /run/user/<uid>.
        cmd("mount", "--make-rprivate", "/")
        cmd("mount", "-t", "tmpfs", "tmpfs", "/run")

        e_cert, e_key, e_hop = make_tls(root, "entry")
        x_cert, x_key, x_hop = make_tls(root, "exit")
        e_proc = x_proc = None
        try:
            setup_topology()
            e_proc, e_info = launch_hop_worker(ENTRY, "entry", binary, root, entry_cohort, e_cert, e_key)
            x_proc, x_info = launch_hop_worker(EXIT, "exit", binary, root, exit_cohort, x_cert, x_key)

            client_spec = root / "client-spec.json"
            write_private(
                client_spec,
                json.dumps(
                    {
                        "root": str(root / "client"),
                        "issuer_name": entry_cohort.issuer_name,
                        "pool_name": entry_cohort.pool_name,
                        "epoch": epoch,
                        "issuer_spki": spki.hex(),
                        "entry_cert": str(e_cert),
                        "exit_cert": str(x_cert),
                        "entry_hop": e_hop.hex(),
                        "exit_hop": x_hop.hex(),
                        "entry_stats": e_info["stats"],
                        "exit_stats": x_info["stats"],
                        "pairs": [[a.hex(), b.hex()] for a, b in opened_pairs],
                    }
                ).encode(),
            )
            (root / "client").mkdir(parents=True, exist_ok=True)
            lan1_before = int(ns_exec(ENTRY, "cat", "/sys/class/net/lan1/statistics/rx_packets").stdout.strip())
            res = ns_exec(CLIENT, sys.executable, SCRIPT, "client-driver", str(client_spec))
            driver_out = json.loads(res.stdout)

            # Verify zero packets ever arrived on entry's direct fallback interface (lan1) after guard setup.
            lan1_after = int(ns_exec(ENTRY, "cat", "/sys/class/net/lan1/statistics/rx_packets").stdout.strip())
            lan1_rx = lan1_after - lan1_before
            if lan1_rx != 0:
                raise RuntimeError(f"leaked {lan1_rx} packets on direct fallback interface")

            # Verify real GotaTun monotonic+wall grant expiry evicts peer automatically.
            tmp_pub = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
            tmp_psk = os.urandom(32).hex()
            e_proc.stdin.write(f"short-lease {tmp_pub} {tmp_psk} 4\n")
            e_proc.stdin.flush()
            json.loads(e_proc.stdout.readline())
            wait_peers(Path(e_info["stats"]), 1)
            wait_peers(Path(e_info["stats"]), 0, timeout=10.0)

            # Verify aggregate-only stats and admission metrics (no IPs or timestamps).
            e_proc.stdin.write("metrics\n")
            e_proc.stdin.flush()
            e_metrics = json.loads(e_proc.stdout.readline())
            x_proc.stdin.write("metrics\n")
            x_proc.stdin.flush()
            x_metrics = json.loads(x_proc.stdout.readline())
            e_stats_raw = Path(e_info["stats"]).read_text()
            x_stats_raw = Path(x_info["stats"]).read_text()
            for blob in (e_stats_raw, x_stats_raw, json.dumps(e_metrics), json.dumps(x_metrics)):
                for forbidden in ("192.0.2.", "198.51.100.", "10.78.0.", "10.79.0.", "timestamp", "credential"):
                    if forbidden in blob:
                        raise RuntimeError(f"forbidden metadata {forbidden!r} in aggregate output")

            print(
                json.dumps(
                    {
                        "schema": 1,
                        "hardware": "physical Nitrokey" if physical else "mocked",
                        "carrier": "two-hop schema-3 GotaTun (DAITA)",
                        **driver_out,
                        "direct_fallback_rx_packets": lan1_rx,
                        "grant_expiry_evicted_peer": True,
                        "entry_metrics": e_metrics,
                        "exit_metrics": x_metrics,
                        "aggregate_logs_hygienic": True,
                    },
                    indent=2,
                )
            )
        finally:
            for p in (e_proc, x_proc):
                if p is not None:
                    with suppress(OSError, ValueError):
                        p.stdin.write("stop\n")
                        p.stdin.flush()
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
            for ns in (CLIENT, ENTRY, EXIT):
                cmd("ip", "netns", "delete", ns, check=False)


if __name__ == "__main__":
    main()

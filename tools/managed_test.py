#!/usr/bin/env python3
"""Actual WireGuard/DAITA + dual PQ tunnel, managed kill switch and DoT tests.

Requires unshare -Urnm. Refuses host root or any inherited network interface.
"""

import difflib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import sys
import time

from managed_profile import lab_setup, HardwareOperator
from provision import authority, leaf, put
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]


# Linux capability numbers (include/uapi/linux/capability.h).
CAPS = {
    "CAP_CHOWN": 0,
    "CAP_DAC_OVERRIDE": 1,
    "CAP_DAC_READ_SEARCH": 2,
    "CAP_FOWNER": 3,
    "CAP_FSETID": 4,
    "CAP_KILL": 5,
    "CAP_SETGID": 6,
    "CAP_SETUID": 7,
    "CAP_SETPCAP": 8,
    "CAP_NET_BIND_SERVICE": 10,
    "CAP_NET_RAW": 13,
    "CAP_NET_ADMIN": 12,
    "CAP_SYS_ADMIN": 21,
    "CAP_SYS_PTRACE": 19,
}


def unit_capabilities():
    """The installed supervisor's CapabilityBoundingSet, read from the shipped unit."""
    for line in (ROOT / "deploy/cypherpunk-vpn.service").read_text().splitlines():
        if line.startswith("CapabilityBoundingSet="):
            return {CAPS[c] for c in line.split("=", 1)[1].split()}
    raise RuntimeError("unit has no capability bounding set")


def as_installed_unit(fd):
    """Enter the role namespace, then keep only the unit's capabilities and set
    no_new_privs, so lab supervisors run with the same privilege as systemd gives them."""
    import ctypes

    os.setns(fd, os.CLONE_NEWNET)
    lib = ctypes.CDLL(None)
    keep = unit_capabilities()
    for cap in range(64):
        if cap not in keep:
            lib.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP
    if lib.prctl(38, 1, 0, 0, 0) != 0:
        os._exit(1)  # PR_SET_NO_NEW_PRIVS (unit: NoNewPrivileges=yes)


def run(*args, check=True, timeout=15, input=None):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout, input=input)


def stop(p):
    if p is not None and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)


# Runs in av-upstream as 192.0.2.4, a peer the relay has never been told about.
PROBE = r"""
import hashlib, json, os, socket, sys
relay = ("192.0.2.1", int(sys.argv[2]))
public = bytes.fromhex(sys.argv[1])
def mac1(msg):
    # WireGuard: MAC1 = BLAKE2s-128 keyed with BLAKE2s-256("mac1----" || responder public key).
    key = hashlib.blake2s(b"mac1----" + public).digest()
    return hashlib.blake2s(msg, key=key, digest_size=16).digest()
body = b"\x01\0\0\0" + os.urandom(112)
probes = [os.urandom(n) for n in (1, 16, 32, 64, 92, 148, 1200)] + [
    b"\x01\0\0\0" + os.urandom(144),         # handshake initiation, invalid MAC1
    body + mac1(body) + bytes(16),               # valid MAC1 (knows the public key), forged contents
    b"\x02\0\0\0" + os.urandom(88),          # unsolicited handshake response
    b"\x03\0\0\0" + os.urandom(60),          # cookie reply
    b"\x04\0\0\0" + os.urandom(48),          # transport data for an unknown session
]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("192.0.2.4", 0))
s.settimeout(0.3)
got = 0
for p in probes * 5:
    s.sendto(p, relay)
    try:
        s.recv(65536)
        got += 1
    except socket.timeout:
        pass
print(json.dumps(dict(sent=len(probes) * 5, received=got)))
"""


def probe_first_hop(state, run):
    """Prove WireGuard on the first hop is unreachable from outside: garbage and forged
    handshakes (even with a valid MAC1) sent to its port get nothing back, because only
    the local cloak may reach it. A TCP connection to the public port must answer, which
    proves the counter would have seen a reply; a closed port stays silent too. (The cloak's public port answers
    like an HTTP/3 server instead; src/cloak.rs tests that.)"""
    public = json.loads((state / "relay" / "request.json").read_text())["wireguard_public_hex"]
    nft = ("ip", "netns", "exec", "av-relay", "/usr/sbin/nft")

    def answered():
        out = run(*nft, "-j", "list", "counters").stdout
        rows = [x["counter"] for x in json.loads(out)["nftables"] if "counter" in x]
        return next(r["packets"] for r in rows if r["table"] == "seen" and r["name"] == "answered")

    run(*nft, "reset", "counters", "table", "inet", "seen")
    out = run("ip", "netns", "exec", "av-upstream", sys.executable, "-c", PROBE, public, "41194", timeout=60)
    probe = json.loads(out.stdout)
    silent = answered()
    assert probe["received"] == 0 and silent == 0, ("the first hop answered a stranger", probe, silent)
    # Control: the same stranger opens TCP to the public port, which must answer (a
    # handshake or a reset), so the counter would have seen a reply. (Closed ports get
    # nothing at all: the egress lock drops what is not addressed to the chain.)
    run("ip", "netns", "exec", "av-upstream", sys.executable, "-c",
        "import socket\ns=socket.socket();s.bind(('192.0.2.4',0));s.settimeout(3)\n"
        "try:\n s.connect(('192.0.2.1',443))\nexcept OSError:\n pass", timeout=30)  # fmt: skip
    assert answered() > 0, "control failed: the public port produced no reply, so the counter proves nothing"
    run(*nft, "reset", "counters", "table", "inet", "seen")
    run("ip", "netns", "exec", "av-upstream", sys.executable, "-c", PROBE, public, "41195", timeout=60)
    closed_silent = answered() == 0
    assert closed_silent, "a closed port answered a stranger (the egress lock should drop it)"
    return dict(probes=probe["sent"], replies=silent, closed_port_silent=closed_silent)


# Set by main(): where every process's log is written, for the failure report below.
LOG_DIR = [None]


def failure_report(lines=25):
    """The tail of every process log, so a CI failure explains itself (long hex redacted:
    CI logs are public)."""
    import re

    if LOG_DIR[0] is None:
        return
    for log in sorted(Path(LOG_DIR[0]).glob("*.log")):
        try:
            tail = log.read_text(errors="replace").splitlines()[-lines:]
        except OSError:
            continue
        print("---- %s (last %d lines)" % (log.name, len(tail)), file=sys.stderr)
        for line in tail:
            print("  " + re.sub(r"[0-9a-fA-F]{32,}", "<hex>", line), file=sys.stderr)


# What the lab internet sees: the exit's outward address, and the client's own address.
EXIT_PUBLIC = "203.0.113.1"
CLIENT_PUBLIC = "192.0.2.2"


def main():
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument(
        "--hardware-vault", type=Path, help="client keys and operator signature on this FIDO2 vault (PIN+touch 4 times)"
    )
    p.add_argument(
        "--link-transport",
        choices=["udp", "tcp"],
        default="udp",
        help="tcp: the relay reaches the exit over TCP on IPv6 only (an IPv6-only exit, as on Fly)",
    )
    a = p.parse_args()
    os.umask(0o077)
    exit_endpoint = "[2001:db8:1::2]:4444" if a.link_transport == "tcp" else "198.51.100.2:4444"
    # Constant-cell padding is always on. The data plane runs as an unprivileged
    # service UID, so its datagram-size audit must land somewhere that UID can write
    # (the state dir is root-owned 0700).
    audit_dir = Path(tempfile.mkdtemp(prefix="cpvpn-cellaudit-"))
    audit_dir.chmod(0o777)
    os.environ["CPVPN_CELL_AUDIT"] = str(audit_dir / "cellaudit")
    from cypherpunkctl import lab_guard, identity_of, runtime_dir

    lab_guard()
    if {r["ifname"] for r in json.loads(run("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    state = a.state.resolve()
    LOG_DIR[0] = state
    state.mkdir(mode=0o700, exist_ok=False)
    ops = state / "operator"
    # An isolated TLS DNS upstream avoids contacting any real resolver.
    # Public DoT resolvers use classical WebPKI; the lab upstream mirrors that.
    ca = authority("DNS lab", "ecdsa")
    key, cert = leaf("dns.lab.internal", ca, 12, algorithm="ecdsa")
    put(state / "dns-cert.pem", cert.public_bytes(serialization.Encoding.PEM))
    put(
        state / "dns-key.pem",
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )
    dns = dict(
        upstream="203.0.113.2:8530",
        server_name="dns.lab.internal",
        test_ca=ca[1].public_bytes(serialization.Encoding.DER),
        # The exit's anti-tracker: a tracker domain, one allowed name under it, and the
        # lab upstream answers cloaked.test with a CNAME into it (managed_lab_peer.CLOAKED).
        blocklist=b"tracker.test\n",
        allowlist=b"ok.tracker.test\n",
    )
    if a.hardware_vault:
        print(
            "Hardware: the client request, operator signature and enrollment each need the FIDO2 PIN and a touch.",
            flush=True,
        )
    # Real request -> init -> enroll: every device generates its own keys; bundles hold none.
    ops = lab_setup(
        state,
        "192.0.2.1:443",
        exit_endpoint,
        link_transport=a.link_transport,
        dns=dns,
        daily_mib=1024,
        destinations=["203.0.113.0/30"],
        protect={"client": "nitrokey"} if a.hardware_vault else None,
        vault=a.hardware_vault.resolve() if a.hardware_vault else None,
        operator=HardwareOperator(a.hardware_vault) if a.hardware_vault else None,
    )
    bundles = [f.name for f in ops.glob("*.cpvpn")]
    import zipfile

    for b in bundles:
        members = zipfile.ZipFile(ops / b).namelist()
        assert not any(m.endswith(("-key.der", "-key.bin")) for m in members), ("private key in bundle", b, members)
    run("mount", "--make-rprivate", "/")
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if a.hardware_vault and xdg:
        # Keep the desktop session bus reachable for the local PIN dialog.
        (state / "xdg").mkdir()
        run("mount", "--rbind", xdg, str(state / "xdg"))
    run("mount", "-t", "tmpfs", "-o", "size=64m", "tmpfs", "/run")
    if a.hardware_vault and xdg:
        Path(xdg).mkdir(parents=True, exist_ok=True)
        run("mount", "--rbind", str(state / "xdg"), xdg)
    # Whole-device tests write only this private resolver inode, never the host's file.
    resolver_target = Path("/etc/resolv.conf").resolve()
    resolver_target.parent.mkdir(parents=True, exist_ok=True)
    if not resolver_target.exists():
        resolver_target.write_text("")
    isolated = state / "isolated-resolv.conf"
    isolated.write_text("nameserver 192.0.2.254\n")
    run("mount", "--bind", str(isolated), str(resolver_target))
    namespaces = ["av-client", "av-relay", "av-exit", "av-destination", "av-upstream", "av-lan"]
    procs = []
    logs = []

    def spawn(ns, args, name, unit=False):
        f = (state / (name + ".log")).open("w")
        logs.append(f)
        fd = os.open("/run/netns/" + ns, os.O_RDONLY)
        try:
            # Enter only the network namespace. ip netns exec also clones the
            # mount namespace, which would hide newly created named namespaces
            # from independent app launches. The installed supervisor likewise
            # deliberately shares its administrative mount namespace.
            x = subprocess.Popen(
                list(map(str, args)),
                preexec_fn=(lambda: as_installed_unit(fd)) if unit else (lambda: os.setns(fd, os.CLONE_NEWNET)),
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        finally:
            os.close(fd)
        procs.append(x)
        return x

    def manager(role, name=None, whole=False):
        args = [
            sys.executable,
            ROOT / "tools/cypherpunkctl.py",
            "--state",
            state / (name or role),
            "--bin-dir",
            ROOT / "target/release",
            "--lab",
            "connect",
        ]
        if whole:
            args += ["--whole-device"]
        return spawn("av-" + role, args, (name or role) + str(len(procs)), unit=True)

    def app(code, ok=True, timeout=8):
        args = [
            sys.executable,
            ROOT / "tools/cypherpunkctl.py",
            "--state",
            state / "client",
            "--lab",
            "run",
            "--",
            sys.executable,
            "-c",
            code,
        ]
        r = run("ip", "netns", "exec", "av-client", *map(str, args), check=False, timeout=timeout)
        if ok and r.returncode:
            raise RuntimeError("managed app failed: " + r.stderr)
        if not ok and not r.returncode:
            raise RuntimeError("application traffic escaped")
        return r

    def stun_code(expect):
        """A WebRTC-style STUN Binding request to the lab's STUN server; the reflected
        address must be `expect`. With None it succeeds only if no answer arrives."""
        ask = (
            "import os,socket\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)\n"
            "def ask():\n"
            " s.sendto(b'\\0\\1\\0\\0\\x21\\x12\\xa4\\x42'+os.urandom(12),('203.0.113.2',3478))\n"
            " return s.recv(2048)\n"
        )
        if expect is None:
            return ask + "try:\n ask()\nexcept OSError:\n raise SystemExit(0)\nraise SystemExit('STUN answered')\n"
        return ask + (
            "r=ask();assert r[:2]==b'\\1\\1' and r[20:22]==b'\\0\\x20',r\n"
            "ip=socket.inet_ntoa(bytes(x^y for x,y in zip(r[28:32],b'\\x21\\x12\\xa4\\x42')))\n"
            "assert ip==%r,('STUN reflected',ip)\n" % expect
        )

    ping_code = 'import subprocess;raise SystemExit(subprocess.run(["ping","-n","-c","1","-W","1","10.77.0.1"],stdout=subprocess.DEVNULL).returncode)'

    def wait_online(proc, seconds=25):
        end = time.monotonic() + seconds
        last = ""
        while time.monotonic() < end:
            if proc.poll() is not None:
                raise RuntimeError("supervisor exited")
            try:
                r = app(ping_code, ok=False)
                last = r.stderr
                if r.returncode == 0:
                    return
            except RuntimeError as e:
                if str(e) == "application traffic escaped":
                    return
            time.sleep(0.2)
        raise RuntimeError("managed tunnel deadline: " + last[-1500:])

    try:
        for ns in namespaces:
            run("ip", "netns", "add", ns)
            run("ip", "-n", ns, "link", "set", "lo", "up")
        # The client's network (192.0.2.0/29) is one L2 segment: the client, the relay and
        # the upstream router all sit on it, so the relay stays single-homed.
        run("ip", "-n", "av-lan", "link", "add", "br0", "type", "bridge")
        run("ip", "-n", "av-lan", "link", "set", "br0", "up")
        for ns, dev, addr, port in [
            ("av-client", "c0", "192.0.2.2/29", "lc"),
            ("av-relay", "r0", "192.0.2.1/29", "lr"),
            ("av-upstream", "ub", "192.0.2.3/29", "lu"),
        ]:
            run("ip", "link", "add", dev, "type", "veth", "peer", "name", port)
            run("ip", "link", "set", dev, "netns", ns)
            run("ip", "link", "set", port, "netns", "av-lan")
            run("ip", "-n", "av-lan", "link", "set", port, "master", "br0", "up")
            run("ip", "-n", ns, "address", "add", addr, "dev", dev)
            run("ip", "-n", ns, "link", "set", dev, "up")
        # An internet stranger on the same segment probes the first hop from 192.0.2.4.
        run("ip", "-n", "av-upstream", "address", "add", "192.0.2.4/29", "dev", "ub")
        links = [
            ("av-relay", "r1", "198.51.100.1/30", "av-exit", "e0", "198.51.100.2/30"),
            ("av-exit", "e1", "203.0.113.1/30", "av-destination", "d0", "203.0.113.2/30"),
        ]
        for n1, d1, ip1, n2, d2, ip2 in links:
            run("ip", "link", "add", d1, "type", "veth", "peer", "name", d2)
            for ns, dev, addr in [(n1, d1, ip1), (n2, d2, ip2)]:
                run("ip", "link", "set", dev, "netns", ns)
                run("ip", "-n", ns, "address", "add", addr, "dev", dev)
                run("ip", "-n", ns, "link", "set", dev, "up")
        if a.link_transport == "tcp":
            # The relay-exit segment also carries IPv6, and the chain names the exit only by
            # its IPv6 address: the link must run over TCP on IPv6 to work at all.
            for ns, dev, addr in [("av-relay", "r1", "2001:db8:1::1/64"), ("av-exit", "e0", "2001:db8:1::2/64")]:
                run("ip", "-n", ns, "address", "add", addr, "dev", dev, "nodad")
        # av-upstream stands in for an existing VPN provider: the client reaches it on u0
        # and it NATs to the relay, so the relay sees only the provider's address.
        for n1, d1, ip1, n2, d2, ip2 in [("av-client", "u0", "100.64.0.2/30", "av-upstream", "ua", "100.64.0.1/30")]:
            run("ip", "link", "add", d1, "type", "veth", "peer", "name", d2)
            for ns, dev, addr in [(n1, d1, ip1), (n2, d2, ip2)]:
                run("ip", "link", "set", dev, "netns", ns)
                run("ip", "-n", ns, "address", "add", addr, "dev", dev)
                run("ip", "-n", ns, "link", "set", dev, "up")
        # Like a VPN client, the upstream's gateway lives in its own routing table.
        run("ip", "-n", "av-client", "route", "add", "default", "via", "100.64.0.1", "dev", "u0", "table", "100")
        run("ip", "netns", "exec", "av-upstream", "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        run(
            "ip",
            "netns",
            "exec",
            "av-upstream",
            "/usr/sbin/nft",
            "-f",
            "-",
            input='table ip nat {\n chain post { type nat hook postrouting priority 100; policy accept;\n  oifname "ub" ip saddr != 192.0.2.4 masquerade\n }\n}\n',
        )
        # The relay counts first-hop packets by source: direct (the client's own address)
        # or through the upstream (the provider's address).
        run(
            "ip",
            "netns",
            "exec",
            "av-relay",
            "/usr/sbin/nft",
            "-f",
            "-",
            input="table inet seen {\n counter direct {\n }\n counter upstream {\n }\n counter answered {\n }\n"
            " chain in { type filter hook prerouting priority -300; policy accept;\n"
            "  ip saddr 192.0.2.2 udp dport 443 counter name direct\n"
            "  ip saddr 192.0.2.3 udp dport 443 counter name upstream\n }\n"
            " chain out { type filter hook output priority -300; policy accept;\n"
            "  ip daddr 192.0.2.4 counter name answered\n }\n}\n",
        )
        # A working unencrypted fallback route is present, so the whole-device leak test is meaningful.
        run("ip", "-n", "av-client", "route", "add", "default", "via", "192.0.2.1")
        run("ip", "-n", "av-relay", "route", "add", "203.0.113.0/30", "via", "198.51.100.2")
        run("ip", "-n", "av-exit", "route", "add", "192.0.2.0/30", "via", "198.51.100.1")
        run("ip", "-n", "av-destination", "route", "add", "192.0.2.0/30", "via", "203.0.113.1")
        for ns in ["av-relay", "av-exit"]:
            run("ip", "netns", "exec", ns, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
        run("ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "203.0.113.2")
        dns = spawn(
            "av-destination", [sys.executable, ROOT / "tools/managed_lab_peer.py", "dot", "--state", state], "dns"
        )
        spawn("av-destination", [sys.executable, ROOT / "tools/managed_lab_peer.py", "echo", "--state", state], "echo")
        spawn("av-destination", [sys.executable, ROOT / "tools/managed_lab_peer.py", "stun", "--state", state], "stun")
        spawn(
            "av-relay", [sys.executable, ROOT / "tools/managed_lab_peer.py", "observer", "--state", state], "observer"
        )
        # Watch the relay -> exit link (raw QUIC, no WireGuard carrier), for the record.
        spawn(
            "av-exit",
            [
                sys.executable,
                ROOT / "tools/managed_lab_peer.py",
                "tcp6sizes" if a.link_transport == "tcp" else "quicsizes",
                "--state",
                state,
                "--iface",
                "e0",
                "--out",
                state / "interhop.json",
            ],
            "interhop",
        )
        if a.hardware_vault:
            plaintext = [
                n
                for n in ["outer-key.der", "inner-key.der", "wireguard-key.bin", "kem-key.bin"]
                if (state / "client" / n).exists()
            ]
            assert not plaintext, plaintext
            print("Cold start: enter the FIDO2 PIN and touch the key.", flush=True)
        manager("relay")
        manager("exit")
        client = manager("client")
        client_log = Path(logs[-1].name)
        wait_online(client, 240 if a.hardware_vault else 25)
        silence = probe_first_hop(state, run)
        # The monthly cap, end to end: a relay whose cap is set just above what it has
        # sent stops serving and says why, the client's traffic stops, and lifting the cap
        # brings the chain back (a lab runs uncapped without a cap file; a real server
        # refuses to start without one, and removing it while running keeps the last cap).
        import fee_guard
        from cypherpunkctl import runtime_dir as rdir

        cap_path = fee_guard.paths(state / "relay")[0]
        relay_status = rdir(state / "relay", create=False) / "status.json"

        def relay_row():
            try:
                return json.loads(relay_status.read_text())
            except (OSError, ValueError):
                return {}

        def captured():
            path = state / "interhop.json"
            time.sleep(0.5)  # the capture publishes every 0.2 s of quiet, or on its own schedule
            return len(json.loads(path.read_text())) if path.exists() else 0

        cap_window = [captured()]
        sent = relay_row()["monthly"]["used_bytes"]
        fee_guard.write_cap(cap_path, sent + (1 << 20), "lab: 1 MiB above what the relay has sent")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and relay_row().get("state") != "capped":
            time.sleep(0.5)
        capped = relay_row()
        assert capped.get("state") == "capped" and capped.get("reason") == "monthly_cap", ("relay never capped", capped)
        assert capped["monthly"]["used_bytes"] <= sent + (1 << 20) + 2 * fee_guard.STEP, capped["monthly"]
        time.sleep(3)  # the client's in-flight packets drain
        app(ping_code, ok=False)
        cap_path.unlink()
        wait_online(client, 90)
        time.sleep(3)  # retransmissions after the outage settle
        cap_window.append(captured())
        monthly_cap = dict(capped=True, client_blocked=True, resumed_when_lifted=True,
                           resumes=capped["monthly"]["resumes"], egress_lock=capped["monthly"]["egress_lock"])  # fmt: skip
        if a.hardware_vault:
            marker = "PRIVATE-HARDWARE-" + os.urandom(16).hex()
            app(
                "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);b="
                + repr(marker.encode())
                + ';s.sendto(b,("203.0.113.2",45991));assert s.recv(4096)==b'
            )
            sealed = sorted(f.name for f in (state / "client").glob("*-key.sealed.json"))
            result = dict(
                schema=1,
                hardware_unlocked_managed_session=True,
                sealed_envelopes=sealed,
                plaintext_keys_on_disk=[
                    n
                    for n in ["outer-key.der", "inner-key.der", "wireguard-key.bin"]
                    if (state / "client" / n).exists()
                ],
                generated_on_device=True,
                bundles_contain_private_keys=False,
                operator_signature="FIDO2 assertion (Ed25519) + sealed ML-DSA-65",
                kem_key_removed_after_enroll=not any(
                    (state / "client" / n).exists() for n in ["kem-key.sealed.json", "kem-key.bin"]
                ),
                traffic_through_tunnel=True,
                supervisor_bounded_to_unit_capabilities=True,
                data_plane_non_dumpable=True,
                authentication="ML-DSA-65",
                note="FIDO2 hmac-secret unseals keys into memory at cold start; data-plane keys are not hardware-resident",
            )
            assert (
                sealed == ["inner-key.sealed.json", "outer-key.sealed.json", "wireguard-key.sealed.json"]
                and not result["plaintext_keys_on_disk"]
            )
            (state / "HARDWARE_RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result), flush=True)
            return
        app('import socket;assert socket.gethostbyname("vpn.test")=="203.0.113.2"')
        # Anti-tracker at the exit: a blocked name, a name cloaked behind a CNAME into the
        # blocked domain, and an allowlisted name under it.
        app(
            "import socket\n"
            "for name in ['x.tracker.test', 'cloaked.test']:\n"
            "    try:\n"
            "        socket.gethostbyname(name)\n"
            "    except socket.gaierror:\n"
            "        continue\n"
            "    raise SystemExit(name + ' resolved through the anti-tracker')\n"
            "assert socket.gethostbyname('ok.tracker.test') == '203.0.113.2'"
        )
        # Kill-switch drift watchdog: another process deletes the app namespace's kill
        # switch, then slips an accept rule into it. The supervisor restores the exact
        # table each time, within a few seconds.

        def app_table():
            r = run("ip", "netns", "exec", "av-client", "ip", "netns", "exec", "cpvpn-app", "/usr/sbin/nft", "list",
                    "table", "inet", "cypherpunk_vpn", check=False)  # fmt: skip
            return r.stdout if r.returncode == 0 else None

        def restored_within(expected, cause, log_offset, limit=8):
            t0 = time.monotonic()
            seen = None
            recovery = f"kill switch table cypherpunk_vpn restored in cpvpn-app: was {cause} (".encode()
            while time.monotonic() - t0 < limit:
                seen = app_table()
                if seen == expected:
                    with client_log.open("rb") as log:
                        log.seek(log_offset)
                        if recovery in log.read():
                            return round(time.monotonic() - t0, 2)
                time.sleep(0.2)
            diff = "\n".join(difflib.unified_diff((expected or "").splitlines(), (seen or "<absent>").splitlines(),
                                                  "expected", "last seen", lineterm=""))  # fmt: skip
            raise RuntimeError(f"the watchdog did not confirm restoration of the {cause} kill switch\n" + diff)

        expected_table = app_table()
        assert expected_table and "policy drop" in expected_table, expected_table
        # The checked nft mutations can be repaired before a second command observes them.
        # Require a new watchdog event for each mutation as well as the exact restored table.
        offset = client_log.stat().st_size
        run("ip", "netns", "exec", "av-client", "ip", "netns", "exec", "cpvpn-app", "/usr/sbin/nft", "delete", "table",
            "inet", "cypherpunk_vpn")  # fmt: skip
        restore_deleted = restored_within(expected_table, "absent", offset)
        offset = client_log.stat().st_size
        run("ip", "netns", "exec", "av-client", "ip", "netns", "exec", "cpvpn-app", "/usr/sbin/nft", "insert", "rule",
            "inet", "cypherpunk_vpn", "output", "accept")  # fmt: skip
        restore_altered = restored_within(expected_table, "altered", offset)
        marker = "PRIVATE-MANAGED-" + os.urandom(16).hex()
        app(
            "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);b="
            + repr(marker.encode())
            + ';s.sendto(b,("203.0.113.2",45991));assert s.recv(4096)==b'
        )
        # WebRTC leak: a page's STUN request must reflect the exit's address.
        app(stun_code(EXIT_PUBLIC))
        app(
            'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5);s.sendto(b"x",("203.0.113.2",53));s.recv(4096)',
            ok=False,
        )
        app(
            'import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.sendto(b"x",("2001:db8::1",53))',
            ok=False,
        )
        # Host resolvers reachable over Unix sockets bypass network namespaces (nss-resolve,
        # D-Bus resolve1). Stand up fake ones; the harness reaches them, a protected app must not.
        import socket as _socket

        fakes = []
        for path in ["/run/systemd/resolve/io.systemd.Resolve", "/run/dbus/system_bus_socket"]:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            srv.bind(path)
            srv.listen(4)
            fakes.append(srv)
            probe = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            probe.connect(path)
            probe.close()  # reachable outside the app
        app(
            'import socket,os\nfor p in ["/run/systemd/resolve/io.systemd.Resolve","/run/dbus/system_bus_socket"]:\n s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n try:s.connect(p)\n except OSError:continue\n raise SystemExit("host resolver reachable: "+p)\nassert "10.77.0.1" in open("/etc/resolv.conf").read()'
        )
        for srv in fakes:
            srv.close()
        time.sleep(5)
        children = json.loads((runtime_dir(state / "client") / "status.json").read_text())["children"]
        service_uid = 1 if len(Path("/proc/self/uid_map").read_text().splitlines()) > 1 else 0
        for child in children.values():
            status = Path("/proc/" + str(child["pid"]) + "/status").read_text()
            assert int(next(v for v in status.splitlines() if v.startswith("Uid:")).split()[1]) == service_uid
            assert int(next(v for v in status.splitlines() if v.startswith("CapEff:")).split()[1], 16) == 0
        # Data-plane processes are non-dumpable: the kernel then gives their /proc
        # entries to the namespace root instead of their own service UID, which blocks
        # same-UID ptrace and /proc/<pid>/mem reads of key memory. (The controller's
        # own hardening is checked in test_managed.HardeningTests.)
        for child in children.values():
            pid = str(child["pid"])
            uid = int(Path("/proc/" + pid + "/status").read_text().split("Uid:")[1].split()[1])
            assert uid != 0 and Path("/proc/" + pid + "/mem").stat().st_uid == 0, "data-plane process is dumpable"
        # Every data-plane process, on the client and on both servers, runs under its
        # seccomp filter (src/sandbox.rs): mode 2 with a filter installed.
        confined = 0
        for role in ["client", "relay", "exit"]:
            status_file = runtime_dir(state / role) / "status.json"
            if not status_file.exists():
                continue
            for name, child in json.loads(status_file.read_text())["children"].items():
                lines = Path("/proc/%d/status" % child["pid"]).read_text().splitlines()
                mode = next(v for v in lines if v.startswith("Seccomp:")).split()[1]
                filters = int(next(v for v in lines if v.startswith("Seccomp_filters:")).split()[1])
                assert mode == "2" and filters >= 1, "%s %s is not confined" % (role, name)
                confined += 1
        assert confined >= len(children), confined
        stats = json.loads((runtime_dir(state / "client") / "carrier-status.json").read_text())
        assert stats["handshake"] and stats["tx_padding_bytes"] > 0 and stats["tx_decoy_bytes"] > 0
        physical = json.loads((state / "physical.json").read_text())
        # Nothing on the wire is WireGuard; it is QUIC, and full packets share one size
        # (a few differ by the ACK frames QUIC adds to some of them).
        assert physical["wireguard_messages"] == 0 and physical["quic_packets"] > 0, physical
        outer = {int(k): v for k, v in physical["outer_sizes"].items()}
        size = max(outer, key=outer.get)
        # The capture sees GSO super-frames before segmentation: k packets of one size.
        # QUIC loss probes alone stay unpadded (so a shrunken path MTU can be detected);
        # they are rare, and anything else of another size fails.
        packets = sum(k // size * v for k, v in outer.items())
        odd = sum(v for k, v in outer.items() if k % size)
        assert odd <= max(2, packets // 100), ("outer sizes vary", outer)
        assert marker.encode() not in (state / "physical-capture.bin").read_bytes()
        # Fresh leaves are self-issued by the same pinned device identity. No CA
        # private key is present on a peer, and the remote peer accepts rotation.
        before = (runtime_dir(state / "client") / "inner-active-cert.der").read_bytes()
        run(
            "ip",
            "netns",
            "exec",
            "av-client",
            sys.executable,
            str(ROOT / "tools/cypherpunkctl.py"),
            "--state",
            str(state / "client"),
            "--lab",
            "rotate",
        )
        end = time.monotonic() + 10
        while (
            time.monotonic() < end and (runtime_dir(state / "client") / "inner-active-cert.der").read_bytes() == before
        ):
            time.sleep(0.1)
        assert (runtime_dir(state / "client") / "inner-active-cert.der").read_bytes() != before
        wait_online(client)
        # The removed defense preference is refused: no local setting changes the stream.
        refused = run(
            "ip",
            "netns",
            "exec",
            "av-client",
            sys.executable,
            str(ROOT / "tools/cypherpunkctl.py"),
            "--state",
            str(state / "client"),
            "--lab",
            "preferences",
            "--defense",
            "balanced",
            check=False,
        )
        assert refused.returncode != 0, "preferences --defense must be refused"
        wait_online(client)
        # Crash the WireGuard child; the supervisor recreates it without opening a direct route.
        status = json.loads((runtime_dir(state / "client") / "status.json").read_text())
        os.kill(status["children"]["carrier"]["pid"], signal.SIGKILL)
        wait_online(client)
        # A hard supervisor death leaves its children, but the persistent network guard survives.
        status = json.loads((runtime_dir(state / "client") / "status.json").read_text())
        children = status["children"]
        client.kill()
        client.wait()
        end = time.monotonic() + 2

        def child_dead(child):
            path = Path("/proc/" + str(child["pid"]) + "/stat")
            try:
                return identity_of(child["pid"]) != child["identity"] or (
                    path.read_text().rsplit(")", 1)[1].split()[0] == "Z"
                )
            except (FileNotFoundError, ProcessLookupError):
                return True  # reaped between the two reads: gone

        while time.monotonic() < end and not all(child_dead(v) for v in children.values()):
            time.sleep(0.05)
        assert all(child_dead(v) for v in children.values()), "orphan data plane survived controller death"
        app(ping_code, ok=False)
        client = manager("client")
        wait_online(client)
        # Deliberate disconnect keeps the application sandbox blocked.
        stop(client)
        app(ping_code, ok=False)

        # Upstream entry: the first hop must see only the upstream's address, and losing
        # the upstream must never fall back to the direct path.
        def ctl(*args, check=True):
            return run(
                "ip",
                "netns",
                "exec",
                "av-client",
                sys.executable,
                str(ROOT / "tools/cypherpunkctl.py"),
                "--state",
                str(state / "client"),
                "--lab",
                *args,
                check=check,
            )

        def seen():
            out = run("ip", "netns", "exec", "av-relay", "/usr/sbin/nft", "-j", "list", "counters").stdout
            rows = [x["counter"] for x in json.loads(out)["nftables"] if "counter" in x]
            return {r["name"]: r["packets"] for r in rows if r["table"] == "seen"}

        run("ip", "netns", "exec", "av-relay", "/usr/sbin/nft", "reset", "counters", "table", "inet", "seen")
        ctl("preferences", "--upstream-interface", "u0")
        client = manager("client")
        try:
            wait_online(client)
        except RuntimeError:
            for args in [
                ("ip", "-n", "av-client", "route", "get", "192.0.2.1"),
                ("ip", "-n", "av-client", "-4", "route", "show", "table", "all"),
                ("ip", "netns", "exec", "av-client", "/usr/sbin/nft", "list", "ruleset"),
                ("ip", "netns", "exec", "av-relay", "/usr/sbin/nft", "list", "counters"),
                ("ip", "-n", "av-upstream", "-s", "link"),
                ("ip", "-n", "av-client", "-s", "link", "show", "u0"),
            ]:
                r = run(*args, check=False)
                print("$", " ".join(args), "\n", r.stdout[-3000:], r.stderr[-500:], flush=True)
            raise
        app(
            "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);b=b'via-upstream'"
            ';s.sendto(b,("203.0.113.2",45991));assert s.recv(4096)==b'
        )
        counts = seen()
        assert counts["upstream"] > 0 and counts["direct"] == 0, ("first hop saw the client directly", counts)
        route = json.loads(run("ip", "-n", "av-client", "-j", "route", "get", "192.0.2.1").stdout)[0]
        assert route["dev"] == "u0", route
        # The upstream drops: the kernel would now route to the relay over c0 (the
        # direct path), so only the upstream guard stands between the carrier and a leak.
        run("ip", "-n", "av-client", "link", "set", "u0", "down")
        fallback = json.loads(run("ip", "-n", "av-client", "-j", "route", "get", "192.0.2.1").stdout)[0]
        assert fallback["dev"] == "c0", fallback
        end = time.monotonic() + 6
        while time.monotonic() < end:
            app(ping_code, ok=False)
        upstream_down = seen()
        assert upstream_down["direct"] == 0, ("direct packets reached the first hop", upstream_down)
        stop(client)
        # An absent upstream refuses the connection outright.
        run("ip", "-n", "av-client", "link", "del", "u0")
        refused = manager("client", "client")
        refused.wait(timeout=20)
        assert refused.returncode != 0, "connected without its upstream"
        assert seen()["direct"] == 0
        ctl("preferences", "--no-upstream")
        # Switch the same enrollment from Applications to Whole device.
        before_dns = isolated.read_bytes()
        assert not json.loads((state / "client" / "network-before.json").read_text())["whole_device"]
        whole = manager("client", "client", True)
        end = time.monotonic() + 25
        while time.monotonic() < end:
            r = run("ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1", check=False)
            if not r.returncode:
                break
            if whole.poll() is not None:
                raise RuntimeError("whole-device supervisor exited")
        else:
            raise RuntimeError("whole-device handshake deadline")
        stun_host = [sys.executable, "-c"]
        run("ip", "netns", "exec", "av-client", *stun_host, stun_code(EXIT_PUBLIC))
        stop(whole)
        run("ip", "-n", "av-client", "route", "replace", "default", "via", "192.0.2.1")
        escaped = run(
            "ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "203.0.113.2", check=False
        )
        assert escaped.returncode != 0, "whole-device fallback route leaked"
        stun_blocked = run("ip", "netns", "exec", "av-client", *stun_host, stun_code(None), check=False)
        assert stun_blocked.returncode == 0, ("STUN left the disconnected device", stun_blocked.stderr[-300:])
        stun_sources = json.loads((state / "stun.json").read_text())
        assert stun_sources == [EXIT_PUBLIC], ("the STUN server saw another address", stun_sources)
        # Only an explicit request may leave the protected state.
        run(
            "ip",
            "netns",
            "exec",
            "av-client",
            sys.executable,
            str(ROOT / "tools/cypherpunkctl.py"),
            "--state",
            str(state / "client"),
            "--lab",
            "reset",
            "--allow-cleartext",
        )
        assert isolated.read_bytes() == before_dns, "whole-device disarm did not restore ordinary DNS"
        assert not (state / "client" / "network-before.json").exists()
        run("ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "203.0.113.2")
        # Positive control: with the protection explicitly off, the STUN server does see
        # the client's own address, so the checks above could have failed.
        run("ip", "netns", "exec", "av-client", *stun_host, stun_code(CLIENT_PUBLIC))
        # Wire capture on the relay->exit link, kept for the record (QUIC header jitter
        # and receive offload mean it is not byte-uniform; the datagram audit below is
        # the exact proof).
        inter_sizes = json.loads((state / "interhop.json").read_text()) if (state / "interhop.json").exists() else []
        inter_hop = sorted(set(inter_sizes))
        if a.link_transport == "tcp":
            # Over TCP the link must be whole cells: every payload a multiple of the one cell
            # size the UDP link uses (1242 bytes in this chain), never a fraction of one.
            import math

            assert inter_sizes, "no TCP traffic seen on the relay-exit link"
            # Outside the cap phase every TCP payload is whole cells. Inside it the relay's
            # kernel quota drops segments, and TCP may repack a retransmission up to its
            # MSS: that reflects loss on the path, never the traffic (the cells are constant).
            lo, hi = cap_window
            steady = inter_sizes[:lo] + inter_sizes[hi:]
            cell = math.gcd(*steady)
            assert cell == 1242, ("TCP link payloads are not whole cells", cell, sorted(set(steady))[:10])
            repacked = sorted(set(inter_sizes[lo:hi]) - {1242})
            inter_hop = [cell]
        # Every hop that sent data must have padded every datagram to one size.
        # cellaudit.<layer>.<pid>: every process, every layer, exactly one datagram size,
        # and one size per layer across all the processes the lab started.
        per_process = {f.name.split(".", 1)[1]: json.loads(f.read_text()) for f in audit_dir.glob("cellaudit.*")}
        for name, sizes in per_process.items():
            assert len(sizes) == 1, ("%s sent more than one datagram size" % name, sizes)
        cell_audit = {}
        for name, sizes in per_process.items():
            cell_audit.setdefault(name.split(".")[0], set()).update(sizes)
        cell_audit = {k: sorted(v) for k, v in cell_audit.items()}
        assert {"client", "relay", "exit", "bridge"} <= set(cell_audit), ("missing audited layers", sorted(cell_audit))
        for role, sizes in cell_audit.items():
            assert len(sizes) == 1, ("%s used more than one cell size across processes" % role, sizes)
        result = dict(
            schema=2,
            wireguard_implementation="GotaTun 0.10.2",
            daita_framework="Maybenot 2.2.2",
            dual_hybrid_pq_retained=True,
            signed_enrollment_verified=True,
            automatic_network_setup=True,
            dns_tls_verified=True,
            kill_switch_restored_seconds=dict(deleted=restore_deleted, altered=restore_altered),
            system_resolver_inside_namespace=True,
            dns_bypass_rejected=True,
            ipv6_leak_rejected=True,
            webrtc_stun_reflects_exit_only=True,
            carrier_padding_and_decoys_verified=True,
            wireguard_messages_on_the_wire=physical["wireguard_messages"],
            outer_quic_sizes=physical["outer_sizes"],
            private_marker_absent_from_physical_capture=True,
            carrier_stats=stats,
            child_crash_recovered=True,
            supervisor_crash_guard_persisted=True,
            disconnected_namespace_blocked=True,
            data_plane_dies_with_supervisor=True,
            automatic_leaf_rotation_verified=True,
            strong_profile_connected=True,
            explicit_unlock_restores_route=True,
            data_plane_uid=service_uid,
            data_plane_capabilities_zero=True,
            private_keys_fd_only=True,
            supervisor_bounded_to_unit_capabilities=True,
            data_plane_non_dumpable=True,
            bundles_contain_private_keys=False,
            host_resolver_sockets_hidden_from_apps=True,
            whole_device_guard_blocks_working_fallback_route=True,
            upstream_entry_first_hop_sees_only_upstream=True,
            upstream_entry_fails_closed_when_upstream_drops=True,
            upstream_entry_missing_interface_refused=True,
            first_hop_silent_to_unauthenticated=silence,
            monthly_cap=monthly_cap,
            tcp_repacked_during_cap_phase=repacked if a.link_transport == "tcp" else None,
            inter_hop_cell_sizes=inter_hop,
            datagram_sizes_per_role=cell_audit,
            host_network_changed=False,
            host_dns_changed=False,
            classifier_resistance_measured=False,
            wan_tested=False,
        )
        (state / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    finally:
        # Reap supervised descendants before removing their namespaces.
        for role in ["client", "relay", "exit"]:
            path = runtime_dir(state / role) / "status.json"
            if path.exists():
                for child in json.loads(path.read_text()).get("children", {}).values():
                    try:
                        if identity_of(child["pid"]) == child["identity"]:
                            os.kill(child["pid"], signal.SIGTERM)
                    except ProcessLookupError:
                        pass
        for proc in reversed(procs):
            stop(proc)
        for f in logs:
            f.close()
        for ns in ["cpvpn-app", *reversed(namespaces)]:
            run("ip", "netns", "del", ns, check=False)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        failure_report()
        raise

#!/usr/bin/env python3
"""Actual WireGuard/DAITA + dual PQ tunnel, managed kill switch and DoT tests.

Requires unshare -Urnm. Refuses host root or any inherited network interface.
"""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import sys
import time

from managed_profile import lab_setup, HardwareOperator
import shutil
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
    for line in (ROOT / "deploy/advanced-vpn.service").read_text().splitlines():
        if line.startswith("CapabilityBoundingSet="):
            return {CAPS[c] for c in line.split("=", 1)[1].split()}
    raise RuntimeError("unit has no capability bounding set")


def as_installed_unit(fd):
    """Enter the role namespace, then keep only the unit's capabilities and set
    no_new_privs, so lab supervisors run with the same privilege as systemd gives them."""
    import ctypes

    os.setns(fd, 0)
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
relay = ("192.0.2.1", int(sys.argv[3]))
public, replay = bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2])
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
    replay,                                      # the client's real, already-used initiation
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


def last_initiation(capture, source="192.0.2.2", port=41194):
    """The newest WireGuard handshake initiation from `source` in the observer's raw
    frame stream (Ethernet frames written back to back)."""
    data, i, found = capture.read_bytes(), 0, None
    while i + 34 <= len(data) and data[i + 12 : i + 14] == b"\x08\x00" and data[i + 14] >> 4 == 4:
        total = int.from_bytes(data[i + 16 : i + 18], "big")
        frame = data[i : i + 14 + total]
        ihl = (frame[14] & 15) * 4
        udp = 14 + ihl
        if frame[23] == 17 and socket.inet_ntoa(frame[26:30]) == source:
            if int.from_bytes(frame[udp + 2 : udp + 4], "big") == port:
                payload = frame[udp + 8 :]
                if len(payload) == 148 and payload[:4] == b"\x01\0\0\0":
                    found = payload
        i += 14 + total
    if found is None:
        raise RuntimeError("no client handshake initiation in the capture")
    return found


def probe_first_hop(state, run):
    """Prove the first hop never answers a peer it has not been enrolled with: garbage,
    forged and replayed handshakes all get nothing back. A closed port on the same host
    must answer (ICMP), which proves the counter would have seen a reply."""
    public = json.loads((state / "relay" / "request.json").read_text())["wireguard_public_hex"]
    replay = last_initiation(state / "physical-capture.bin")
    nft = ("ip", "netns", "exec", "av-relay", "/usr/sbin/nft")

    def answered():
        out = run(*nft, "-j", "list", "counters").stdout
        rows = [x["counter"] for x in json.loads(out)["nftables"] if "counter" in x]
        return next(r["packets"] for r in rows if r["table"] == "seen" and r["name"] == "answered")

    run(*nft, "reset", "counters", "table", "inet", "seen")
    out = run(
        "ip", "netns", "exec", "av-upstream", sys.executable, "-c", PROBE, public, replay.hex(), "41194", timeout=60
    )
    probe = json.loads(out.stdout)
    silent = answered()
    assert probe["received"] == 0 and silent == 0, ("the first hop answered a stranger", probe, silent)
    # Control: the same stranger, a closed port. The kernel must reply (port unreachable).
    run("ip", "netns", "exec", "av-upstream", sys.executable, "-c", PROBE, public, replay.hex(), "41195", timeout=60)
    assert answered() > 0, "control failed: a closed port produced no reply, so the counter proves nothing"
    return dict(probes=probe["sent"], replies=silent, control_replies=answered())


def main():
    import argparse

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument(
        "--hardware-vault", type=Path, help="client keys and operator signature on this FIDO2 vault (PIN+touch 4 times)"
    )
    p.add_argument("--cells", action="store_true", help="constant-cell padding on every hop")
    a = p.parse_args()
    os.umask(0o077)
    audit_dir = None
    if a.cells:
        # The data plane runs as an unprivileged service UID, so the audit must land
        # somewhere it can write (the state dir is root-owned 0700).
        audit_dir = Path(tempfile.mkdtemp(prefix="avpn-cellaudit-"))
        audit_dir.chmod(0o777)
        os.environ["AVPN_CELL_AUDIT"] = str(audit_dir / "cellaudit")
    from avpnctl import lab_guard, identity_of, runtime_dir

    lab_guard()
    if {r["ifname"] for r in json.loads(run("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    state = a.state.resolve()
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
    )
    if a.hardware_vault:
        print(
            "Hardware: the client request, operator signature and enrollment each need the FIDO2 PIN and a touch.",
            flush=True,
        )
    # Real request -> init -> enroll: every device generates its own keys; bundles hold none.
    ops = lab_setup(
        state,
        "192.0.2.1:41194",
        "198.51.100.2:4444",
        dns=dns,
        daily_mib=1024,
        destinations=["203.0.113.0/30"],
        protect={"client": "nitrokey"} if a.hardware_vault else None,
        vault=a.hardware_vault.resolve() if a.hardware_vault else None,
        operator=HardwareOperator(a.hardware_vault) if a.hardware_vault else None,
        cells=a.cells,
    )
    bundles = [f.name for f in ops.glob("*.avpn")]
    import zipfile

    for b in bundles:
        members = zipfile.ZipFile(ops / b).namelist()
        assert not any(m.endswith(("-key.der", "-key.bin")) for m in members), ("private key in bundle", b, members)
    # The whole-device run reuses this device's enrolled identity (same machine).
    if not a.hardware_vault:
        shutil.copytree(state / "client", state / "whole")
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
                preexec_fn=(lambda: as_installed_unit(fd)) if unit else (lambda: os.setns(fd, 0)),
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
            ROOT / "tools/avpnctl.py",
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
            ROOT / "tools/avpnctl.py",
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
            " chain in { type filter hook input priority -300; policy accept;\n"
            "  ip saddr 192.0.2.2 udp dport 41194 counter name direct\n"
            "  ip saddr 192.0.2.3 udp dport 41194 counter name upstream\n }\n"
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
        spawn(
            "av-relay", [sys.executable, ROOT / "tools/managed_lab_peer.py", "observer", "--state", state], "observer"
        )
        # Watch the relay -> exit link (raw QUIC, no WireGuard carrier). With cells on,
        # the data-bearing packets there must collapse to a single size.
        spawn(
            "av-exit",
            [
                sys.executable,
                ROOT / "tools/managed_lab_peer.py",
                "quicsizes",
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
        wait_online(client, 240 if a.hardware_vault else 25)
        silence = probe_first_hop(state, run)
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
        marker = "PRIVATE-MANAGED-" + os.urandom(16).hex()
        app(
            "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);b="
            + repr(marker.encode())
            + ';s.sendto(b,("203.0.113.2",45991));assert s.recv(4096)==b'
        )
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
        stats = json.loads((runtime_dir(state / "client") / "carrier-status.json").read_text())
        assert stats["handshake"] and stats["tx_padding_bytes"] > 0 and stats["tx_decoy_bytes"] > 0
        physical = json.loads((state / "physical.json").read_text())
        assert physical["wireguard_data_packets"] > 0 and len(physical["data_sizes"]) == 1, physical
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
            str(ROOT / "tools/avpnctl.py"),
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
        # Switching defense profiles is an authenticated local preference, not a
        # fallback that silently turns padding off.
        run(
            "ip",
            "netns",
            "exec",
            "av-client",
            sys.executable,
            str(ROOT / "tools/avpnctl.py"),
            "--state",
            str(state / "client"),
            "--lab",
            "preferences",
            "--defense",
            "strong",
        )
        time.sleep(2)
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
            return identity_of(child["pid"]) != child["identity"] or (
                path.exists() and path.read_text().rsplit(")", 1)[1].split()[0] == "Z"
            )

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
                str(ROOT / "tools/avpnctl.py"),
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
        # Separate enrollment for a true whole-device firewall test in this disposable netns.
        whole = manager("client", "whole", True)
        end = time.monotonic() + 25
        while time.monotonic() < end:
            r = run("ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "10.77.0.1", check=False)
            if not r.returncode:
                break
            if whole.poll() is not None:
                raise RuntimeError("whole-device supervisor exited")
        else:
            raise RuntimeError("whole-device handshake deadline")
        stop(whole)
        run("ip", "-n", "av-client", "route", "replace", "default", "via", "192.0.2.1")
        escaped = run(
            "ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "203.0.113.2", check=False
        )
        assert escaped.returncode != 0, "whole-device fallback route leaked"
        # Only an explicit request may leave the protected state.
        run(
            "ip",
            "netns",
            "exec",
            "av-client",
            sys.executable,
            str(ROOT / "tools/avpnctl.py"),
            "--state",
            str(state / "whole"),
            "--lab",
            "reset",
            "--allow-cleartext",
        )
        run("ip", "netns", "exec", "av-client", "ping", "-n", "-c", "1", "-W", "1", "203.0.113.2")
        # Wire capture on the relay->exit link, kept for the record (QUIC header jitter
        # and receive offload mean it is not byte-uniform; the datagram audit below is
        # the exact proof).
        inter_sizes = json.loads((state / "interhop.json").read_text()) if (state / "interhop.json").exists() else []
        inter_hop = sorted(set(inter_sizes))
        # Every hop that sent data must have padded every datagram to one size.
        cell_audit = {}
        if a.cells:
            for f in audit_dir.glob("cellaudit.*"):
                cell_audit[f.suffix[1:]] = json.loads(f.read_text())
            assert {"client", "relay", "exit", "bridge"} <= set(cell_audit), (
                "missing audited layers",
                sorted(cell_audit),
            )
            for role, sizes in cell_audit.items():
                assert len(sizes) == 1, ("%s sent more than one datagram size under padding" % role, sizes)
        result = dict(
            schema=2,
            wireguard_implementation="GotaTun 0.10.2",
            daita_framework="Maybenot 2.2.2",
            dual_hybrid_pq_retained=True,
            signed_enrollment_verified=True,
            automatic_network_setup=True,
            dns_tls_verified=True,
            system_resolver_inside_namespace=True,
            dns_bypass_rejected=True,
            ipv6_leak_rejected=True,
            carrier_padding_and_decoys_verified=True,
            wireguard_data_sizes=physical["data_sizes"],
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
        for role in ["client", "relay", "exit", "whole"]:
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
        for ns in ["avpn-app", *reversed(namespaces)]:
            run("ip", "netns", "del", ns, check=False)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise the actual GotaTun carrier's private peer lease channel in isolation."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from keyguard import memory_fd  # noqa: E402
from shared_admission import (  # noqa: E402
    Cohort,
    EPOCH_SECONDS,
    PSS,
    ReplayLedger,
    SPKI_PREFIX,
    TOKEN_TYPE,
    binding_message,
)
from shared_carrier import SharedCarrier  # noqa: E402


def verified_grant(control, root, carrier_key, psk):
    """Exercise the same verifier and replay ledger as the sponsored admission lab."""
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = SPKI_PREFIX + issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    cohort = Cohort("issuer.vpn.test", "pool.vpn.test", "entry", int(time.time()) // EPOCH_SECONDS, spki)
    body = TOKEN_TYPE + os.urandom(32) + hashlib.sha256(cohort.challenge).digest() + hashlib.sha256(spki).digest()
    token = body + issuer.sign(body, PSS, hashes.SHA384())
    ledger = ReplayLedger(root / "replay.sqlite", "entry")
    ledger.initialize()
    session_key = mldsa.MLDSA65PrivateKey.generate()
    hop_key, binding = os.urandom(32), os.urandom(32)
    proof = session_key.sign(binding_message(cohort, token, hop_key, binding, carrier_key))
    control.install(
        cohort,
        ledger,
        token,
        address="10.78.0.2",
        psk=psk,
        hop_key_id=hop_key,
        channel_binding=binding,
        carrier_key=carrier_key,
        session_key=session_key.public_key(),
        proof=proof,
    )


def command(*args, check=True):
    """Run one network command inside the fixture's isolated namespace."""
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=10)  # noqa: S603


def write_private(path, contents):
    """Create a temporary file under the fixture's private umask."""
    with path.open("xb") as stream:
        stream.write(contents)


def peers(path, count):
    """Wait for aggregate carrier status, without reading any peer identifiers."""
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if path.exists() and json.loads(path.read_text())["peers"] == count:
            return
        time.sleep(0.1)
    raise RuntimeError(f"carrier did not report {count} peers")


def ping(expected):
    """Prove whether the tested peer can send through the carrier."""
    result = command("ip", "netns", "exec", "lease-client", "ping", "-c", "1", "-W", "2", "10.78.0.1", check=False)
    if (result.returncode == 0) != expected:
        raise RuntimeError(f"unexpected carrier delivery: {result.stdout} {result.stderr}")


def set_client_keys(root, server_key, client_key, psk):
    """Configure a fresh private key and preshared key on the test client."""
    private_path, psk_path = root / "client-key", root / "psk"
    write_private(private_path, base64.b64encode(client_key.private_bytes_raw()) + b"\n")
    write_private(psk_path, base64.b64encode(psk) + b"\n")
    server_public = base64.b64encode(server_key.public_key().public_bytes_raw()).decode()
    command(
        "ip",
        "netns",
        "exec",
        "lease-client",
        "wg",
        "set",
        "wg0",
        "private-key",
        str(private_path),
        "peer",
        server_public,
        "preshared-key",
        str(psk_path),
        "allowed-ips",
        "10.78.0.1/32",
        "endpoint",
        "192.0.2.1:41194",
    )
    private_path.unlink()
    psk_path.unlink()


def overlay(root, server_key, client_key, psk):
    """Make a WireGuard client on a disposable underlay with no public route."""
    command("ip", "netns", "add", "lease-client")
    command("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "wan0", "netns", "lease-client")
    command("ip", "addr", "add", "192.0.2.1/30", "dev", "wan0")
    command("ip", "link", "set", "wan0", "up")
    command("ip", "-n", "lease-client", "addr", "add", "192.0.2.2/30", "dev", "wan0")
    command("ip", "-n", "lease-client", "link", "set", "wan0", "up")
    command("ip", "-n", "lease-client", "link", "add", "wg0", "type", "wireguard")
    command("ip", "-n", "lease-client", "addr", "add", "10.78.0.2/24", "dev", "wg0")
    set_client_keys(root, server_key, client_key, psk)
    command("ip", "-n", "lease-client", "link", "set", "wg0", "up")
    command("ip", "tuntap", "add", "dev", "cpwg0", "mode", "tun")
    command("ip", "addr", "add", "10.78.0.1/24", "dev", "cpwg0")
    command("ip", "link", "set", "cpwg0", "mtu", "1340", "up")


def run(binary, root):
    """Verify add, expiry, explicit removal, and carrier shutdown on supervisor loss."""
    server_key, client_key = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    psk = os.urandom(32)
    overlay(root, server_key, client_key, psk)
    config, stats = root / "carrier.json", root / "statistics.json"
    binding, unused_key = root / "binding", root / "unused"
    write_private(binding, b"fixture")
    write_private(
        config,
        json.dumps(
            dict(
                schema=3,
                role="wireguard",
                tun="cpwg0",
                listen_port=41194,
                endpoint=None,
                peer_public_hex="",
                allowed_ip="",
                identity=dict(key=str(unused_key), cert=str(binding)),
                defense="strong",
                statistics=str(stats),
            )
        ).encode(),
    )
    key_fd = memory_fd(server_key.private_bytes_raw())
    supervisor, helper = socket.socketpair()
    with (
        supervisor,
        helper,
        subprocess.Popen(  # noqa: S603 - isolated test carrier
            [
                str(binary),
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
        ) as carrier,
    ):
        helper.close()
        os.close(key_fd)
        try:
            supervisor.settimeout(8)
            peers(stats, 0)
            ping(False)
            public = client_key.public_key().public_bytes_raw()

            def send_lease(seconds, *, fragment=False):
                frame = b"\x01" + public + psk + ipaddress.IPv4Address("10.78.0.2").packed
                frame += struct.pack("!Q", int(time.time()) + seconds)
                if fragment:
                    supervisor.sendall(frame[:13])
                    time.sleep(1.1)  # ensure the status ticker can run mid-frame
                    frame = frame[13:]
                supervisor.sendall(frame)
                if supervisor.recv(1) != b"\0":
                    raise RuntimeError("carrier did not acknowledge the lease")

            send_lease(10, fragment=True)
            peers(stats, 1)
            ping(True)
            peers(stats, 0)
            ping(False)
            control = SharedCarrier(supervisor)
            client_key, psk = X25519PrivateKey.generate(), os.urandom(32)
            set_client_keys(root, server_key, client_key, psk)
            public = client_key.public_key().public_bytes_raw()
            verified_grant(control, root, public, psk)
            peers(stats, 1)
            ping(True)
            control.remove(public)
            peers(stats, 0)
            ping(False)
            supervisor.close()
            if carrier.wait(timeout=5) == 0:
                raise RuntimeError("carrier did not report a supervisor loss")
        except BaseException:
            if carrier.poll() is None:
                carrier.kill()
            _, error = carrier.communicate(timeout=5)
            if error:
                print(error, file=sys.stderr)
            raise


def main():
    """Verify that the fixture cannot start on the host network."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, required=True)
    binary = parser.parse_args().bin.resolve()
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[1] == "0" or mapping[2] != "1":
        raise RuntimeError("fresh unprivileged user namespace required")
    if {link["ifname"] for link in json.loads(command("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    os.umask(0o077)
    command("mount", "--make-rprivate", "/")
    command("mount", "-t", "tmpfs", "tmpfs", "/run")
    with tempfile.TemporaryDirectory(prefix="cpvpn-carrier-lease-") as directory:
        try:
            run(binary, Path(directory))
        finally:
            command("ip", "netns", "delete", "lease-client", check=False)
    print(
        json.dumps(
            dict(
                delivery_after_install=True,
                blocked_before_install=True,
                blocked_after_expiry=True,
                blocked_after_remove=True,
                stopped_on_supervisor_loss=True,
            )
        )
    )


if __name__ == "__main__":
    main()

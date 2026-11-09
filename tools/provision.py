#!/usr/bin/env python3
"""Create two independent offline authorities and four short-lived identities.

Creates a NEW directory only. No cloud, routing, hardware or production changes.
Python cryptography is used for certificates, not for the transport protocol.
"""

import argparse
import datetime as dt
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError as e:  # pragma: no cover - environment guard
    raise SystemExit(
        "ML-DSA requires the hash-locked environment (tools/hardware-requirements.txt, cryptography 49)"
    ) from e
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# Per-session forwarding bound at every hop (the config maximum). Measured: the old
# 2 MB/s / 2000 pkt/s default capped the tunnel at ~10 Mbit/s; this allows ~230 Mbit/s
# in the namespace benchmark. Only the operator's own authenticated peers can use it.
RATE_BYTES = 100_000_000
RATE_PACKETS = 100_000


def put(path, data):
    """Create `path` exclusively with mode 0600 and write `data`."""
    with path.open("xb") as f:
        os.chmod(path, 0o600)
        f.write(data)


# Device and authority identities are ML-DSA-65 (FIPS 204). 'ecdsa' exists only so
# tests can prove that a fully consistent classical deployment is refused.
ALGORITHMS = ("ml-dsa-65", "ecdsa")


def new_key(algorithm):
    """A new signing key: ML-DSA-65, or ECDSA P-256 for the refusal tests."""
    if algorithm == "ml-dsa-65":
        return mldsa.MLDSA65PrivateKey.generate()
    if algorithm == "ecdsa":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError("unknown signature algorithm")


def digest_for(key):
    """The hash to pass when signing with `key` (None for ML-DSA, which signs the message itself)."""
    # ML-DSA signs the message directly; it takes no separate hash parameter.
    return None if isinstance(key, mldsa.MLDSA65PrivateKey) else hashes.SHA256()


def authority(name, algorithm="ml-dsa-65"):
    """A new self-signed authority: (key, certificate)."""
    key = new_key(algorithm)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, digest_for(key))
    )
    return key, cert


def leaf(name, ca, hours, expired=False, algorithm="ml-dsa-65"):
    """A short-lived leaf certificate for `name`, signed by authority `ca`."""
    key = new_key(algorithm)
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=2) if expired else now - dt.timedelta(minutes=5)
    end = now - dt.timedelta(hours=1) if expired else now + dt.timedelta(hours=hours)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca[1].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .sign(ca[0], digest_for(ca[0]))
    )
    return key, cert


def key_bytes(key):
    """PKCS#8 DER encoding of a private key."""
    return key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def provision(root, relay, exit_address, hours=12, adversarial=False, algorithm="ml-dsa-65"):
    """Create a fresh lab deployment: two authorities, four identities and their configs."""
    if not 1 <= hours <= 23:
        raise ValueError("leaf validity must be 1..23 hours")
    root = root.resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ["offline", "relay", "client", "exit"]:
        (root / name).mkdir(mode=0o700)
    authorities = {lane: authority("advanced-vpn-" + lane, algorithm) for lane in ["outer", "inner"]}
    for lane, pair in authorities.items():
        put(root / "offline" / (lane + "-ca.key"), key_bytes(pair[0]))
    peers = {}
    for role in ["relay", "client-outer", "exit", "client-inner"]:
        lane = "outer" if role in ["relay", "client-outer"] else "inner"
        peers[role] = leaf(role + ".advanced-vpn.internal", authorities[lane], hours, algorithm=algorithm)

    def identity(directory, role, peer, lane):
        put(directory / (lane + "-ca.der"), authorities[lane][1].public_bytes(serialization.Encoding.DER))
        put(directory / (lane + "-cert.der"), peers[role][1].public_bytes(serialization.Encoding.DER))
        put(directory / (lane + "-key.der"), key_bytes(peers[role][0]))
        return dict(
            ca=str(directory / (lane + "-ca.der")),
            cert=str(directory / (lane + "-cert.der")),
            key=str(directory / (lane + "-key.der")),
            peer_sha256=peers[peer][1].fingerprint(hashes.SHA256()).hex(),
            server_name=peer + ".advanced-vpn.internal",
        )

    configs = {}
    for role in ["relay", "exit", "client"]:
        directory = root / role
        config = dict(
            schema=1,
            role=role,
            listen=relay if role == "relay" else exit_address if role == "exit" else "0.0.0.0:0",
            relay=relay if role == "client" else None,
            exit=exit_address if role == "relay" else None,
            outer=None,
            inner=None,
            tun=None if role == "relay" else "avpn0",
            local_ip="10.77.0.2" if role == "client" else "10.77.0.1" if role == "exit" else None,
            peer_ip="10.77.0.1" if role == "client" else "10.77.0.2" if role == "exit" else None,
            destinations=[],
            session_seconds=300,
            packets_per_second=RATE_PACKETS,
            bytes_per_second=RATE_BYTES,
            mtu=1280,
        )
        if role == "relay":
            config["outer"] = identity(directory, "relay", "client-outer", "outer")
        if role == "exit":
            config["inner"] = identity(directory, "exit", "client-inner", "inner")
        if role == "client":
            config["outer"] = identity(directory, "client-outer", "relay", "outer")
            config["inner"] = identity(directory, "client-inner", "exit", "inner")
        configs[role] = config
        put(directory / "config.json", (json.dumps(config, indent=2) + "\n").encode())
    if adversarial:
        # Synthetic identities only, kept in the test output, never uploaded to Git.
        tests = root / "tests"
        tests.mkdir(mode=0o700)
        # 'classical' is an ECDSA leaf issued by the genuine outer authority.
        for name, ca, expired, alg in [
            ("unlisted", authorities["outer"], False, algorithm),
            ("untrusted", authority("unknown", algorithm), False, algorithm),
            ("expired", authorities["outer"], True, algorithm),
            ("classical", authorities["outer"], False, "ecdsa"),
        ]:
            k, c = leaf(name + ".advanced-vpn.internal", ca, hours, expired, algorithm=alg)
            put(tests / (name + "-key.der"), key_bytes(k))
            put(tests / (name + "-cert.der"), c.public_bytes(serialization.Encoding.DER))
    receipt = dict(
        schema=1,
        leaf_valid_hours=hours,
        offline_ca_keys_in_peer_directories=False,
        authentication=(
            "ML-DSA-65 certificates and TLS 1.3 CertificateVerify"
            if algorithm == "ml-dsa-65"
            else "TEST ONLY: classical ECDSA (must be refused)"
        )
        + " + exact SHA256 pins",
        key_exchange="X25519MLKEM768 only",
        application_cipher="AES-256-GCM",
        note="Post-quantum key exchange and post-quantum authentication; the QUIC Initial packets use standard AES-128 protection.",
    )
    put(root / "PROVISION.json", (json.dumps(receipt, indent=2) + "\n").encode())
    return configs


if __name__ == "__main__":
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--relay", required=True)
    p.add_argument("--exit", required=True)
    p.add_argument("--hours", type=int, default=12)
    p.add_argument("--algorithm", choices=ALGORITHMS, default="ml-dsa-65", help="ecdsa is for rejection tests only")
    a = p.parse_args()
    provision(a.out, a.relay, a.exit, a.hours, algorithm=a.algorithm)
    print("Created separate private peer directories; keep offline/ off every peer.")

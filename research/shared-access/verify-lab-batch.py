#!/usr/bin/env python3
"""Run sponsored blind issuance, local sealing and per-hop admission in a disposable lab."""

import argparse
import json
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, x25519

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from shared_admission import Cohort, EPOCH_SECONDS, ROLES, ReplayLedger, admit, binding_message  # noqa: E402
from shared_wallet import CreditWallet, PAIRS_PER_BATCH  # noqa: E402
import keyguard  # noqa: E402


def lab_tls_identity(role):
    """Generate a disposable pinned TLS endpoint for a single local role."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, f"{role}.vpn.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"{role}.vpn.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_id = hashlib.sha256(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).digest()
    return key_id, dict(
        cert=cert.public_bytes(serialization.Encoding.PEM).decode(),
        key=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    )


def main():
    """Run the lab and print aggregate results without exposing credits or private keys."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("issuer", nargs="?", type=Path, default=Path(__file__).with_name("issue-lab-batch.mjs"))
    parser.add_argument("--wireguard", action="store_true", help="exercise nested carriers in fresh namespaces")
    hardware_options = parser.add_mutually_exclusive_group()
    hardware_options.add_argument(
        "--hardware", action="store_true", help="create a disposable non-resident Nitrokey credential"
    )
    hardware_options.add_argument(
        "--hardware-vault", type=Path, help="use an existing test Nitrokey vault for one pair"
    )
    args = parser.parse_args()
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node 24 is required for the independent Privacy Pass issuer")
    script = args.issuer.resolve()
    hop_ids, servers = zip(*(lab_tls_identity(role) for role in ROLES), strict=True)
    output = subprocess.check_output(  # noqa: S603 - local lab issuer
        [node, str(script)], input=json.dumps(dict(zip(ROLES, servers, strict=True))).encode(), timeout=30
    )
    batch = json.loads(output)
    spki = bytes.fromhex(batch["issuerSpki"])
    cohorts = tuple(Cohort(batch["issuerName"], batch["poolName"], role, batch["epoch"], spki) for role in ROLES)
    pairs = [tuple(bytes.fromhex(token) for token in pair) for pair in batch["pairs"]]
    now = batch["epoch"] * EPOCH_SECONDS
    session_keys, carrier_keys, exporters = set(), set(), set()
    first_carriers, first_expiries = [], []
    physical = args.hardware or args.hardware_vault is not None
    with tempfile.TemporaryDirectory(prefix="cpvpn-admission-") as temp:
        directory = Path(temp)
        ledgers = [ReplayLedger(directory / f"{role}.sqlite", role) for role in ROLES]
        for ledger in ledgers:
            ledger.initialize()
        wallet = CreditWallet(directory / "wallet.json", args.hardware_vault or directory / "vault", *cohorts)
        # The memory-only fixture stands in for hardware_assertion. It creates no real PIN requests.
        meta = {"credential": "Y3JlZGVudGlhbA==", "salt": "c2FsdA=="}
        count = 1 if physical else PAIRS_PER_BATCH
        hardware = (
            keyguard.one_pin()
            if physical
            else patch("keyguard.hardware_secret", return_value=(secrets.token_bytes(32), meta))
        )
        with hardware:
            if args.hardware:
                print(
                    "Creating a disposable Nitrokey credential. Enter the PIN and touch when it flashes.",
                    file=sys.stderr,
                    flush=True,
                )
                keyguard.enroll(wallet.vault)
            if physical:
                print("Sealing the sponsored credits. Touch the Nitrokey when it flashes.", file=sys.stderr, flush=True)
            wallet.import_batch(pairs)
            for index, channel_pair in enumerate(batch["channels"][:count]):
                if physical:
                    print(
                        "Opening the sealed credits. Touch the Nitrokey when it flashes.", file=sys.stderr, flush=True
                    )
                for cohort, ledger, token, hop_id, channel in zip(
                    cohorts, ledgers, wallet.take_pair(now), hop_ids, channel_pair, strict=True
                ):
                    identity = mldsa.MLDSA65PrivateKey.generate()
                    private = x25519.X25519PrivateKey.generate()
                    carrier = private.public_key().public_bytes_raw()
                    client_exporter, server_exporter = map(bytes.fromhex, channel)
                    proof = identity.sign(binding_message(cohort, token, hop_id, client_exporter, carrier))
                    expires = admit(
                        cohort,
                        ledger,
                        token,
                        now,
                        hop_key_id=hop_id,
                        channel_binding=server_exporter,
                        carrier_key=carrier,
                        session_key=identity.public_key(),
                        proof=proof,
                    )
                    session_keys.add(
                        identity.public_key().public_bytes(
                            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    )
                    carrier_keys.add(carrier)
                    exporters.add(server_exporter)
                    if index == 0:
                        first_carriers.append(private)
                        first_expiries.append(expires)
    expected = count * len(ROLES)
    if any(len(values) != expected for values in (session_keys, carrier_keys, exporters)):
        raise RuntimeError("lab reused a session key or channel")
    result = dict(
        verified_redemptions=expected,
        fresh_tls_identities=len(session_keys),
        fresh_carrier_keys=len(carrier_keys),
        hardware="physical Nitrokey" if physical else "mocked",
        transport="pinned loopback TLS 1.3",
        unique_tls_exporters=len(exporters),
    )
    if args.wireguard:
        from wireguard_lab import run_wireguard

        result["wireguard"] = run_wireguard(first_carriers, first_expiries, now, servers[1])
    print(json.dumps(result))


if __name__ == "__main__":
    main()

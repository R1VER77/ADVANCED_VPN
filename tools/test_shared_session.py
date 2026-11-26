"""Tests for shared carrier leases, two-hop TLS 1.3 admission, and `cypherpunk shared` CLI."""

from argparse import Namespace
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, rsa, x25519

import mesh
import shared_cli
from shared_admission import AdmissionError, Cohort, EPOCH_SECONDS, PSS, ROLES, ReplayLedger, SPKI_PREFIX, TOKEN_TYPE
from shared_carrier import LeaseAllocator, SharedCarrier
from shared_pool import DIRECTORY_DOMAIN
from shared_session import AdmissionServer, HopEndpoint, SharedSessionClient, admit_hop, disconnect_hop
from shared_wallet import PAIRS_PER_BATCH


def make_tls_cert(directory: Path, name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    hop_id = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).digest()
    return cert_path, key_path, hop_id


def make_issuer_and_tokens(epoch: int, count: int = PAIRS_PER_BATCH):
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = SPKI_PREFIX + issuer.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    cohorts = tuple(Cohort("issuer.vpn.test", "pool.vpn.test", role, epoch, spki) for role in ROLES)
    pairs = []
    for _ in range(count):
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


class FakeCarrierDaemon:
    """In-memory peer for SharedCarrier socketpair frames during unit tests."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.installed: dict[bytes, tuple[str, int]] = {}
        self.frames: list[bytes] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            while True:
                buf = bytearray()
                while len(buf) < 77:
                    chunk = self.sock.recv(77 - len(buf))
                    if not chunk:
                        return
                    buf.extend(chunk)
                frame = bytes(buf)
                self.frames.append(frame)
                op = frame[0]
                key = frame[1:33]
                if op == 1:
                    addr = socket.inet_ntoa(frame[65:69])
                    (expiry,) = struct.unpack("!Q", frame[69:77])
                    self.installed[key] = (addr, expiry)
                elif op == 2:
                    self.installed.pop(key, None)
                self.sock.sendall(b"\x00")
        except OSError:
            pass
        finally:
            self.sock.close()


class TestSharedCarrierAndSession(unittest.TestCase):
    def test_lease_allocator_isolates_entry_and_exit_subnets(self):
        entry = LeaseAllocator("entry")
        exit_alloc = LeaseAllocator("exit")
        now = 1000
        a1 = entry.reserve(b"\x01" * 32, now + 60, now=now)
        a2 = entry.reserve(b"\x02" * 32, now + 60, now=now)
        x1 = exit_alloc.reserve(b"\x01" * 32, now + 60, now=now)
        self.assertEqual(str(a1), "10.78.0.2")
        self.assertEqual(str(a2), "10.78.0.3")
        self.assertEqual(str(x1), "10.79.0.2")
        self.assertEqual(entry.active_count(now=now), 2)
        entry.release(b"\x01" * 32)
        self.assertEqual(str(entry.reserve(b"\x03" * 32, now + 60, now=now)), "10.78.0.2")
        # Expired leases are reclaimed automatically.
        self.assertEqual(entry.active_count(now=now + 61), 0)

    def test_two_hop_tls13_admission_rollback_and_disconnect(self):
        now = int(time.time())
        epoch = now // EPOCH_SECONDS
        _, (entry_cohort, exit_cohort), pairs = make_issuer_and_tokens(epoch)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            e_cert, e_key, e_hop = make_tls_cert(root, "entry.vpn.test")
            x_cert, x_key, x_hop = make_tls_cert(root, "exit.vpn.test")
            e_ledger = ReplayLedger(root / "entry.sqlite", "entry")
            x_ledger = ReplayLedger(root / "exit.sqlite", "exit")
            e_ledger.initialize()
            x_ledger.initialize()
            e_sup, e_dev = socket.socketpair()
            x_sup, x_dev = socket.socketpair()
            e_fake = FakeCarrierDaemon(e_dev)
            x_fake = FakeCarrierDaemon(x_dev)
            e_carrier = SharedCarrier(e_sup, role="entry")
            x_carrier = SharedCarrier(x_sup, role="exit")
            e_srv = AdmissionServer(
                bind=("127.0.0.1", 0),
                cert_path=e_cert,
                key_path=e_key,
                cohort=entry_cohort,
                ledger=e_ledger,
                carrier=e_carrier,
                server_wg_public=x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
            )
            x_srv = AdmissionServer(
                bind=("127.0.0.1", 0),
                cert_path=x_cert,
                key_path=x_key,
                cohort=exit_cohort,
                ledger=x_ledger,
                carrier=x_carrier,
                server_wg_public=x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
            )
            e_srv.start()
            x_srv.start()
            try:
                e_ep = HopEndpoint("127.0.0.1", e_srv.address[1], "entry.vpn.test", e_cert, e_hop)
                x_ep = HopEndpoint("127.0.0.1", x_srv.address[1], "exit.vpn.test", x_cert, x_hop)
                events = []
                # 1. Required upstream unavailable -> fail closed before any admission.
                client_down = SharedSessionClient(
                    entry_cohort=entry_cohort,
                    exit_cohort=exit_cohort,
                    entry_endpoint=e_ep,
                    exit_endpoint=x_ep,
                    upstream_interface="wg-missing",
                    activate_entry=lambda g: events.append(("up-e", g.assigned_address)),
                    teardown_entry=lambda g: events.append(("down-e", g.assigned_address)),
                    activate_exit=lambda g: events.append(("up-x", g.assigned_address)),
                    teardown_exit=lambda g: events.append(("down-x", g.assigned_address)),
                    upstream_check=lambda _: False,
                )
                with self.assertRaises(AdmissionError):
                    client_down.connect(*pairs[0])
                self.assertEqual(e_fake.installed, {})
                self.assertEqual(x_fake.installed, {})

                # 2. Exit admission failure (wrong role token) -> entry peer rolled back cleanly.
                client = SharedSessionClient(
                    entry_cohort=entry_cohort,
                    exit_cohort=exit_cohort,
                    entry_endpoint=e_ep,
                    exit_endpoint=x_ep,
                    upstream_interface="up0",
                    activate_entry=lambda g: events.append(("up-e", g.assigned_address)),
                    teardown_entry=lambda g: events.append(("down-e", g.assigned_address)),
                    activate_exit=lambda g: events.append(("up-x", g.assigned_address)),
                    teardown_exit=lambda g: events.append(("down-x", g.assigned_address)),
                    upstream_check=lambda iface: iface == "up0",
                )
                with self.assertRaises(AdmissionError):
                    client.connect(pairs[0][0], pairs[0][0])  # entry token passed to exit
                self.assertEqual(e_fake.installed, {})
                self.assertEqual(x_fake.installed, {})
                self.assertEqual(e_srv.metrics()["active_leases"], 0)
                self.assertEqual(e_srv.metrics()["disconnected"], 1)

                # 3. Full two-hop connect + distinct exporters + clean disconnect.
                e_grant, x_grant = client.connect(*pairs[1])
                self.assertEqual(e_grant.assigned_address, "10.78.0.2")
                self.assertEqual(x_grant.assigned_address, "10.79.0.2")
                self.assertNotEqual(e_grant.channel_binding, x_grant.channel_binding)
                self.assertNotEqual(e_grant.psk, x_grant.psk)
                self.assertEqual(len(e_fake.installed), 1)
                self.assertEqual(len(x_fake.installed), 1)
                # Replay of spent entry token is rejected.
                with self.assertRaises(AdmissionError):
                    admit_hop(entry_cohort, e_ep, pairs[1][0])
                # Disconnect removes both peers.
                client.disconnect(e_grant, x_grant)
                self.assertEqual(e_fake.installed, {})
                self.assertEqual(x_fake.installed, {})
                # Aggregate-only metrics contain no IPs or timestamps.
                self.assertEqual(set(e_srv.metrics()), {"active_leases", "admitted", "rejected", "disconnected"})
                # Disconnecting again fails (lease already removed).
                with self.assertRaises(AdmissionError):
                    disconnect_hop(e_grant)
            finally:
                e_srv.stop()
                x_srv.stop()
                e_sup.close()
                x_sup.close()


class TestSharedCli(unittest.TestCase):
    def _signed_manifest(self, root: Path, spki: bytes, epoch: int, now: int):
        pool_key = mldsa.MLDSA65PrivateKey.generate()
        nodes = []
        for role, provider, country, op_name in (
            ("entry", "gcp", "US", "op-alpha"),
            ("exit", "host", "CH", "op-beta"),
        ):
            op_key = mldsa.MLDSA65PrivateKey.generate()
            op_pub = op_key.public_key().public_bytes_raw()
            desc = mesh.sign_descriptor(
                {
                    "schema": 1,
                    "node_public_key": base64.b64encode(op_pub).decode(),
                    "node_id": mesh.member_id(op_pub),
                    "operator": op_name,
                    "provider": provider,
                    "country": country,
                    "roles": [role],
                    "published": now - 60,
                    "expires": now + 2 * EPOCH_SECONDS,
                },
                op_key,
            )
            nodes.append(desc)
        manifest = {
            "schema": 1,
            "pool": "pool.vpn.test",
            "issuer": "issuer.vpn.test",
            "issuer_spki": base64.b64encode(spki).decode(),
            "epoch": epoch,
            "nodes": nodes,
        }
        manifest["signature"] = base64.b64encode(
            pool_key.sign(DIRECTORY_DOMAIN + mesh.canonical(manifest))
        ).decode()
        manifest_path = root / "pool.json"
        manifest_path.write_text(json.dumps(manifest))
        pinned_b64 = base64.b64encode(pool_key.public_key().public_bytes_raw()).decode()
        return manifest_path, pinned_b64

    def test_import_status_connect_disconnect_and_credits(self):
        now = int(time.time())
        next_epoch = now // EPOCH_SECONDS + 1
        spki, _, pairs = make_issuer_and_tokens(next_epoch)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest_path, pinned = self._signed_manifest(root, spki, next_epoch, now)
            batch_path = root / "batch.json"
            # Sponsor/order fields in input must never be persisted to local index.
            batch_path.write_text(
                json.dumps(
                    {
                        "sponsor_id": "must-not-be-stored",
                        "order_id": "must-not-be-stored",
                        "pairs": [[a.hex(), b.hex()] for a, b in pairs],
                    }
                )
            )
            env = {
                "CPVPN_SHARED_DIR": str(root / "shared"),
                "CPVPN_UPSTREAM_INTERFACE": "lo",
            }
            meta = {"credential": "Y3JlZGVudGlhbA==", "salt": "c2FsdA=="}
            with (
                patch.dict(os.environ, env, clear=False),
                patch("keyguard.hardware_secret", return_value=(b"\x42" * 32, meta)),
                patch.object(mesh, "token_store_path", return_value=root / "tokens.json"),
            ):
                imported = shared_cli.cmd_import(
                    Namespace(
                        pool=str(manifest_path),
                        pinned_key=pinned,
                        batch=str(batch_path),
                        vault=str(root / "vault"),
                        allow_current_epoch=False,
                        now=now,
                    )
                )
                self.assertTrue(imported["ok"], imported)
                self.assertEqual(imported["imported_pairs"], PAIRS_PER_BATCH)
                index_text = (root / "shared" / "index.json").read_text()
                self.assertNotIn("must-not-be-stored", index_text)

                status = shared_cli.cmd_status(Namespace())
                self.assertTrue(status["ok"])
                self.assertFalse(status["shared_access_enabled"])
                self.assertEqual(status["shared_pending_pairs"], PAIRS_PER_BATCH)
                self.assertIn("Classical RSA-PSS", status["token_verification"])
                self.assertIn("cookies", status["identity_notice"])

                credits = mesh.cmd_quota(Namespace())
                self.assertTrue(credits["ok"])
                self.assertEqual(credits["pending_total"], PAIRS_PER_BATCH * 2)
                self.assertIn("Public pool disabled", credits["pool_badge"])

                conn = shared_cli.cmd_connect(Namespace())
                self.assertFalse(conn["ok"])
                self.assertEqual(conn["error"], "SharedAccessDisabled")

                disc = shared_cli.cmd_disconnect(Namespace())
                self.assertTrue(disc["ok"])
                self.assertEqual(disc["kill_switch"], "preserved")


if __name__ == "__main__":
    unittest.main()

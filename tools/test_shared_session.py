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
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, rsa, x25519

import mesh
import shared_cli
from shared_admission import AdmissionError, Cohort, EPOCH_SECONDS, PSS, ROLES, ReplayLedger, SPKI_PREFIX, TOKEN_TYPE
from shared_carrier import LeaseAllocator, SharedCarrier
from shared_pool import DIRECTORY_DOMAIN
from shared_pq import HybridPqIdentity, PqEpochStamper, issue_checkout_ticket, slhdsa_available
from shared_session import AdmissionServer, HopEndpoint, SharedSessionClient, admit_hop, disconnect_hop
from shared_wallet import PAIRS_PER_BATCH


def make_tls_cert(directory: Path, name: str):
    key = ed25519.Ed25519PrivateKey.generate()
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
        .sign(key, None)
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
                TOKEN_TYPE + os.urandom(32) + hashlib.sha256(cohort.challenge).digest() + hashlib.sha256(spki).digest()
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
    def test_lease_allocator_isolates_entry_and_exit_subnets_and_randomizes(self):
        entry = LeaseAllocator("entry")
        exit_alloc = LeaseAllocator("exit")
        now = 1000
        a1 = entry.reserve(b"\x01" * 32, now + 60, now=now)
        a2 = entry.reserve(b"\x02" * 32, now + 60, now=now)
        x1 = exit_alloc.reserve(b"\x01" * 32, now + 60, now=now)
        self.assertTrue(str(a1).startswith("10.78.0."))
        self.assertTrue(str(a2).startswith("10.78.0."))
        self.assertNotEqual(a1, a2)
        self.assertTrue(str(x1).startswith("10.79.0."))
        self.assertEqual(entry.active_count(now=now), 2)
        entry.release(b"\x01" * 32)
        self.assertEqual(entry.active_count(now=now), 1)
        # Expired leases are reclaimed automatically.
        self.assertEqual(entry.active_count(now=now + 61), 0)

    def test_witness_quorum_blocks_key_tagging(self):
        from shared_pool import SharedPool, witness_payload

        now = int(time.time())
        epoch = now // EPOCH_SECONDS
        spki, _, _ = make_issuer_and_tokens(epoch, count=1)
        pool_key = mldsa.MLDSA65PrivateKey.generate()
        w1, w2 = mldsa.MLDSA65PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
        nodes = []
        for role, provider, country, op_name in (("entry", "gcp", "US", "op-a"), ("exit", "host", "CH", "op-b")):
            op_key = mldsa.MLDSA65PrivateKey.generate()
            op_pub = op_key.public_key().public_bytes_raw()
            nodes.append(
                mesh.sign_descriptor(
                    {
                        "schema": 1,
                        "node_public_key": base64.b64encode(op_pub).decode(),
                        "node_id": mesh.member_id(op_pub),
                        "operator": op_name,
                        "provider": provider,
                        "country": country,
                        "roles": [role],
                        "published": now - 60,
                        "expires": now + EPOCH_SECONDS,
                    },
                    op_key,
                )
            )
        manifest = {
            "schema": 1,
            "pool": "pool.vpn.test",
            "issuer": "issuer.vpn.test",
            "issuer_spki": base64.b64encode(spki).decode(),
            "epoch": epoch,
            "nodes": nodes,
        }
        commitment = witness_payload(manifest)
        manifest["witnesses"] = {
            "w1": base64.b64encode(w1.sign(commitment)).decode(),
            "w2": base64.b64encode(w2.sign(commitment)).decode(),
        }
        manifest["signature"] = base64.b64encode(pool_key.sign(DIRECTORY_DOMAIN + mesh.canonical(manifest))).decode()
        wkeys = {"w1": w1.public_key(), "w2": w2.public_key()}
        pool = SharedPool.verify(manifest, pool_key.public_key(), now, witness_keys=wkeys, witness_quorum=2)
        self.assertEqual(pool.cohorts[0].epoch, epoch)
        # Missing quorum (only 1 valid witness when 2 required) is rejected.
        bad = {**manifest, "witnesses": {"w1": manifest["witnesses"]["w1"]}}
        bad["signature"] = base64.b64encode(pool_key.sign(DIRECTORY_DOMAIN + mesh.canonical(bad))).decode()
        with self.assertRaisesRegex(AdmissionError, "witness quorum"):
            SharedPool.verify(bad, pool_key.public_key(), now, witness_keys=wkeys, witness_quorum=2)

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
                e_ep = HopEndpoint(
                    "127.0.0.1", e_srv.address[1], "entry.vpn.test", e_cert, e_hop, e_srv.server_pq_public
                )
                x_ep = HopEndpoint(
                    "127.0.0.1", x_srv.address[1], "exit.vpn.test", x_cert, x_hop, x_srv.server_pq_public
                )
                # Wrong pinned server PQ identity must fail BEFORE credit is sent (blocks live quantum TLS MITM).
                wrong_ep = HopEndpoint(
                    "127.0.0.1", e_srv.address[1], "entry.vpn.test", e_cert, e_hop, HybridPqIdentity().public
                )
                with self.assertRaises(AdmissionError):
                    admit_hop(entry_cohort, wrong_ep, pairs[0][0])
                self.assertEqual(e_fake.installed, {})
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
                import ssl

                self.assertTrue(bool(e_srv.context.options & ssl.OP_NO_TICKET))
                self.assertTrue(bool(x_srv.context.options & ssl.OP_NO_TICKET))
                slept = []
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
                    hop_delay_range=(0.4, 1.5),
                    disconnect_tail_range=(0.3, 1.0),
                    silent_entry_disconnect=False,
                    sleep_fn=slept.append,
                )
                with self.assertRaises(AdmissionError):
                    client.connect(pairs[0][0], pairs[0][0])  # entry token passed to exit
                self.assertEqual(e_fake.installed, {})
                self.assertEqual(x_fake.installed, {})
                self.assertEqual(e_srv.metrics()["active_leases"], 0)
                self.assertEqual(e_srv.metrics()["disconnected"], 1)

                # 3. Full two-hop connect + PQ-hybrid exporters + decoupled expiry + tight jitter + key wipe.
                slept.clear()
                e_grant, x_grant = client.connect(*pairs[1])
                self.assertTrue(e_grant.assigned_address.startswith("10.78.0."))
                self.assertTrue(x_grant.assigned_address.startswith("10.79.0."))
                self.assertGreaterEqual(e_grant.expiry, x_grant.expiry)
                self.assertEqual(len(slept), 1)
                self.assertTrue(0.4 <= slept[0] <= 1.5)
                self.assertNotEqual(e_grant.channel_binding, x_grant.channel_binding)
                self.assertNotEqual(e_grant.psk, x_grant.psk)
                self.assertEqual(len(e_fake.installed), 1)
                self.assertEqual(len(x_fake.installed), 1)
                # Replay of spent entry token is rejected.
                with self.assertRaises(AdmissionError):
                    admit_hop(entry_cohort, e_ep, pairs[1][0])
                # Explicit disconnect removes both peers after short cover tail and wipes ephemeral keys.
                client.disconnect(e_grant, x_grant)
                self.assertEqual(len(slept), 2)
                self.assertTrue(0.3 <= slept[1] <= 1.0)
                self.assertEqual(e_fake.installed, {})
                self.assertEqual(x_fake.installed, {})
                self.assertEqual(e_grant.psk, b"")
                self.assertIsNone(e_grant.client_private)
                self.assertIsNone(x_grant.session_private)
                # Aggregate-only metrics contain no IPs or timestamps.
                self.assertEqual(set(e_srv.metrics()), {"active_leases", "admitted", "rejected", "disconnected"})
                # Disconnecting again fails (wiped keys refused).
                with self.assertRaises(AdmissionError):
                    disconnect_hop(e_grant)

                # 4. Default silent-entry disconnect has zero disconnect sleep and wipes keys.
                slept.clear()
                silent_client = SharedSessionClient(
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
                    sleep_fn=slept.append,
                )
                self.assertTrue(silent_client.silent_entry_disconnect)
                self.assertEqual(silent_client.hop_delay_range, (0.4, 1.5))
                e2, x2 = silent_client.connect(*pairs[2])
                self.assertEqual(len(slept), 1)
                silent_client.disconnect(e2, x2)
                # Zero extra sleep during silent disconnect; exit removed, entry expires silently.
                self.assertEqual(len(slept), 1)
                self.assertEqual(x_fake.installed, {})
                self.assertEqual(len(e_fake.installed), 1)
                self.assertEqual(e2.psk, b"")
                self.assertIsNone(e2.client_private)
            finally:
                e_srv.stop()
                x_srv.stop()
                e_sup.close()
                x_sup.close()

    def test_split_authority_pq_stamped_credits_defeat_rsa_and_single_family_breaks(self):
        """Triple-family composite credits (RFC 9578 RSA-PSS + ML-DSA-87 + SLH-DSA + Ed25519) fail closed."""
        from shared_pool import SharedPool, witness_payload

        now = int(time.time())
        epoch = now // EPOCH_SECONDS
        spki, _, pairs = make_issuer_and_tokens(epoch, count=2)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            attester = HybridPqIdentity()
            stamper = PqEpochStamper(root / "stamper.sqlite", attester.public)
            stamper.initialize()
            # On OpenSSL 3.5 hosts (e.g. Debian 13), SLH-DSA-SHA2-128f hash-based leg is active too.
            if slhdsa_available():
                self.assertIsNotNone(stamper.public.slhdsa_raw)

            # Bind pq_stamper_public into a witness-attested SharedPool manifest.
            pool_key = mldsa.MLDSA65PrivateKey.generate()
            w1 = mldsa.MLDSA65PrivateKey.generate()
            nodes = []
            for role, provider, country, op_name in (("entry", "gcp", "US", "op-a"), ("exit", "host", "CH", "op-b")):
                op_key = mldsa.MLDSA65PrivateKey.generate()
                op_pub = op_key.public_key().public_bytes_raw()
                nodes.append(
                    mesh.sign_descriptor(
                        {
                            "schema": 1,
                            "node_public_key": base64.b64encode(op_pub).decode(),
                            "node_id": mesh.member_id(op_pub),
                            "operator": op_name,
                            "provider": provider,
                            "country": country,
                            "roles": [role],
                            "published": now - 60,
                            "expires": now + EPOCH_SECONDS,
                        },
                        op_key,
                    )
                )
            manifest = {
                "schema": 1,
                "pool": "pool.vpn.test",
                "issuer": "issuer.vpn.test",
                "issuer_spki": base64.b64encode(spki).decode(),
                "pq_stamper_public": stamper.public.to_dict(),
                "epoch": epoch,
                "nodes": nodes,
            }
            manifest["witnesses"] = {"w1": base64.b64encode(w1.sign(witness_payload(manifest))).decode()}
            manifest["signature"] = base64.b64encode(
                pool_key.sign(DIRECTORY_DOMAIN + mesh.canonical(manifest))
            ).decode()
            pool = SharedPool.verify(
                manifest, pool_key.public_key(), now, witness_keys={"w1": w1.public_key()}, witness_quorum=1
            )
            entry_cohort = pool.cohorts[0]
            self.assertEqual(entry_cohort.pq_stamper_public, stamper.public)

            # Forged ticket from a non-attester (e.g. CRQC breaking RSA-2048 alone) is rejected by stamper.
            forged_ticket = issue_checkout_ticket(HybridPqIdentity(), epoch)
            with self.assertRaisesRegex(AdmissionError, "invalid ML-DSA-87"):
                stamper.stamp(entry_cohort, pairs[0][0], forged_ticket, now=now)

            # Genuine PQ ticket + RFC 9578 token produces a valid triple-family PQ stamp; replays rejected.
            ticket = issue_checkout_ticket(attester, epoch)
            ticket2 = issue_checkout_ticket(attester, epoch)
            pq_stamp = stamper.stamp(entry_cohort, pairs[0][0], ticket, now=now)
            with self.assertRaisesRegex(AdmissionError, "already stamped"):
                stamper.stamp(entry_cohort, pairs[0][0], ticket, now=now)

            # Live AdmissionServer enforces ALL pinned families on the credit.
            cert, key, hop_id = make_tls_cert(root, "entry.vpn.test")
            ledger = ReplayLedger(root / "entry.sqlite", "entry")
            ledger.initialize()
            sup, dev = socket.socketpair()
            fake = FakeCarrierDaemon(dev)
            carrier = SharedCarrier(sup, role="entry")
            srv = AdmissionServer(
                bind=("127.0.0.1", 0),
                cert_path=cert,
                key_path=key,
                cohort=entry_cohort,
                ledger=ledger,
                carrier=carrier,
                server_wg_public=x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
            )
            srv.start()
            try:
                ep = HopEndpoint("127.0.0.1", srv.address[1], "entry.vpn.test", cert, hop_id, srv.server_pq_public)
                # Missing PQ stamp is refused (classical RSA-only credit rejected!).
                with self.assertRaises(AdmissionError):
                    admit_hop(entry_cohort, ep, pairs[0][0])
                # Tampered ML-DSA-87 leg is refused.
                bad_mldsa = {**pq_stamp, "mldsa87": base64.b64encode(b"\x00" * 16).decode()}
                with self.assertRaises(AdmissionError):
                    admit_hop(entry_cohort, ep, pairs[0][0], pq_stamp=bad_mldsa)
                # Tampered SLH-DSA leg (when active) is refused even if RSA + ML-DSA-87 + Ed25519 verify!
                if "slhdsa_sha2_128f" in pq_stamp:
                    raw_slh = bytearray(base64.b64decode(pq_stamp["slhdsa_sha2_128f"]))
                    raw_slh[0] ^= 1
                    bad_slh = {**pq_stamp, "slhdsa_sha2_128f": base64.b64encode(bytes(raw_slh)).decode()}
                    with self.assertRaises(AdmissionError):
                        admit_hop(entry_cohort, ep, pairs[0][0], pq_stamp=bad_slh)
                # Valid composite credit (RSA-2048-PSS + ML-DSA-87 + Ed25519 + SLH-DSA-SHA2-128f) succeeds!
                grant = admit_hop(entry_cohort, ep, pairs[0][0], pq_stamp=pq_stamp)
                self.assertEqual(len(fake.installed), 1)
                disconnect_hop(grant)
                grant.wipe()
                self.assertEqual(fake.installed, {})
            finally:
                srv.stop()
                sup.close()
                stamper.retire_epoch(now + EPOCH_SECONDS)
                attester.wipe()
                # Retired stamper cannot mint new stamps even with a valid ticket (forward privacy).
                with self.assertRaisesRegex(AdmissionError, "wiped"):
                    stamper.stamp(entry_cohort, pairs[1][0], ticket2, now=now)


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
        manifest["signature"] = base64.b64encode(pool_key.sign(DIRECTORY_DOMAIN + mesh.canonical(manifest))).decode()
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

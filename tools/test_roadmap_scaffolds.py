"""Unit tests for inside-tunnel IPv6, STARK credit bridge, split signing VM, and hardware carrier keys."""

import hashlib
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

import hw_carrier
import ipv6_tunnel
import shared_pq
import signing_vm
import zk_credits
import zkid


class TestIpv6Tunnel(unittest.TestCase):
    def test_dual_stack_plan_refuses_unsafe_exits_translation_and_split_tunnel(self):
        good_v6 = {"prefix": "2001:db8:cafe:1::/64", "egress": "both"}
        plan = ipv6_tunnel.DualStackPlan.build(exit_v6=good_v6)
        cmds = plan.namespace_commands()
        self.assertIn(["ip", "-6", "route", "replace", "default", "dev", "cpvpn0"], cmds)
        nft = plan.symmetric_guard_nft()
        self.assertIn('oifname "cpvpn0" meta nfproto { ipv4, ipv6 } accept', nft)
        self.assertIn("meta nfproto { ipv4, ipv6 } drop", nft)
        self.assertIn('oifname "lo" ip6 daddr ::1 udp dport 53 accept', nft)

        # Reject v4-only exit, non-global ULA prefix, translation, split-tunnel, and bad MTU.
        with self.assertRaises(ipv6_tunnel.Ipv6TunnelError):
            ipv6_tunnel.DualStackPlan.build(exit_v6={"prefix": "2001:db8::/64", "egress": "v4"})
        with self.assertRaises(ipv6_tunnel.Ipv6TunnelError):
            ipv6_tunnel.DualStackPlan.build(exit_v6={"prefix": "fd00:1234::/64", "egress": "both"})
        with self.assertRaises(ipv6_tunnel.Ipv6TunnelError):
            ipv6_tunnel.DualStackPlan.build(exit_v6=good_v6, use_translation=True)
        with self.assertRaises(ipv6_tunnel.Ipv6TunnelError):
            ipv6_tunnel.DualStackPlan.build(exit_v6=good_v6, split_v6_exceptions=("2001:db8::1",))
        with self.assertRaises(ipv6_tunnel.Ipv6TunnelError):
            ipv6_tunnel.DualStackPlan.build(exit_v6=good_v6, inner_mtu=1200)

        # Stages 3 & 4 telemetry helpers.
        gp = ipv6_tunnel.record_family_goodput(100.0, 97.3)
        self.assertEqual(gp["cell_bytes"], 1380)
        self.assertEqual(gp["ipv6_vs_ipv4_delta_pct"], -2.7)
        self.assertEqual(ipv6_tunnel.annotate_stream_family({"service": "x"}, "2001:db8::1")["family"], "ipv6")
        self.assertEqual(ipv6_tunnel.annotate_stream_family({"service": "x"}, "198.51.100.1")["family"], "ipv4")


class TestZkCredits(unittest.TestCase):
    def test_stark_credit_merkle_action_binding_replay_and_hybrid_stamp(self):
        start, lifetime, epoch = 20000, 365, 20005
        s0_a, s0_b = os.urandom(32), os.urandom(32)
        leaf_a = zkid.leaf(s0_a, lifetime)
        leaf_b = zkid.leaf(s0_b, lifetime)
        tree = zk_credits.MemberTree([leaf_a, leaf_b, os.urandom(32)])
        x_a = zkid.walk(s0_a, epoch - start)
        scope = hashlib.sha256(b"cpvpn/scope/shared-entry/v1").digest()
        req = b"admit-entry-session-payload"
        journal = zk_credits.reference_guest_evaluate(
            x_epoch=x_a,
            path=tree.proof_path(0),
            lifetime=lifetime,
            start=start,
            epoch=epoch,
            scope=scope,
            request_bytes=req,
        )
        self.assertEqual(journal.root, tree.root)

        image_id = os.urandom(32)
        stamper_id = shared_pq.HybridPqIdentity()
        stamp = stamper_id.sign(b"cpvpn/zk-hybrid-stamp/v1\0", journal.canonical_bytes())
        with tempfile.TemporaryDirectory() as td:
            ledger = zk_credits.NullifierLedger(Path(td) / "nf.sqlite")
            ledger.initialize()
            verifier = zk_credits.StarkCreditVerifier(
                image_id=image_id,
                trusted_root=tree.root,
                tree_start=start,
                tree_lifetime=lifetime,
                allowed_scopes={scope},
                ledger=ledger,
                verify_receipt=lambda img, rcpt, j: img == image_id and rcpt == b"valid-stark" and j == journal,
                hybrid_pq_public=stamper_id.public,
            )
            # Wrong request action, wrong scope, invalid receipt, or missing PQ stamp all fail closed.
            with self.assertRaisesRegex(zk_credits.ZkCreditError, "different request"):
                verifier.redeem(
                    receipt=b"valid-stark",
                    journal=journal,
                    request_bytes=b"other-request",
                    current_epoch=epoch,
                    pq_stamp=stamp,
                )
            with self.assertRaisesRegex(zk_credits.ZkCreditError, "invalid STARK receipt"):
                verifier.redeem(
                    receipt=b"forged-stark", journal=journal, request_bytes=req, current_epoch=epoch, pq_stamp=stamp
                )
            with self.assertRaises(Exception):
                verifier.redeem(
                    receipt=b"valid-stark", journal=journal, request_bytes=req, current_epoch=epoch, pq_stamp=None
                )

            # Valid STARK + multi-family PQ stamp succeeds once; replay is rejected.
            nf = verifier.redeem(
                receipt=b"valid-stark", journal=journal, request_bytes=req, current_epoch=epoch, pq_stamp=stamp
            )
            self.assertEqual(nf, journal.nullifier)
            with self.assertRaisesRegex(zk_credits.ZkCreditError, "already spent"):
                verifier.redeem(
                    receipt=b"valid-stark", journal=journal, request_bytes=req, current_epoch=epoch, pq_stamp=stamp
                )

            # Epoch retirement permanently blocks older epochs.
            ledger.retire_before(epoch + 1)
            with self.assertRaisesRegex(zk_credits.ZkCreditError, "permanently retired"):
                ledger.consume(epoch, scope, os.urandom(32))
        stamper_id.wipe()


class TestSigningVmAndHardwareCarrier(unittest.TestCase):
    def test_qrexec_validation_and_unix_socket_signing_vm_roundtrip(self):
        with self.assertRaises(signing_vm.SigningVmError):
            signing_vm.QrexecTransport("bad;vm")
        q = signing_vm.QrexecTransport("vault-hw")
        self.assertEqual(q.argv(), ["/usr/bin/qrexec-client-vm", "vault-hw", "cypherpunk.SessionSign"])

        now = int(time.time())
        lanes = {"outer": (b"\x11" * 48).hex(), "inner": (b"\x22" * 48).hex()}
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "signer.sock"

            def fake_vault(req):
                return {
                    "leaves": {k: (b"\xab" * 96).hex() for k in req["lanes"]},
                    "carry": {k: (b"\xcd" * 32).hex() for k in req["carry"]},
                    "not_before": now - 60,
                    "not_after": now + 3600,
                    "hardening": {"dumpable": False},
                }

            t = threading.Thread(target=signing_vm.serve_unix_socket_once, args=(sock_path, fake_vault), daemon=True)
            t.start()
            deadline = time.monotonic() + 5
            while not sock_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            reply = signing_vm.UnixSocketVmTransport(sock_path).request("/vault/state", lanes, carry=("wireguard",))
            t.join(timeout=3)
            self.assertEqual(set(reply["leaves"]), {"outer", "inner"})
            self.assertEqual(set(reply["carry"]), {"wireguard"})

        # Excess session window is rejected fail-closed.
        req = signing_vm.validate_signer_request("/vault/state", lanes, ())
        with self.assertRaisesRegex(signing_vm.SigningVmError, "MAX_SECONDS"):
            signing_vm.validate_signer_reply(
                req,
                {
                    "leaves": {k: (b"\xab" * 96).hex() for k in lanes},
                    "carry": {},
                    "not_before": now,
                    "not_after": now + 100_000,
                },
            )

    def test_hardware_carrier_adapters_and_hybrid_mlkem1024_psk(self):
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        peer_priv = x25519.X25519PrivateKey.generate()
        peer_pub = peer_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        peer_kem = mlkem.MLKEM1024PrivateKey.generate()
        peer_kem_pub = peer_kem.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # 1. OpenPGP v3.4 PSO:DECIPHER APDU exact framing + SW=9000 verification.
        def fake_card(apdu: bytes) -> bytes:
            self.assertEqual(apdu[:4], hw_carrier.OPENPGP_PSO_DECIPHER_HEADER)
            self.assertEqual(apdu[12:44], peer_pub)
            return client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub)) + b"\x90\x00"

        card = hw_carrier.OpenPgpCardEcdhProvider(client_pub, fake_card)
        sess = hw_carrier.derive_hardware_carrier_psk(card, peer_pub, peer_kem_pub, context=b"entry-hop-v1")
        self.assertTrue(sess.hardware_backed)
        self.assertEqual(len(sess.psk), 32)
        # Peer derives the exact same hybrid X25519 + ML-KEM-1024 PSK!
        peer_x = peer_priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub))
        peer_pq = peer_kem.decapsulate(sess.mlkem_ciphertext)
        expected_transcript = (
            hw_carrier.CARRIER_PSK_DOMAIN
            + client_pub
            + peer_pub
            + peer_kem_pub
            + sess.mlkem_ciphertext
            + b"entry-hop-v1"
        )
        expected_psk = shared_pq.dual_hkdf_expand(peer_x + peer_pq, expected_transcript, b"cpvpn/hw-carrier/psk/v1", 32)
        self.assertEqual(sess.psk, expected_psk)

        # 2. SLIP-0017 Trezor and Tillitis TKey adapters agree with the same ECDH secret.
        expected_ecdh = client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub))
        trezor = hw_carrier.Slip0017TrezorProvider(
            client_pub, "cypherpunk-vpn://entry", lambda _u, _p: b"\x04" + expected_ecdh
        )
        self.assertEqual(trezor.ecdh(peer_pub), expected_ecdh)
        tkey = hw_carrier.TKeyCarrierAppProvider(
            client_pub,
            lambda frame: (
                hw_carrier.TKeyCarrierAppProvider.RSP_OK + expected_ecdh if frame[:2] == b"\x43\x01" else b"\x00"
            ),
        )
        self.assertEqual(tkey.ecdh(peer_pub), expected_ecdh)


if __name__ == "__main__":
    unittest.main()

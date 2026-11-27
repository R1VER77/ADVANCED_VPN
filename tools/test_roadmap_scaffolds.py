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

            ready = threading.Event()
            t = threading.Thread(
                target=signing_vm.serve_unix_socket_once,
                args=(sock_path, fake_vault),
                kwargs={"ready": ready},
                daemon=True,
            )
            t.start()
            self.assertTrue(ready.wait(timeout=5))
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

    def test_managed_profile_sign_session_dispatches_to_unix_signing_vm(self):
        import managed_profile

        now = int(time.time())
        with tempfile.TemporaryDirectory() as td:
            sock_path = Path(td) / "vault.sock"

            def fake_vault(req):
                return {
                    "leaves": {k: (b"\xef" * 64).hex() for k in req["lanes"]},
                    "carry": {k: (b"\x12" * 32).hex() for k in req["carry"]},
                    "not_before": now - 30,
                    "not_after": now + 1800,
                }

            ready = threading.Event()
            t = threading.Thread(
                target=signing_vm.serve_unix_socket_once,
                args=(sock_path, fake_vault),
                kwargs={"ready": ready},
                daemon=True,
            )
            t.start()
            self.assertTrue(ready.wait(timeout=5))
            res = managed_profile.sign_session(
                {"outer": True, "inner": True},
                Path(td),
                carry=("wireguard",),
                signing_vm_spec=f"unix:{sock_path}",
            )
            t.join(timeout=3)
            self.assertEqual(set(res["leaves"]), {"outer", "inner"})
            self.assertEqual(res["carry"]["wireguard"], b"\x12" * 32)
            with self.assertRaisesRegex(ValueError, "unsupported CPVPN_SIGNING_VM"):
                managed_profile.sign_session({"outer": True}, Path(td), signing_vm_spec="http://evil")


class TestPhase1And3Hardening(unittest.TestCase):
    def test_server_egress_nts_and_strict_nts_rules(self):
        import server_egress

        profile = {"role": "exit", "network": {"relay_endpoint": "198.51.100.1:443"}}
        cfg = {"core": {"listen": "198.51.100.2:4444"}}
        default = server_egress.egress_rules(profile, cfg, 1000)
        self.assertIn("udp dport 123 accept", default)
        self.assertNotIn("tcp dport 4460", default)

        nts = server_egress.egress_rules(profile, cfg, 1000, nts=True)
        self.assertIn("tcp dport 4460 accept", nts)
        self.assertIn("udp dport 123 accept", nts)

        strict_pinned = server_egress.egress_rules(
            profile,
            cfg,
            1000,
            nts=True,
            strict_nts=True,
            nts_servers=("162.159.200.1", "2606:4700:f1::1"),
        )
        self.assertIn("ip daddr { 162.159.200.1 } tcp dport 4460 accept", strict_pinned)
        self.assertIn("ip daddr { 162.159.200.1 } udp dport 123 accept", strict_pinned)
        self.assertIn("ip6 daddr { 2606:4700:f1::1 } tcp dport 4460 accept", strict_pinned)
        self.assertNotIn("\n  udp dport 123 accept\n", strict_pinned)

        with self.assertRaisesRegex(ValueError, "strict_nts requires nts=True"):
            server_egress.egress_rules(profile, cfg, 1000, nts=False, strict_nts=True)

    def test_endpoint_hygiene_detects_unencrypted_swap_hibernation_and_coredumps(self):
        import cypherpunkctl

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            swaps = root / "swaps"
            cmdline = root / "cmdline"
            core = root / "core_pattern"

            # Clean host: zram swap, no resume=, core_pattern=|/bin/false.
            swaps.write_text("Filename\tType\tSize\tUsed\tPriority\n/dev/zram0\tpartition\t1024\t0\t100\n")
            cmdline.write_text("BOOT_IMAGE=/vmlinuz root=UUID=1234 ro quiet\n")
            core.write_text("|/bin/false\n")
            clean = dict((name, ok) for name, ok, _ in cypherpunkctl.endpoint_hygiene(swaps, cmdline, core))
            self.assertTrue(all(clean.values()), clean)

            # Risky host: raw /swapfile, resume=/dev/nvme0n1p3, apport coredump pipe.
            swaps.write_text("Filename\tType\tSize\tUsed\tPriority\n/swapfile\tfile\t1024\t0\t-2\n")
            cmdline.write_text("BOOT_IMAGE=/vmlinuz resume=/dev/nvme0n1p3 ro\n")
            core.write_text("|/usr/share/apport/apport %p %s\n")
            risky = dict((name, ok) for name, ok, _ in cypherpunkctl.endpoint_hygiene(swaps, cmdline, core))
            self.assertFalse(risky["endpoint swap encryption"])
            self.assertFalse(risky["endpoint hibernation disabled"])
            self.assertFalse(risky["endpoint core dumps suppressed"])

    def test_tor_namespace_guard_and_ephemeral_browser_profile_wipe(self):
        import tor_lab

        rules = tor_lab.tor_namespace_nft_rules(tunnel_iface="cpvpn0", tor_uid=115, dns_server="10.79.0.1")
        self.assertIn('meta skuid 115 oifname "cpvpn0" counter name tor_tunnel_packets accept', rules)
        self.assertIn('meta skuid 115 oifname != "cpvpn0" counter name tor_direct_drops drop', rules)
        self.assertIn('oifname "cpvpn0" ip daddr 10.79.0.1 udp dport 53 accept', rules)
        with self.assertRaises(ValueError):
            tor_lab.tor_namespace_nft_rules(tunnel_iface="cpvpn0; flush")

        with tempfile.TemporaryDirectory() as td:
            with tor_lab.EphemeralBrowserProfile("firefox", base_dir=Path(td), socks_proxy="127.0.0.1:9050") as prof:
                root_path = prof.root
                self.assertIsNotNone(root_path)
                prefs = (prof.profile_dir / "user.js").read_text()
                self.assertIn('privacy.resistFingerprinting", true', prefs)
                self.assertIn('network.proxy.socks_remote_dns", true', prefs)
                env = prof.env({"PATH": "/usr/bin", "MOZ_CRASHREPORTER_URL": "https://leak.example"})
                self.assertNotIn("MOZ_CRASHREPORTER_URL", env)
                self.assertTrue(env["HOME"].startswith(str(root_path)))
                argv = prof.argv("/usr/bin/firefox", "https://example.org")
                self.assertIn("--no-remote", argv)
                (prof.profile_dir / "cookies.sqlite").write_bytes(b"SECRET_SESSION_COOKIE")
            self.assertFalse(root_path.exists())

    def test_credit_wallet_and_shared_cli_seal_and_verify_pq_stamps_with_witness_quorum(self):
        from argparse import Namespace
        import base64
        import json
        from unittest import mock

        from cryptography.hazmat.primitives.asymmetric import mldsa
        import mesh
        from shared_admission import AdmissionError, EPOCH_SECONDS
        import shared_cli
        from shared_pool import DIRECTORY_DOMAIN, witness_payload
        from shared_pq import HybridPqIdentity, PqEpochStamper, issue_checkout_ticket
        from test_shared_session import make_issuer_and_tokens

        now = int(time.time())
        next_epoch = (now // EPOCH_SECONDS) + 1
        spki, _, pairs = make_issuer_and_tokens(next_epoch, count=4)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            attester = HybridPqIdentity()
            stamper = PqEpochStamper(root / "stamper.sqlite", attester.public)
            stamper.initialize()
            pool_key = mldsa.MLDSA65PrivateKey.generate()
            w1 = mldsa.MLDSA65PrivateKey.generate()
            nodes = []
            for role, prov, country, op_name in (("entry", "gcp", "US", "op-a"), ("exit", "host", "CH", "op-b")):
                op_key = mldsa.MLDSA65PrivateKey.generate()
                op_pub = op_key.public_key().public_bytes_raw()
                nodes.append(
                    mesh.sign_descriptor(
                        {
                            "schema": 1,
                            "node_public_key": base64.b64encode(op_pub).decode(),
                            "node_id": mesh.member_id(op_pub),
                            "operator": op_name,
                            "provider": prov,
                            "country": country,
                            "roles": [role],
                            "published": now - 60,
                            "expires": (next_epoch + 1) * EPOCH_SECONDS,
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
                "epoch": next_epoch,
                "nodes": nodes,
            }
            manifest["witnesses"] = {"w1": base64.b64encode(w1.sign(witness_payload(manifest))).decode()}
            manifest["signature"] = base64.b64encode(
                pool_key.sign(DIRECTORY_DOMAIN + mesh.canonical(manifest))
            ).decode()

            from shared_pool import SharedPool

            pool = SharedPool.verify(
                manifest, pool_key.public_key(), now, witness_keys={"w1": w1.public_key()}, witness_quorum=1
            )
            entry_c, exit_c = pool.cohorts
            pq_stamps = []
            for e_tok, x_tok in pairs:
                e_st = stamper.stamp(entry_c, e_tok, issue_checkout_ticket(attester, next_epoch), now=now)
                x_st = stamper.stamp(exit_c, x_tok, issue_checkout_ticket(attester, next_epoch), now=now)
                pq_stamps.append([e_st, x_st])

            pool_file = root / "pool.json"
            pool_file.write_text(json.dumps(manifest))
            witness_file = root / "witnesses.json"
            witness_file.write_text(json.dumps({"w1": base64.b64encode(w1.public_key().public_bytes_raw()).decode()}))
            unstamped_file = root / "unstamped.json"
            unstamped_file.write_text(json.dumps({"pairs": [[a.hex(), b.hex()] for a, b in pairs]}))
            stamped_file = root / "stamped.json"
            stamped_file.write_text(
                json.dumps({"pairs": [[a.hex(), b.hex()] for a, b in pairs], "pq_stamps": pq_stamps})
            )
            pinned_b64 = base64.b64encode(pool_key.public_key().public_bytes_raw()).decode()
            fake_secret = (b"\x55" * 32, {"credential": "00" * 16, "salt": "11" * 32})

            with (
                mock.patch.dict(os.environ, {"CPVPN_SHARED_DIR": str(root / "shared")}),
                mock.patch("keyguard.hardware_secret", return_value=fake_secret),
            ):
                # Unstamped batch into a PQ-stamped pool MUST fail closed.
                bad = shared_cli.cmd_import(
                    Namespace(
                        pool=str(pool_file),
                        batch=str(unstamped_file),
                        pinned_key=pinned_b64,
                        witness_keys=str(witness_file),
                        witness_quorum=1,
                        vault=str(root / "v"),
                        now=now,
                    )
                )
                self.assertFalse(bad["ok"])
                self.assertIn("PQ stamps", bad["message"])

                # Valid multi-family PQ stamped batch + witness quorum succeeds and seals fixed-size wallet!
                good = shared_cli.cmd_import(
                    Namespace(
                        pool=str(pool_file),
                        batch=str(stamped_file),
                        pinned_key=pinned_b64,
                        witness_keys=str(witness_file),
                        witness_quorum=1,
                        vault=str(root / "v"),
                        now=now,
                    )
                )
                self.assertTrue(good["ok"], good)
                self.assertTrue(good["pq_stamped"])
                self.assertIn("ML-DSA-87", good["token_verification"])

                # Taking a stamped pair returns both token pair and verified multi-family PQ stamps.
                from shared_wallet import CreditWallet

                w = CreditWallet(
                    root / "shared" / f"batch-pool.vpn.test-{next_epoch}.json",
                    root / "v",
                    entry_c,
                    exit_c,
                )
                taken_pair, taken_stamps = w.take_stamped_pair(next_epoch * EPOCH_SECONDS + 10)
                self.assertEqual(len(taken_pair), 2)
                self.assertEqual(len(taken_stamps), 2)
                self.assertIn("mldsa87", taken_stamps[0])
                # Attempting re-import cannot resurrect spent credits.
                with self.assertRaises(AdmissionError):
                    w.import_batch(pairs, pq_stamps=pq_stamps)
            attester.wipe()
            stamper.identity.wipe()

    def test_keyguard_kem_v2_triple_kex_and_v1_compat(self):
        import keyguard

        # schema=2: X25519 + X448 + ML-KEM-1024 + dual HKDF-SHA-512 XOR HKDF-SHA3-512.
        priv2, pub2 = keyguard.kem_keypair_v2()
        self.assertEqual((len(priv2), len(pub2)), (keyguard.KEM_V2_PRIVATE, keyguard.KEM_V2_PUBLIC))
        env2 = keyguard.kem_seal_v2(pub2, b"secret-psk-material", b"ctx-v2")
        self.assertEqual(env2["schema"], 2)
        self.assertEqual(keyguard.kem_open(priv2, env2, b"ctx-v2"), b"secret-psk-material")
        with self.assertRaises(Exception):
            keyguard.kem_open(priv2, env2, b"wrong-ctx")
        with self.assertRaises(ValueError):
            keyguard.kem_open(b"\x00" * 96, env2, b"ctx-v2")

        # schema=1 legacy envelopes remain 100% compatible.
        priv1, pub1 = keyguard.kem_keypair()
        env1 = keyguard.kem_seal(pub1, b"legacy-psk", b"ctx-v1")
        self.assertEqual(env1["schema"], 1)
        self.assertEqual(keyguard.kem_open(priv1, env1, b"ctx-v1"), b"legacy-psk")

    def test_managed_profile_multi_dot_upstreams_and_server_fees_nts_wiring(self):
        import json
        from unittest import mock

        import cypherpunkctl
        import managed_profile as mp
        import server_egress

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mp.lab_setup(root, "192.0.2.1:443", "198.51.100.2:4444")
            exit_prof = json.loads((root / "exit/profile.json").read_text())
            exit_prof["dns"]["upstreams"] = list(mp.DEFAULT_PQ_DOT_UPSTREAMS)
            mp.profile_validate(exit_prof)
            # Non-loopback upstreams rejected in recursive mode.
            bad_rec = json.loads((root / "exit/profile.json").read_text())
            bad_rec["dns"].update(upstream="127.0.0.1:5335", server_name="localhost", recursive=True, test_ca=None)
            bad_rec["dns"]["upstreams"] = [{"addr": "8.8.8.8:853", "server_name": "dns.google"}]
            with self.assertRaises(ValueError):
                mp.profile_validate(bad_rec)

        # ServerFees.egress_text() enables RFC 8915 NTS by default and supports CPVPN_STRICT_NTS_SERVERS.
        f = cypherpunkctl.ServerFees.__new__(cypherpunkctl.ServerFees)
        f.se, f.uid, f.front_uid, f.maintenance, f.lab = server_egress, 1001, None, False, False
        f.profile = dict(role="exit", network=dict(relay_endpoint="198.51.100.1:443"))
        f.cfg = dict(core=dict(listen="198.51.100.2:4444"))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CPVPN_STRICT_NTS_SERVERS", None)
            rules = f.egress_text()
            self.assertIn("tcp dport 4460 accept", rules)
            self.assertIn("udp dport 123 accept", rules)
        with mock.patch.dict(os.environ, {"CPVPN_STRICT_NTS_SERVERS": "162.159.200.1,162.159.200.123"}):
            strict = f.egress_text()
            self.assertIn("ip daddr { 162.159.200.1, 162.159.200.123 } tcp dport 4460 accept", strict)
            self.assertNotIn("\n  udp dport 123 accept\n", strict)

    def test_mesh_cli_accepts_shared_import_witness_flags(self):
        import inspect

        import mesh

        src = inspect.getsource(mesh.main)
        self.assertIn('"--witness-keys"', src)
        self.assertIn('"--witness-quorum"', src)

    def test_three_tier_security_levels_and_hardwareless_vault_vm_session_signer(self):
        import session_signer
        import vault_vm

        # 1. No hardware key detected -> only Standard (hardwareless vault-vm) is available & recommended.
        env_no_hw = vault_vm.SecurityEnvironment(
            hardware_keys=(), tpm2_usable=False, qubes_available=False, kvm_available=False, signing_vm_configured=False
        )
        rep = vault_vm.evaluate_tiers(env_no_hw)
        self.assertEqual(rep["recommended"], "standard")
        self.assertEqual(vault_vm.select_tier("standard", env_no_hw)["protection_mode"], "vault-vm")
        with self.assertRaisesRegex(vault_vm.VaultVmError, "unavailable"):
            vault_vm.select_tier("safer", env_no_hw)
        with self.assertRaisesRegex(vault_vm.VaultVmError, "unavailable"):
            vault_vm.select_tier("safest", env_no_hw)

        # 2. Hardware key + Qubes/KVM isolation -> all 3 tiers unlocked, Safest recommended.
        env_full = vault_vm.SecurityEnvironment(
            hardware_keys=("Nitrokey 3",),
            tpm2_usable=True,
            qubes_available=True,
            kvm_available=True,
            signing_vm_configured=False,
        )
        rep_full = vault_vm.evaluate_tiers(env_full)
        self.assertEqual(rep_full["recommended"], "safest")
        self.assertEqual(vault_vm.select_tier("safer", env_full)["protection_mode"], "nitrokey")
        self.assertEqual(vault_vm.select_tier("safest", env_full)["transport"], "qrexec")

        # 3. VaultVmStore enroll + authorize_session + verify_assertion + wrong-passphrase refusal.
        with tempfile.TemporaryDirectory() as td:
            vault_dir = Path(td) / "vault"
            with self.assertRaisesRegex(vault_vm.VaultVmError, "at least"):
                vault_vm.VaultVmStore.enroll(vault_dir, "short", scrypt_n=1 << 14)
            meta = vault_vm.VaultVmStore.enroll(vault_dir, "cypherpunk-vault-passphrase!", scrypt_n=1 << 14)
            stmt = b"session-auth-statement-test"
            secret, opened_meta, assertion = vault_vm.VaultVmStore.authorize_session(
                vault_dir, stmt, "cypherpunk-vault-passphrase!"
            )
            self.assertEqual(len(secret), 32)
            self.assertEqual(opened_meta["mode"], "vault-vm")
            vault_vm.VaultVmStore.verify_assertion(meta["consent_public"], stmt, assertion)
            with self.assertRaises(vault_vm.VaultVmError):
                vault_vm.VaultVmStore.authorize_session(vault_dir, stmt, "wrong-passphrase-12345")
            with self.assertRaises(vault_vm.VaultVmError):
                vault_vm.VaultVmStore.verify_assertion(meta["consent_public"], b"tampered", assertion)

            # End-to-end session_signer.sign() works seamlessly in hardwareless vault-vm mode!
            import json
            from cryptography.hazmat.primitives.asymmetric import mldsa
            import keyguard
            import managed_profile as mp

            state = Path(td) / "state"
            mp.lab_setup(state, "192.0.2.1:443", "198.51.100.2:4444")
            client_dir = state / "client"
            outer_key = mp.load_keys(client_dir, ["outer"])["outer"]
            sealed = keyguard.seal_bytes(secret, opened_meta, "outer", mp.binding(client_dir, "outer"), outer_key)
            keyguard.atomic(client_dir / "outer-key.sealed.json", json.dumps(sealed).encode())
            (client_dir / "outer-key.der").unlink()
            keyguard.atomic(
                client_dir / "protection.json",
                json.dumps({"mode": "vault-vm", "vault": str(vault_dir)}).encode(),
            )
            sess_key = mldsa.MLDSA65PrivateKey.generate()
            spki_hex = (
                sess_key.public_key()
                .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                .hex()
            )
            reply = session_signer.sign(
                client_dir,
                {"outer": spki_hex},
                passphrase_fn=lambda: "cypherpunk-vault-passphrase!",
            )
            self.assertEqual(reply["protection_mode"], "vault-vm")
            self.assertIn("outer", reply["leaves"])


if __name__ == "__main__":
    unittest.main()

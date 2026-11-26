"""End-to-end tests for onion-only shielded testnet checkout and dual independent watchers."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from threading import Thread
import unittest

from cryptography.hazmat.primitives.asymmetric import mldsa

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from checkout_policy import CheckoutError  # noqa: E402
from checkout_service import (  # noqa: E402
    CheckoutService,
    TorOnionBridge,
    prepare_signer_dir,
    purchase_blind_batch,
    run_signer,
)
from shared_admission import Cohort, EPOCH_SECONDS, ROLES, ReplayLedger, admit, binding_message  # noqa: E402
from zcash_watchers import (  # noqa: E402
    make_http_watcher,
    orchard_note_commitment,
)


class MockWatcherServer:
    """Local HTTP watcher server mimicking one independent Zcash testnet operator."""

    def __init__(self, ivk: bytes, records: dict):
        self.ivk = ivk
        self.records = records
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(n).decode("utf-8"))
                key = (req["txid"], req["receiver"])
                rec = parent.records.get(key)
                if rec is None:
                    body = json.dumps({"found": False}).encode()
                    self.send_response(404)
                else:
                    txid = bytes.fromhex(rec["txid"])
                    bhash = bytes.fromhex(rec["block_hash"])
                    recv = bytes.fromhex(rec["receiver"])
                    proof = orchard_note_commitment(
                        parent.ivk, txid, bhash, rec["height"], recv, rec["amount"]
                    )
                    payload = {**rec, "found": True, "decryption_proof": proof.hex()}
                    body = json.dumps(payload).encode()
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/orchard-note"
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Shut down the local mock watcher HTTP server."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class TestOnionCheckout(unittest.TestCase):
    """End-to-end verification of onion-only shielded testnet checkout and watchers."""

    @classmethod
    def setUpClass(cls):
        """Stage the pinned Privacy Pass blind-RSA signer once for the test class."""
        cls.tmp = tempfile.TemporaryDirectory(prefix="cpvpn-checkout-node-")
        cls.signer = prepare_signer_dir(Path(cls.tmp.name))
        cls.issuer_keys = run_signer(cls.signer, {"op": "keygen"})

    @classmethod
    def tearDownClass(cls):
        """Clean up the temporary signer directory."""
        cls.tmp.cleanup()

    def test_disabled_by_default_and_loopback_only_bind(self):
        """Checkout stays disabled by default and refuses non-loopback bind addresses."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with self.assertRaisesRegex(CheckoutError, "disabled"):
                CheckoutService(
                    ledger_path=root / "c1.sqlite",
                    issuer_name="issuer.vpn.test",
                    pool_name="pool.vpn.test",
                    issuer_keys=self.issuer_keys,
                    signer_script=self.signer,
                    watchers=(),
                    enable_testnet_pilot=False,
                )
            with self.assertRaisesRegex(CheckoutError, "127.0.0.1"):
                CheckoutService(
                    ledger_path=root / "c2.sqlite",
                    issuer_name="issuer.vpn.test",
                    pool_name="pool.vpn.test",
                    issuer_keys=self.issuer_keys,
                    signer_script=self.signer,
                    watchers=(),
                    bind_host="0.0.0.0",  # noqa: S104 - verifying rejection of non-loopback bind
                    enable_testnet_pilot=True,
                )

    def test_end_to_end_blind_checkout_dual_watchers_and_redemption(self):
        """Dual-watcher confirmation mints 8 redeemable blind tokens; replay/reorg/transparent fail."""
        ivk = os.urandom(32)
        records_a, records_b = {}, {}
        srv_a = MockWatcherServer(ivk, records_a)
        srv_b = MockWatcherServer(ivk, records_b)
        watcher_a = make_http_watcher(operator="operator-alpha", url=srv_a.url, ivk=ivk)
        watcher_b = make_http_watcher(operator="operator-beta", url=srv_b.url, ivk=ivk)
        fixed_now = 10 * EPOCH_SECONDS + 100
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            service = CheckoutService(
                ledger_path=root / "checkout.sqlite",
                issuer_name="issuer.vpn.test",
                pool_name="pool.vpn.test",
                issuer_keys=self.issuer_keys,
                signer_script=self.signer,
                watchers=(watcher_a, watcher_b),
                enable_testnet_pilot=True,
                now_fn=lambda: fixed_now,
            )
            service.start()
            try:
                # 1. Successful dual-watcher confirmed Orchard testnet payment -> 8 valid blind tokens.
                txid = os.urandom(32)
                bhash = os.urandom(32)

                def pay_confirmed(order_resp):
                    rec = {
                        "network": "testnet",
                        "pool": "orchard",
                        "txid": txid.hex(),
                        "block_hash": bhash.hex(),
                        "height": 2_900_000,
                        "tip_height": 2_900_012,
                        "receiver": order_resp["receiver"],
                        "amount": order_resp["price_zat"],
                    }
                    records_a[(txid.hex(), order_resp["receiver"])] = rec
                    records_b[(txid.hex(), order_resp["receiver"])] = rec
                    return txid

                batch = purchase_blind_batch(
                    host="127.0.0.1",
                    port=service.port,
                    signer_script=self.signer,
                    pay_fn=pay_confirmed,
                    allow_loopback_test=True,
                )
                # No order_id or txid leaked into exported client batch.
                self.assertEqual(set(batch), {"issuer_name", "pool_name", "epoch", "issuer_spki", "pairs"})
                self.assertEqual(batch["epoch"], 11)
                self.assertEqual(len(batch["pairs"]), 4)

                # Redeem all 8 unblinded tokens through shared_admission.admit() in the next epoch.
                spki = bytes.fromhex(batch["issuer_spki"])
                cohorts = tuple(Cohort("issuer.vpn.test", "pool.vpn.test", role, 11, spki) for role in ROLES)
                ledgers = [ReplayLedger(root / f"{role}.sqlite", role) for role in ROLES]
                for ledger in ledgers:
                    ledger.initialize()
                for pair in batch["pairs"]:
                    for tok_hex, cohort, ledger in zip(pair, cohorts, ledgers, strict=True):
                        token = bytes.fromhex(tok_hex)
                        sk = mldsa.MLDSA65PrivateKey.generate()
                        hop, chan, ckey = os.urandom(32), os.urandom(32), os.urandom(32)
                        proof = sk.sign(binding_message(cohort, token, hop, chan, ckey))
                        expiry = admit(
                            cohort,
                            ledger,
                            token,
                            11 * EPOCH_SECONDS,
                            hop_key_id=hop,
                            channel_binding=chan,
                            carrier_key=ckey,
                            session_key=sk.public_key(),
                            proof=proof,
                        )
                        self.assertGreater(expiry, 11 * EPOCH_SECONDS)

                # 2. Reusing the same txid on a new order is rejected.
                with self.assertRaisesRegex(CheckoutError, "already used"):
                    purchase_blind_batch(
                        host="127.0.0.1",
                        port=service.port,
                        signer_script=self.signer,
                        pay_fn=pay_confirmed,
                        allow_loopback_test=True,
                    )

                # 3. Watcher disagreement (simulated reorg on watcher B) is rejected.
                txid2 = os.urandom(32)

                def pay_disagree(order_resp):
                    rec_a = {
                        "network": "testnet",
                        "pool": "orchard",
                        "txid": txid2.hex(),
                        "block_hash": (b"\xaa" * 32).hex(),
                        "height": 2_900_000,
                        "tip_height": 2_900_012,
                        "receiver": order_resp["receiver"],
                        "amount": order_resp["price_zat"],
                    }
                    rec_b = {**rec_a, "block_hash": (b"\xbb" * 32).hex()}
                    records_a[(txid2.hex(), order_resp["receiver"])] = rec_a
                    records_b[(txid2.hex(), order_resp["receiver"])] = rec_b
                    return txid2

                with self.assertRaisesRegex(CheckoutError, "disagree"):
                    purchase_blind_batch(
                        host="127.0.0.1",
                        port=service.port,
                        signer_script=self.signer,
                        pay_fn=pay_disagree,
                        allow_loopback_test=True,
                    )

                # 4. Mainnet or transparent payment is rejected.
                txid3 = os.urandom(32)

                def pay_transparent(order_resp):
                    rec = {
                        "network": "testnet",
                        "pool": "transparent",
                        "txid": txid3.hex(),
                        "block_hash": (b"\xcc" * 32).hex(),
                        "height": 2_900_000,
                        "tip_height": 2_900_012,
                        "receiver": order_resp["receiver"],
                        "amount": order_resp["price_zat"],
                    }
                    records_a[(txid3.hex(), order_resp["receiver"])] = rec
                    records_b[(txid3.hex(), order_resp["receiver"])] = rec
                    return txid3

                with self.assertRaisesRegex(CheckoutError, "payment confirmation unavailable|not confirmed"):
                    purchase_blind_batch(
                        host="127.0.0.1",
                        port=service.port,
                        signer_script=self.signer,
                        pay_fn=pay_transparent,
                        allow_loopback_test=True,
                    )
            finally:
                service.stop()
                srv_a.stop()
                srv_b.stop()

    def test_tor_v3_onion_provisioning(self):
        """Isolated Tor process provisions a valid v3 .onion address for loopback checkout."""
        if shutil.which("tor") is None:
            self.skipTest("tor not installed")
        with tempfile.TemporaryDirectory(prefix="cpvpn-tor-hs-") as td:
            root = Path(td)
            bridge = TorOnionBridge(target_port=18080, root=root)
            try:
                onion = bridge.start(wait_bootstrap=False, timeout=20.0)
                self.assertTrue(onion.endswith(".onion"))
                self.assertEqual(len(onion), 62)  # 56-char Tor v3 onion + ".onion"
            finally:
                bridge.stop()


if __name__ == "__main__":
    unittest.main()

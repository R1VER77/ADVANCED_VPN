"""Verification, channel binding and durable replay tests for shared access."""

from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, rsa

import shared_admission as shared
import mesh
from shared_pool import DIRECTORY_DOMAIN, SharedPool
from shared_wallet import CreditWallet, PAIRS_PER_BATCH


class SharedAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.spki = shared.SPKI_PREFIX + cls.issuer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.ledger = shared.ReplayLedger(Path(directory.name) / "entry.sqlite", "entry")
        self.ledger.initialize()
        self.cohort = shared.Cohort("issuer.vpn.test", "pool.vpn.test", "entry", 1, self.spki)
        self.session = mldsa.MLDSA65PrivateKey.generate()
        self.hop = secrets.token_bytes(32)
        self.channel = secrets.token_bytes(32)
        self.carrier = secrets.token_bytes(32)

    def token(self, cohort):
        body = (
            shared.TOKEN_TYPE
            + secrets.token_bytes(32)
            + hashlib.sha256(cohort.challenge).digest()
            + hashlib.sha256(self.spki).digest()
        )
        return body + self.issuer.sign(body, shared.PSS, hashes.SHA384())

    def accept(self, token, *, channel=None, now=shared.EPOCH_SECONDS, ledger=None, cohort=None):
        proof = self.session.sign(shared.binding_message(self.cohort, token, self.hop, self.channel, self.carrier))
        return shared.admit(
            cohort or self.cohort,
            ledger or self.ledger,
            token,
            now,
            hop_key_id=self.hop,
            channel_binding=channel or self.channel,
            carrier_key=self.carrier,
            session_key=self.session.public_key(),
            proof=proof,
        )

    def test_rfc9578_public_token_vector(self):
        path = Path(__file__).with_name("testdata") / "shared_admission_rfc9578.json"
        vector = json.loads(path.read_text())
        token, challenge, key = (bytes.fromhex(vector[name]) for name in ("token", "token_challenge", "pkI"))
        self.assertEqual(len(shared.verify_token(token, challenge, key)), 32)
        with self.assertRaisesRegex(shared.AdmissionError, "signature"):
            shared.verify_token(token[:-1] + bytes([token[-1] ^ 1]), challenge, key)

    def test_scheduled_epoch_and_wrong_channel_do_not_consume_token(self):
        token = self.token(self.cohort)
        with self.assertRaisesRegex(shared.AdmissionError, "inactive"):
            self.accept(token, now=shared.EPOCH_SECONDS - 1)
        with self.assertRaisesRegex(shared.AdmissionError, "session proof"):
            self.accept(token, channel=secrets.token_bytes(32))
        self.assertEqual(self.accept(token, now=self.cohort.expires - 30), self.cohort.expires)
        with self.assertRaisesRegex(shared.AdmissionError, "inactive"):
            self.accept(token, now=self.cohort.expires)

    def test_a_classical_session_key_cannot_replace_mldsa(self):
        token = self.token(self.cohort)
        key = ed25519.Ed25519PrivateKey.generate()
        proof = key.sign(shared.binding_message(self.cohort, token, self.hop, self.channel, self.carrier))
        with self.assertRaisesRegex(shared.AdmissionError, "must be ML-DSA-65"):
            shared.admit(
                self.cohort,
                self.ledger,
                token,
                shared.EPOCH_SECONDS,
                hop_key_id=self.hop,
                channel_binding=self.channel,
                carrier_key=self.carrier,
                session_key=key.public_key(),
                proof=proof,
            )
        self.assertEqual(self.accept(token), shared.EPOCH_SECONDS + shared.SESSION_SECONDS)

    def test_tokens_are_bound_to_a_pool_role_and_full_issuer_key(self):
        exit_cohort = shared.Cohort("issuer.vpn.test", "pool.vpn.test", "exit", 1, self.spki)
        with self.assertRaisesRegex(shared.AdmissionError, "inactive"):
            self.accept(self.token(self.cohort), cohort=exit_cohort)
        with self.assertRaisesRegex(shared.AdmissionError, "policy"):
            self.accept(self.token(exit_cohort))
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_spki = shared.SPKI_PREFIX + other.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
        other_cohort = shared.Cohort("issuer.vpn.test", "pool.vpn.test", "entry", 1, other_spki)
        with self.assertRaisesRegex(shared.AdmissionError, "policy"):
            self.accept(self.token(self.cohort), cohort=other_cohort)

    def test_concurrent_redeem_records_one_digest_and_survives_restart(self):
        token = self.token(self.cohort)

        def redeem():
            try:
                self.accept(token, ledger=shared.ReplayLedger(self.ledger.path, "entry"))
                return True
            except shared.AdmissionError as error:
                self.assertEqual(str(error), "token already redeemed")
                return False

        with ThreadPoolExecutor(max_workers=6) as pool:
            self.assertEqual(sum(pool.map(lambda _: redeem(), range(12))), 1)
        with sqlite3.connect(self.ledger.path) as db:
            self.assertEqual(
                db.execute("SELECT * FROM spent").fetchall(),
                [(shared.verify_token(token, self.cohort.challenge, self.spki), self.cohort.expires)],
            )
        with self.assertRaisesRegex(shared.AdmissionError, "already redeemed"):
            self.accept(token, ledger=shared.ReplayLedger(self.ledger.path, "entry"))

    def test_wrong_role_database_and_removed_ledger_fail_closed(self):
        role_mismatch = shared.ReplayLedger(self.ledger.path, "exit")
        with self.assertRaisesRegex(shared.AdmissionError, "wrong role"):
            role_mismatch.consume(secrets.token_bytes(32), self.cohort.expires)
        self.ledger.path.unlink()
        with self.assertRaisesRegex(shared.AdmissionError, "unavailable"):
            self.accept(self.token(self.cohort))
        self.assertFalse(self.ledger.path.exists())

    def test_retirement_prunes_digests_without_reopening_expired_epochs(self):
        old = self.token(self.cohort)
        self.accept(old)
        self.ledger.retire_expired(now=self.cohort.expires)
        with sqlite3.connect(self.ledger.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM spent").fetchone(), (0,))
        with self.assertRaisesRegex(shared.AdmissionError, "permanently retired"):
            self.accept(old)  # a clock rollback must not make an old token usable

    def test_wallet_verifies_and_seals_a_batch_and_reserves_pairs_once(self):
        exit_cohort = shared.Cohort("issuer.vpn.test", "pool.vpn.test", "exit", 1, self.spki)
        pairs = [(self.token(self.cohort), self.token(exit_cohort)) for _ in range(PAIRS_PER_BATCH)]
        path = self.ledger.path.with_name("credits.json")
        wallet = CreditWallet(path, path.with_name("vault"), self.cohort, exit_cohort)
        secret = secrets.token_bytes(32)
        meta = {"credential": "Y3JlZGVudGlhbA==", "salt": "c2FsdA=="}
        with patch("keyguard.hardware_secret", return_value=(secret, meta)) as unlock:
            with self.assertRaisesRegex(shared.AdmissionError, "duplicate"):
                wallet.import_batch([pairs[0]] * PAIRS_PER_BATCH)
            unlock.assert_not_called()
            wallet.import_batch(pairs)
            with self.assertRaisesRegex(shared.AdmissionError, "already been imported"):
                wallet.import_batch(pairs)
            with self.assertRaisesRegex(shared.AdmissionError, "outside"):
                wallet.take_pair(shared.EPOCH_SECONDS - 1)
            for entry, exit in pairs:
                self.assertNotIn(entry.hex(), path.read_text())
                self.assertEqual(wallet.take_pair(shared.EPOCH_SECONDS), (entry, exit))
            self.assertEqual(unlock.call_count, 1 + PAIRS_PER_BATCH)
            with self.assertRaisesRegex(shared.AdmissionError, "empty"):
                wallet.take_pair(shared.EPOCH_SECONDS)

    def test_signed_pool_excludes_own_nodes_and_does_not_fall_back(self):
        now = shared.EPOCH_SECONDS
        signer = mldsa.MLDSA65PrivateKey.generate()

        def node(role, provider, country, operator):
            key = mldsa.MLDSA65PrivateKey.generate()
            public = key.public_key().public_bytes_raw()
            return mesh.sign_descriptor(
                dict(
                    schema=1,
                    node_public_key=base64.b64encode(public).decode(),
                    node_id=mesh.member_id(public),
                    roles=[role],
                    provider=provider,
                    country=country,
                    operator=operator,
                    published=now,
                    expires=now + 5,
                ),
                key,
            )

        own = node("entry", "oci", "DE", "own")
        entry = node("entry", "gcp", "US", "shared-entry")
        exit = node("exit", "host", "CH", "shared-exit")
        manifest = dict(
            schema=1,
            pool="pool.vpn.test",
            issuer="issuer.vpn.test",
            epoch=1,
            issuer_spki=base64.b64encode(self.spki).decode(),
            nodes=[own, entry, exit],
        )
        manifest["signature"] = base64.b64encode(signer.sign(DIRECTORY_DOMAIN + mesh.canonical(manifest))).decode()
        pool = SharedPool.verify(manifest, signer.public_key(), now)
        self.assertEqual(pool.route(now, excluded_operators={"own"}), (entry, exit))
        with self.assertRaisesRegex(shared.AdmissionError, "no independent"):
            pool.route(now, excluded_operators={"own", "shared-entry"})
        with self.assertRaisesRegex(shared.AdmissionError, "no independent"):
            pool.route(now + 5)
        with self.assertRaisesRegex(shared.AdmissionError, "verification failed"):
            SharedPool.verify(dict(manifest, pool="different.vpn.test"), signer.public_key(), now)

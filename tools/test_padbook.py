"""padbook.py: one-time pad books from the Nitrokey, sealed in transit and at rest.

The hardware is injected: a fake `nitropy` (subprocess result) and a fixed hmac-secret
with a keyguard-shaped vault record. The real Nitrokey is exercised by hand (design doc
§6), never in CI.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dcnet_reference
import keyguard
import padbook

SECRET = bytes(range(32))
META = dict(salt=base64.b64encode(b"s" * 32).decode(), credential=base64.b64encode(b"credential").decode())
NOW = 1_800_000_000.0  # a fixed clock
ROUND = padbook.round_now(NOW)


def fake_nitropy(stream):
    """A `nitropy nk3 rng` stand-in printing hex from `stream`, as the tool does."""

    def run(argv, **_):
        assert argv[1:4] == ["nk3", "rng", "--length"], argv
        n = int(argv[4])
        data = stream.read(n)
        return subprocess.CompletedProcess(argv, 0, data.hex() + "\n", "")

    return run


class Stream:
    def __init__(self, data):
        self.data, self.at = data, 0

    def read(self, n):
        out = self.data[self.at : self.at + n]
        self.at += n
        return out


def book_header(rounds=8, first=ROUND):
    return padbook.header(7, "alice", "bob", first, rounds)


class SourceTests(unittest.TestCase):
    def test_bytes_come_from_the_nitrokey_in_health_tested_chunks(self):
        data = os.urandom(3 * padbook.NITROKEY_CHUNK + 100)
        got = padbook.nitrokey_bytes(len(data), run=fake_nitropy(Stream(data)))
        self.assertEqual(got, data)

    def test_a_stuck_or_biased_source_is_refused(self):
        stuck = bytes(padbook.NITROKEY_CHUNK)
        with self.assertRaises(padbook.HealthError):
            padbook.nitrokey_bytes(len(stuck), run=fake_nitropy(Stream(stuck)))
        biased = bytes([7, 1, 2, 3] * (padbook.WINDOW // 4)) * 8  # 7 is 1/4 of every window
        with self.assertRaises(padbook.HealthError):
            padbook.nitrokey_bytes(len(biased), run=fake_nitropy(Stream(biased)))
        chunk = os.urandom(padbook.NITROKEY_CHUNK)
        with self.assertRaises(padbook.HealthError):  # the same chunk twice
            padbook.nitrokey_bytes(2 * len(chunk), run=fake_nitropy(Stream(chunk + chunk)))

    def test_short_output_or_a_failed_call_is_refused(self):
        def short(argv, **_):
            return subprocess.CompletedProcess(argv, 0, "abcd\n", "")

        with self.assertRaises(RuntimeError):
            padbook.nitrokey_bytes(64, run=short)

        def fails(argv, **_):
            return subprocess.CompletedProcess(argv, 1, "", "No Nitrokey 3 device found")

        with self.assertRaisesRegex(RuntimeError, "no random data"):
            padbook.nitrokey_bytes(64, run=fails)

    def test_without_nitropy_nothing_falls_back_to_software(self):
        with self.assertRaisesRegex(RuntimeError, "no software fallback"):
            padbook.nitropy_path("/nonexistent/nitropy")


class ContributionTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public = keyguard.kem_keypair()

    def test_a_sealed_contribution_opens_only_for_its_recipient_and_book(self):
        h = book_header()
        mine = os.urandom(h["rounds"] * padbook.PAD)
        env = padbook.seal_contribution(h, "alice", "in_person", self.public, mine)
        book, sender, delivery, raw, got = padbook.open_contribution(env, "bob", self.private)
        self.assertEqual((book, sender, delivery, raw, got), (h, "alice", "in_person", None, mine))
        other_private, _ = keyguard.kem_keypair()
        with self.assertRaises(Exception):
            padbook.open_contribution(env, "bob", other_private)
        for at in (0, 40, len(env) // 2, len(env) - 1):  # any changed byte breaks it
            flipped = bytearray(env)
            flipped[at] ^= 1
            with self.assertRaises(Exception):
                padbook.open_contribution(bytes(flipped), "bob", self.private)
        with self.assertRaises(ValueError):  # not a member of this pair
            padbook.open_contribution(env, "carol", self.private)
        with self.assertRaises(ValueError):  # alice's own copy is opened only as her own
            padbook.open_contribution(
                padbook.seal_contribution(h, "alice", "in_person", self.public, mine), "alice", self.private
            )

    def test_an_envelope_shows_nothing_and_its_size_only_the_bucket(self):
        h = padbook.header(7, "alice-unique-name", "bob-unique-name", ROUND, 8)
        a = padbook.seal_contribution(h, "alice-unique-name", "in_person", self.public, bytes(8 * 64), dict(h_used=2.0))
        b = padbook.seal_contribution(h, "alice-unique-name", "in_person", self.public, bytes(8 * 64), dict(h_used=2.0))
        for needle in (b"alice-unique-name", b"in_person", b"first_round", b"h_used"):
            self.assertFalse(needle in a, needle)
        same = sum(1 for p, q in zip(a, b, strict=True) if p == q)
        self.assertLess(same / len(a), 0.01)  # two identical contributions share no bytes
        longer = padbook.header(7, "alice-unique-name", "bob-unique-name", ROUND, 2000)
        c = padbook.seal_contribution(longer, "alice-unique-name", "remote", self.public, bytes(2000 * 64))
        self.assertEqual(len(a), len(c))  # 8 rounds and 2000 rounds: the same 30-day bucket

    def test_the_book_is_the_xor_of_both_contributions(self):
        a, b = os.urandom(128), os.urandom(128)
        pads = padbook.combine(a, b)
        self.assertEqual(bytes(x ^ y for x, y in zip(pads, b, strict=True)), a)
        with self.assertRaises(ValueError):
            padbook.combine(a, b[:64])

    def test_an_edge_is_information_theoretic_only_with_a_raw_source_handed_over_in_person(self):
        raw = dict(h_used=1.0)
        c = padbook.edge_claim
        it, comp = "information-theoretic", "computational"
        self.assertEqual(
            c({"alice": dict(delivery="in_person", raw=raw), "bob": dict(delivery="remote", raw=None)}), it
        )
        self.assertEqual(
            c({"alice": dict(delivery="remote", raw=None), "bob": dict(delivery="in_person", raw=raw)}), it
        )
        # Nitrokey output alone (ChaCha8), even in person: computational.
        self.assertEqual(
            c({"alice": dict(delivery="in_person", raw=None), "bob": dict(delivery="in_person", raw=None)}), comp
        )
        # A raw source that only travelled over the network: computational.
        self.assertEqual(
            c({"alice": dict(delivery="remote", raw=raw), "bob": dict(delivery="in_person", raw=None)}), comp
        )

    def test_the_kem_private_key_is_sealed_under_the_nitrokey(self):
        public, value = padbook.kem_keygen(SECRET, META)
        self.assertNotIn(b"private", json.dumps(value).encode())
        private = padbook.kem_private(SECRET, META, value)
        env = padbook.seal_contribution(book_header(1), "alice", "remote", public, os.urandom(64))
        self.assertEqual(len(padbook.open_contribution(env, "bob", private)[4]), 64)
        with self.assertRaises(Exception):  # another Nitrokey's secret opens nothing
            padbook.kem_private(bytes(32), META, value)


class AtRestTests(unittest.TestCase):
    def make(self, rounds=8, first=ROUND):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        h = book_header(rounds, first)
        self.pads = os.urandom(rounds * padbook.PAD)
        d = Path(self.tmp.name) / "book"
        contributions = {
            "alice": dict(delivery="in_person", raw=dict(h_used=1.0)),
            "bob": dict(delivery="remote", raw=None),
        }
        padbook.write_book(d, h, contributions, self.pads, SECRET, META, os.urandom(32))
        return d, h

    def test_pads_are_not_on_disk_in_the_clear(self):
        d, _ = self.make()
        on_disk = (d / "pads.bin").read_bytes() + (d / "book.bin").read_bytes()
        for k in range(8):
            self.assertNotIn(self.pads[k * 64 : k * 64 + 16], on_disk)
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(d / "pads.bin").st_mode & 0o777, 0o600)

    def test_each_round_is_handed_out_once_and_its_record_zeroed(self):
        d, h = self.make()
        b = padbook.Book(d, SECRET, META, clock=lambda: NOW)
        self.assertEqual(b.take(ROUND + 2), self.pads[128:192])
        with self.assertRaises(ValueError):  # used
            b.take(ROUND + 2)
        with self.assertRaises(ValueError):  # skipped, so burned
            b.take(ROUND + 1)
        records = (d / "pads.bin").read_bytes()
        self.assertEqual(records[: 3 * padbook.RECORD], bytes(3 * padbook.RECORD))
        self.assertNotEqual(records[3 * padbook.RECORD : 4 * padbook.RECORD], bytes(padbook.RECORD))
        # A reopened book (a new session) carries on where it was.
        again = padbook.Book(d, SECRET, META, clock=lambda: NOW)
        self.assertEqual(again.rounds_left(), 5)
        self.assertEqual(again.take(ROUND + 3), self.pads[192:256])
        self.assertEqual(again.claim(), "information-theoretic")

    def test_restoring_an_old_state_opens_no_used_round(self):
        d, _ = self.make()
        old_state = (d / "book.bin").read_bytes()
        b = padbook.Book(d, SECRET, META, clock=lambda: NOW)
        b.take(ROUND)
        b.take(ROUND + 1)
        # A backup of the old state, restored: the used records are gone, so the old keys
        # decrypt nothing, and a later clock refuses the rounds anyway.
        (d / "book.bin").write_bytes(old_state)
        rewound = padbook.Book(d, SECRET, META, clock=lambda: NOW)
        with self.assertRaises(Exception):
            rewound.take(ROUND)
        later = padbook.Book(d, SECRET, META, clock=lambda: NOW + 10 * padbook.ROUND_SECS)
        with self.assertRaises(ValueError):
            later.take(ROUND + 2)

    def test_a_used_up_book_stops(self):
        d, _ = self.make(rounds=2)
        b = padbook.Book(d, SECRET, META, clock=lambda: NOW)
        b.take(ROUND + 1)
        with self.assertRaisesRegex(ValueError, "used up"):
            b.take(ROUND + 2)

    def test_the_book_opens_only_with_the_nitrokey_secret(self):
        d, _ = self.make()
        with self.assertRaises(Exception):
            padbook.Book(d, bytes(32), META, clock=lambda: NOW)


class OpaqueAtRestTests(unittest.TestCase):
    """Nothing about a book is readable without the Nitrokey (TrueCrypt's principle: a
    random salt, then everything encrypted), and two ciphers guard it."""

    def make(self, rounds=8):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        h = padbook.header(4242, "alice-unique-name", "bob-unique-name", ROUND, rounds)
        contributions = {
            "alice-unique-name": dict(delivery="in_person", raw=dict(h_used=1.0, source="jitter")),
            "bob-unique-name": dict(delivery="remote", raw=None),
        }
        pads = bytes(rounds * padbook.PAD)  # all zero: any structure would show
        d = Path(tmp.name) / "book"
        padbook.write_book(d, h, contributions, pads, SECRET, META, bytes(32))
        return d

    def test_no_header_field_is_readable_at_rest(self):
        d = self.make()
        blob = b"".join(p.read_bytes() for p in d.iterdir())
        # Long, distinctive strings only: a short one turns up by chance in megabytes of noise.
        for needle in (b"alice-unique-name", b"bob-unique-name", b"in_person", b"first_round", b"contributions"):
            self.assertFalse(needle in blob, needle)
        # Byte values look uniform even though every pad is zero.
        counts = [blob.count(bytes([v])) for v in range(256)]
        self.assertLess(max(counts) / (len(blob) / 256), 1.3)

    def test_two_identical_books_share_no_bytes_on_disk(self):
        a, b = self.make(), self.make()
        for name in (padbook.BOOK_FILE, padbook.PADS_FILE):
            x, y = (a / name).read_bytes(), (b / name).read_bytes()
            same = sum(1 for p, q in zip(x, y, strict=False) if p == q)
            self.assertLess(same / len(x), 0.01)

    def test_the_pad_file_grows_in_30_day_buckets(self):
        d = self.make(rounds=8)
        self.assertEqual((d / padbook.PADS_FILE).stat().st_size, padbook.BUCKET_ROUNDS * padbook.RECORD)

    def test_both_ciphers_of_the_cascade_are_needed(self):
        keys, nonce = os.urandom(64), os.urandom(12)
        c = padbook.cascade_seal(keys, nonce, b"pad" * 20, b"aad")
        self.assertEqual(padbook.cascade_open(keys, nonce, c, b"aad"), b"pad" * 20)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        inner = ChaCha20Poly1305(keys[32:]).decrypt(nonce, c, b"aad")  # one layer off
        self.assertNotEqual(inner, b"pad" * 20)  # still AES-GCM ciphertext
        self.assertEqual(AESGCM(keys[:32]).decrypt(nonce, inner, b"aad"), b"pad" * 20)
        for bad in (os.urandom(32) + keys[32:], keys[:32] + os.urandom(32)):  # either key wrong
            with self.assertRaises(Exception):
                padbook.cascade_open(bad, nonce, c, b"aad")


class ChainTests(unittest.TestCase):
    def make(self, first=ROUND):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        h = padbook.chain_header(7, "alice", "bob", first)
        self.seed = os.urandom(32)
        d = Path(self.tmp.name) / "chain"
        contributions = {"alice": dict(delivery="remote", raw=None), "bob": dict(delivery="remote", raw=None)}
        padbook.write_chain(d, h, contributions, self.seed, SECRET, META)
        return d

    def test_chain_pads_match_the_rust_and_reference_construction(self):
        seed = dcnet_reference.sha256(b"vec-ratchet-0-1")
        rust_vector = bytes.fromhex(
            json.loads(Path(padbook.__file__).parents[1].joinpath("docs/evidence/DCNET_VECTORS.json").read_text())[
                "ratchet_pad_01"
            ]
        )
        s = seed
        for _ in range(77 - 70):
            s = padbook.chain_next(s)
        self.assertEqual(padbook.chain_pad(s, 77), rust_vector)
        self.assertEqual(dcnet_reference.ratchet_pad(seed, 70, 77), rust_vector)

    def test_a_chain_round_is_taken_once_and_its_state_moves_on(self):
        d = self.make()
        c = padbook.Chain(d, SECRET, META, clock=lambda: NOW)
        expected = dcnet_reference.ratchet_pad(self.seed, ROUND, ROUND + 2)
        self.assertEqual(c.take(ROUND + 2), expected)
        with self.assertRaises(ValueError):
            c.take(ROUND + 2)
        with self.assertRaises(ValueError):
            c.take(ROUND + 1)
        again = padbook.Chain(d, SECRET, META, clock=lambda: NOW)
        self.assertEqual(again.take(ROUND + 3), dcnet_reference.ratchet_pad(self.seed, ROUND, ROUND + 3))
        self.assertEqual(again.claim(), "computational")

    def test_the_seed_is_not_at_rest_in_the_clear_and_opens_only_with_the_nitrokey(self):
        d = self.make()
        self.assertNotIn(self.seed.hex().encode(), (d / "book.bin").read_bytes())
        self.assertNotIn(self.seed, (d / "book.bin").read_bytes())
        with self.assertRaises(Exception):
            padbook.Chain(d, bytes(32), META, clock=lambda: NOW)
        with self.assertRaises(ValueError):  # a chain is not a book
            padbook.Book(d, SECRET, META, clock=lambda: NOW)

    def test_a_chain_contribution_is_a_32_byte_seed(self):
        private, public = keyguard.kem_keypair()
        h = padbook.chain_header(7, "alice", "bob", ROUND)
        env = padbook.seal_contribution(h, "alice", "remote", public, os.urandom(32))
        self.assertEqual(len(padbook.open_contribution(env, "bob", private)[4]), 32)
        with self.assertRaises(ValueError):
            padbook.seal_contribution(h, "alice", "remote", public, os.urandom(64))
        both = {"alice": dict(delivery="in_person", raw=dict(h_used=4.0)), "bob": dict(delivery="in_person", raw=None)}
        self.assertEqual(padbook.edge_claim(both, "chain"), "computational")


class RawSourceTests(unittest.TestCase):
    def test_health_cutoffs_follow_sp800_90b(self):
        # RCT: C = 1 + ceil(20 / H).
        self.assertEqual(padbook.rct_cutoff(1.0), 21)
        self.assertEqual(padbook.rct_cutoff(2.0), 11)
        # APT: the smallest C with P(count >= C) <= 2^-20 for Binomial(512, 2^-H).
        import math

        for h in (1.0, 2.0, 4.0):
            c, p = padbook.apt_cutoff(h), 2.0**-h

            def tail(k, p=p):
                return sum(math.comb(512, j) * p**j * (1 - p) ** (512 - j) for j in range(k, 513))

            self.assertLessEqual(tail(c), 2.0**-20)
            self.assertGreater(tail(c - 1), 2.0**-20)

    def test_health_tests_catch_a_stuck_or_biased_raw_source(self):
        good = os.urandom(65536)
        padbook.raw_health(good, 2.0)
        with self.assertRaises(padbook.HealthError):
            padbook.raw_health(good[:100] + bytes(30) + good[130:], 2.0)  # 30 equal in a row
        biased = bytes([0, 1, 2, 3] * 16384)  # in every 512-window the first value is 1/4
        with self.assertRaises(padbook.HealthError):
            padbook.raw_health(biased, 4.0)

    def test_toeplitz_is_the_matrix_product_and_linear(self):
        import random

        rng = random.Random(1)  # noqa: S311 (reproducible test data, not keys)
        n, m = 64, 16
        seed = rng.getrandbits(n + m - 1)
        x, y = rng.getrandbits(n), rng.getrandbits(n)
        got = padbook.toeplitz(x, n, seed, m)
        naive = 0
        for i in range(m):
            bit = 0
            for j in range(n):
                bit ^= ((seed >> (i + j)) & 1) & ((x >> j) & 1)
            naive |= bit << i
        self.assertEqual(got, naive)
        self.assertEqual(padbook.toeplitz(x ^ y, n, seed, m), got ^ padbook.toeplitz(y, n, seed, m))

    def test_the_extractor_outputs_what_the_entropy_allows(self):
        # 1024 samples x 1 bit counted = 1024 bits, minus 2 x 64 = 896 bits = 112 bytes.
        self.assertEqual(padbook.extracted_bits(1.0), 896)
        with self.assertRaises(ValueError):
            padbook.extracted_bits(0.1)  # 102 bits < 128: nothing can be extracted
        m = padbook.extracted_bits(1.0)
        seed = os.urandom((padbook.toeplitz_seed_bits(m) + 7) // 8)
        samples = os.urandom(3 * padbook.JITTER_BLOCK + 10)
        out = padbook.extract(samples, 1.0, seed)
        self.assertEqual(len(out), 3 * 112)
        with self.assertRaises(ValueError):
            padbook.extract(samples, 1.0, seed[:100])

    def test_a_low_entropy_source_still_extracts_to_balanced_bits(self):
        import random

        rng = random.Random(7)  # noqa: S311 (reproducible test data, not keys)
        # Each sample: one of 4 values, 2 bits of min-entropy; extract counting 1 bit.
        samples = bytes(rng.choice((3, 9, 200, 77)) for _ in range(64 * padbook.JITTER_BLOCK))
        m = padbook.extracted_bits(1.0)
        seed = bytes(rng.getrandbits(8) for _ in range((padbook.toeplitz_seed_bits(m) + 7) // 8))
        out = padbook.extract(samples, 1.0, seed)
        ones = sum(bin(b).count("1") for b in out) / (8 * len(out))
        self.assertAlmostEqual(ones, 0.5, delta=0.01)

    def test_jitter_samples_read_the_recorder_and_honour_its_health_failures(self):
        def recorder(argv, **_):
            count, prefix = int(argv[1]), argv[3]
            Path(prefix + "-0001.data").write_text("\n".join(str(1000 + 7 * k) for k in range(count)))
            return subprocess.CompletedProcess(argv, 0, "Processing\n", "")

        got = padbook.jitter_samples(5, "/x/jitterentropy-hashtime", run=recorder)
        self.assertEqual(got, bytes((1000 + 7 * k) & 0xFF for k in range(5)))

        def failing(argv, **kw):
            recorder(argv, **kw)
            return subprocess.CompletedProcess(
                argv, 0, "The main context encountered the following health testing failure(s): RCT\n", ""
            )

        with self.assertRaises(padbook.HealthError):
            padbook.jitter_samples(5, "/x/r", run=failing)

    def test_assess_asks_ea_non_iid_for_the_line_it_parses(self):
        # Verbatim ea_non_iid output tails (this laptop, 2026-11-16): only verbosity 3
        # prints "Assessed min entropy"; with one -v the parser finds nothing.
        verbosity_3 = (
            "H_bitstring = 0.91276296472462859\nH_bitstring Per Symbol = 7.3021037177970287\n"
            "H_original = 6.6383993693288019\nAssessed min entropy: 6.6383993693288019\n"
        )
        verbosity_1 = "\nH_original: 6.638399\nH_bitstring: 0.912763\nmin(H_original, 8 X H_bitstring): 6.638399\n"
        self.assertAlmostEqual(padbook.parse_ea_non_iid(verbosity_3), 6.6383993693288019)
        with self.assertRaises(ValueError):
            padbook.parse_ea_non_iid(verbosity_1)
        import inspect

        self.assertIn('"-a", "-v", "-v", "-v"', inspect.getsource(padbook.main))

    def test_the_assessed_min_entropy_is_read_from_ea_non_iid(self):
        out = "H_original: 2.4\nH_bitstring: 0.33\nmin(H_original, 8 X H_bitstring): 2.4\nAssessed min entropy: 2.387\n"
        self.assertEqual(padbook.parse_ea_non_iid(out), 2.387)
        with self.assertRaises(ValueError):
            padbook.parse_ea_non_iid("no result")


class ContributionMixTests(unittest.TestCase):
    def test_kernel_and_nitrokey_are_drawn_before_the_noise_and_all_three_are_xored(self):
        order = []
        k, nk, raw = os.urandom(64), os.urandom(64), os.urandom(64)

        def getrandom(n):
            order.append("kernel")
            return k[:n]

        def nitrokey(n, _nitropy):
            order.append("nitrokey")
            return nk[:n]

        def rawfn(n, _raw, _recorder):
            order.append("jitter")
            return raw[:n]

        got = padbook.contribution_bytes(64, dict(h_used=1.0), "/x/rec", None, getrandom, nitrokey, rawfn)
        self.assertEqual(order, ["kernel", "nitrokey", "jitter"])
        self.assertEqual(got, bytes(a ^ b ^ c for a, b, c in zip(k, nk, raw, strict=True)))
        # Without a raw source: kernel XOR Nitrokey, and no jitter is recorded.
        order.clear()
        self.assertEqual(
            padbook.contribution_bytes(64, None, None, None, getrandom, nitrokey, rawfn),
            bytes(a ^ b for a, b in zip(k, nk, strict=True)),
        )
        self.assertEqual(order, ["kernel", "nitrokey"])


class MemoryWipeTests(unittest.TestCase):
    """Key material is held in buffers that are zeroed in place, on use, exit and signals."""

    def test_a_secret_reads_back_and_is_zeroed_in_place_by_wipe(self):
        s = padbook.Secret(b"k" * 32)
        self.assertEqual(s.bytes, b"k" * 32)
        buf = s._buf  # the very buffer, not a copy
        s.wipe()
        self.assertEqual(bytes(buf), bytes(32))
        with self.assertRaises(ValueError):
            _ = s.bytes
        s.wipe()  # idempotent

    def test_wipe_all_zeroes_every_live_secret(self):
        a, b = padbook.Secret(b"a" * 16), padbook.Secret(b"b" * 16)
        bufs = (a._buf, b._buf)
        padbook._wipe_all()
        self.assertEqual([bytes(x) for x in bufs], [bytes(16), bytes(16)])

    def test_a_terminating_signal_wipes_and_then_runs_the_previous_handler(self):
        import signal

        calls = []
        old = signal.signal(signal.SIGHUP, lambda *_: calls.append("previous"))
        saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            padbook._install_wipe_on_exit()
            s = padbook.Secret(b"z" * 8)
            buf = s._buf
            os.kill(os.getpid(), signal.SIGHUP)
            self.assertEqual(bytes(buf), bytes(8))
            self.assertEqual(calls, ["previous"])
        finally:
            signal.signal(signal.SIGHUP, old)
            for sig, h in saved.items():
                signal.signal(sig, h)

    def test_book_and_chain_take_zero_their_chain_state_in_ram(self):
        seen = []
        real = padbook._memzero

        def spy(buf):
            seen.append(buf)
            real(buf)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(padbook, "_memzero", spy):
            h = padbook.header(7, "alice", "bob", ROUND, 4)
            padbook.write_book(Path(tmp) / "b", h, {}, os.urandom(4 * 64), SECRET, META, os.urandom(32))
            with padbook.Book(Path(tmp) / "b", SECRET, META, clock=lambda: NOW) as b:
                b.take(ROUND + 1)
                key_buf = b.keys._buf
            self.assertEqual(bytes(key_buf), bytes(len(key_buf)))  # `with` wiped the file key
            hc = padbook.chain_header(7, "alice", "bob", ROUND)
            padbook.write_chain(Path(tmp) / "c", hc, {}, os.urandom(32), SECRET, META)
            padbook.Chain(Path(tmp) / "c", SECRET, META, clock=lambda: NOW).take(ROUND + 2)
        self.assertEqual(len(seen), 2)
        for buf in seen:
            self.assertEqual(len(buf), 32)
            self.assertEqual(bytes(buf), bytes(32))

    def test_harden_makes_the_process_non_dumpable(self):
        code = (
            "import sys; sys.path.insert(0, %r); import padbook, ctypes; padbook.harden();"
            "print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))" % str(Path(padbook.__file__).parent)
        )
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "0")  # PR_GET_DUMPABLE


if __name__ == "__main__":
    unittest.main()

"""Tests for tools/padstore.py: the deniable layered pad store.

Layer keys are fixed bytes here (on the hardware: the Nitrokey's hmac-secret for a salt
derived from the layer's passphrase). Books inside layers use padbook unchanged.
"""

import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import padbook
import padstore

SECRET = bytes(range(32))
META = dict(salt=base64.b64encode(b"s" * 32).decode(), credential=base64.b64encode(b"credential").decode())
DECOY, HIDDEN, DEEPER = (bytes([n]) * 32 for n in (1, 2, 3))
NOW = 1_800_000_000.0


def byte_chi2(data):
    """Pearson chi-square of the byte histogram against uniform (255 degrees of freedom:
    mean 255, sd about 22.6)."""
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    e = len(data) / 256
    return sum((c - e) ** 2 / e for c in counts)


def book_header(rounds=8):
    first = padbook.round_now(NOW)
    return padbook.header(7, "alice", "bob", first, rounds)


class Layers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "store.bin"
        padstore.create(self.path, mib=1)
        self.store = padstore.Store(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def stack(self, store=None):
        store = store or self.store
        d = store.first_layer(DECOY)
        h = store.add_layer(HIDDEN, d)
        return d, h, store.add_layer(DEEPER, h)

    def test_each_key_opens_its_own_layer_and_a_wrong_key_none(self):
        d, h, x = self.stack()
        for key, level in ((DECOY, 0), (HIDDEN, 1), (DEEPER, 2)):
            self.assertEqual(self.store.open(key).header["level"], level)
        self.assertEqual(len({d.slot, h.slot, x.slot}), 3)
        with self.assertRaises(LookupError):
            self.store.open(bytes(32))

    def test_files_round_trip_and_survive_reopening(self):
        d, _, _ = self.stack()
        data = os.urandom(3 * padstore.PAYLOAD + 17)
        d.write("f", data)
        again = padstore.Store(self.path).open(DECOY)
        self.assertEqual(again.read("f"), data)
        self.assertEqual(
            again.read_at("f", padstore.PAYLOAD - 5, 10), data[padstore.PAYLOAD - 5 : padstore.PAYLOAD + 5]
        )
        again.write_at("f", padstore.PAYLOAD - 3, b"abcdef")
        want = bytearray(data)
        want[padstore.PAYLOAD - 3 : padstore.PAYLOAD + 3] = b"abcdef"
        self.assertEqual(padstore.Store(self.path).open(DECOY).read("f"), bytes(want))
        with self.assertRaises(ValueError):
            again.write_at("f", len(data) - 1, b"xx")

    def test_a_hidden_layers_multi_block_file_keeps_its_order(self):
        _, h, _ = self.stack()
        data = os.urandom(5 * padstore.PAYLOAD + 3)  # hidden layers allocate from the back
        h.write("f", data)
        lay = padstore.Store(self.path).open(HIDDEN)
        self.assertEqual(lay.read("f"), data)
        self.assertEqual(
            lay.read_at("f", 2 * padstore.PAYLOAD + 1, 9), data[2 * padstore.PAYLOAD + 1 : 2 * padstore.PAYLOAD + 10]
        )

    def test_the_top_layer_sees_every_lower_block_and_never_overwrites_one(self):
        d, h, x = self.stack()
        d.write("decoy", os.urandom(20 * padstore.PAYLOAD))
        h = self.store.open(HIDDEN)  # reopened: now knows the decoy's blocks
        h.write("hidden", os.urandom(20 * padstore.PAYLOAD))
        x = self.store.open(DEEPER)
        before = {k: self.store.open(k).read(n) for k, n in ((DECOY, "decoy"), (HIDDEN, "hidden"))}
        free = self.store.blocks - len(x.used())
        x.write("deep", os.urandom(free * padstore.PAYLOAD))  # fill every free block
        with self.assertRaises(RuntimeError):
            x.write("more", b"x")
        self.assertEqual(self.store.open(DECOY).read("decoy"), before[DECOY])
        self.assertEqual(self.store.open(HIDDEN).read("hidden"), before[HIDDEN])

    def test_the_decoy_fills_from_the_front_and_hidden_layers_from_the_back(self):
        d, h, _ = self.stack()
        d.write("a", b"1")
        h = self.store.open(HIDDEN)
        h.write("b", b"2")
        self.assertEqual(d.header["files"]["a"]["extents"][0][0], 0)
        self.assertEqual(h.header["files"]["b"]["extents"][0][0], self.store.blocks - 1)

    def test_a_rewrite_scrubs_the_old_blocks(self):
        d, _, _ = self.stack()
        d.write("f", b"first version")
        old = padstore._blocks(d.header["files"]["f"]["extents"])
        before = {b: self.store._read(padstore.SLOTS * padstore.SLOT + b * padstore.BLOCK, padstore.BLOCK) for b in old}
        d.write("f", b"second version")
        new = padstore._blocks(d.header["files"]["f"]["extents"])
        self.assertFalse(set(old) & set(new))
        for b, ct in before.items():
            now = self.store._read(padstore.SLOTS * padstore.SLOT + b * padstore.BLOCK, padstore.BLOCK)
            self.assertNotEqual(now, ct)
            with self.assertRaises(Exception):
                d._get(b)  # random bytes now, not a block of the layer

    def test_a_store_with_one_layer_and_one_with_three_look_alike(self):
        other = Path(self.tmp.name) / "other.bin"
        padstore.create(other, mib=1)
        one, three = padstore.Store(other), self.store
        one.first_layer(DECOY).write("decoy", os.urandom(30 * padstore.PAYLOAD))
        d, h, x = self.stack(three)
        d.write("decoy", os.urandom(30 * padstore.PAYLOAD))
        three.open(HIDDEN).write("hidden", os.urandom(30 * padstore.PAYLOAD))
        a, b = one.path.read_bytes(), three.path.read_bytes()
        self.assertEqual(len(a), len(b))
        slots = padstore.SLOTS * padstore.SLOT
        for blob in (a, b, a[:slots], b[:slots]):
            self.assertLess(byte_chi2(blob), 255 + 6 * 22.6)  # six sd: random-looking
        # With the decoy key, both stores give the same view: one layer, level 0, its file.
        for s in (one, three):
            lay = s.open(DECOY)
            self.assertEqual((lay.header["level"], lay.names(), lay.header["lower"]), (0, ["decoy"], []))

    def test_an_unlock_tries_every_slot_however_many_layers_exist(self):
        other = Path(self.tmp.name) / "other.bin"
        padstore.create(other, mib=1)
        one = padstore.Store(other)
        one.first_layer(DECOY)
        self.stack()
        for s in (one, self.store):
            with mock.patch.object(s, "_try_slot", wraps=s._try_slot) as tried:
                s.open(DECOY)
            self.assertEqual(tried.call_count, padstore.SLOTS)
            with mock.patch.object(s, "_try_slot", wraps=s._try_slot) as tried, self.assertRaises(LookupError):
                s.open(bytes(32))
            self.assertEqual(tried.call_count, padstore.SLOTS)

    def test_nothing_readable_in_the_file(self):
        d, h, _ = self.stack()
        d.write("decoy-book/book.bin", b'{"kind": "book", "partner": "alice"}' * 20)
        blob = self.path.read_bytes()
        for needle in (b"decoy-book", b'"kind"', b"alice", b'"level"', b'"lower"', b'"extents"', DECOY, HIDDEN):
            self.assertNotIn(needle, blob)

    def test_a_layer_header_with_too_many_files_is_refused_not_truncated(self):
        d, _, _ = self.stack()
        with self.assertRaises(RuntimeError):
            for i in range(10_000):
                d.write("file-with-a-long-name-%05d" % i, b"x")
        self.assertEqual(padstore.Store(self.path).open(DECOY).header["level"], 0)  # still opens

    def test_the_layer_salt_depends_on_the_passphrase_only(self):
        self.assertEqual(padstore.layer_salt("correct horse"), padstore.layer_salt("correct horse"))
        self.assertNotEqual(padstore.layer_salt("correct horse"), padstore.layer_salt("correct horsf"))
        self.assertEqual(len(padstore.layer_salt("x")), 32)
        with self.assertRaises(ValueError):
            padstore.layer_salt("")

    def test_a_file_that_is_not_a_store_is_refused(self):
        bad = Path(self.tmp.name) / "bad.bin"
        bad.write_bytes(os.urandom(padstore.SLOTS * padstore.SLOT + 100))
        with self.assertRaises(ValueError):
            padstore.Store(bad)
        with self.assertRaises(FileExistsError):
            padstore.create(self.path, mib=1)


class BooksInLayers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "store.bin"
        padstore.create(self.path, mib=12)  # a book is padded to a 30-day bucket (8.3 MB)
        store = padstore.Store(self.path)
        d = store.first_layer(DECOY)
        store.add_layer(HIDDEN, d)
        self.store = store
        self.h = book_header()
        self.pads = os.urandom(self.h["rounds"] * padbook.PAD)

    def tearDown(self):
        self.tmp.cleanup()

    def files(self, key, name="b1"):
        return padstore.LayerFiles(self.store.open(key), name)

    def test_a_book_in_a_hidden_layer_gives_the_same_pads_as_in_a_directory(self):
        seed = os.urandom(32)
        contributions = {"alice": dict(delivery="in_person", raw=None)}
        padbook.write_book(self.files(HIDDEN), self.h, contributions, self.pads, SECRET, META, seed)
        plain = Path(self.tmp.name) / "plain"
        padbook.write_book(plain, self.h, contributions, self.pads, SECRET, META, seed)
        first = self.h["first_round"]
        for r in range(first, first + 3):
            in_layer = padbook.Book(self.files(HIDDEN), SECRET, META, clock=lambda: NOW).take(r)
            in_dir = padbook.Book(plain, SECRET, META, clock=lambda: NOW).take(r)
            self.assertEqual(in_layer, in_dir)
            self.assertEqual(in_layer, self.pads[(r - first) * padbook.PAD : (r - first + 1) * padbook.PAD])
        book = padbook.Book(self.files(HIDDEN), SECRET, META, clock=lambda: NOW)
        with self.assertRaises(ValueError):
            book.take(first)  # used
        self.assertEqual(book.rounds_left(), self.h["rounds"] - 3)

    def test_used_records_are_zeroed_inside_the_layer(self):
        padbook.write_book(self.files(HIDDEN), self.h, {}, self.pads, SECRET, META, os.urandom(32))
        first = self.h["first_round"]
        padbook.Book(self.files(HIDDEN), SECRET, META, clock=lambda: NOW).take(first + 1)
        layer = self.store.open(HIDDEN)
        self.assertEqual(layer.read_at("b1/" + padbook.PADS_FILE, 0, 2 * padbook.RECORD), bytes(2 * padbook.RECORD))

    def test_a_chain_works_in_a_layer(self):
        seed = os.urandom(32)
        h = padbook.chain_header(7, "alice", "bob", padbook.round_now(NOW))
        padbook.write_chain(self.files(DECOY, "c1"), h, {}, seed, SECRET, META)
        pad = padbook.Chain(self.files(DECOY, "c1"), SECRET, META, clock=lambda: NOW).take(h["first_round"])
        self.assertEqual(pad, padbook.chain_pad(seed, h["first_round"]))

    def test_the_decoy_cannot_see_the_hidden_book(self):
        padbook.write_book(self.files(HIDDEN), self.h, {}, self.pads, SECRET, META, os.urandom(32))
        decoy = self.store.open(DECOY)
        self.assertEqual(decoy.names(), [])
        with self.assertRaises(FileNotFoundError):
            padbook.Book(padstore.LayerFiles(decoy, "b1"), SECRET, META)

    def test_a_book_name_cannot_be_reused_or_escape_its_prefix(self):
        padbook.write_book(self.files(HIDDEN), self.h, {}, self.pads, SECRET, META, os.urandom(32))
        with self.assertRaises(FileExistsError):
            padbook.write_book(self.files(HIDDEN), self.h, {}, self.pads, SECRET, META, os.urandom(32))
        with self.assertRaises(ValueError):
            padstore.LayerFiles(self.store.open(HIDDEN), "a/b")


if __name__ == "__main__":
    unittest.main()

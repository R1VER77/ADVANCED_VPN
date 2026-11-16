"""Tests for tools/zkid.py: the forward-private membership secret at rest.

The Nitrokey is injected as a fixed hmac-secret (as test_padbook). The hash vectors come
from the prototype's own functions (research/zk-membership host `h`/`step`/`walk`/`leaf`
and the guest's nullifier), built and run in Rust against sha2 0.10.9.
"""

import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import padbook
import zkid

SECRET = bytes(range(32))
META = dict(salt=base64.b64encode(b"s" * 32).decode(), credential=base64.b64encode(b"credential").decode())
DAY = 86400
S0 = bytes(range(32))
START, LIFE = 20400, 365
# research/zk-membership: s0 = 0..31, lifetime 365, start 20400, epoch 20405, scope 0x11 * 32
RUST = dict(
    leaf="18a4c2590f55186c53dea99093d6a730bfc4ab68d5bed0b84abb03ee0a3e44e1",
    x5="e78c8b64ef76d755a5cd88856a7efd8c52f295db3141a82bceb7ecbad68fc67f",
    nullifier="806f88f42582dc9d3875385f0a2f5a3327b658ce4b5e666fe273dfe8a7fe593b",
)


class Vectors(unittest.TestCase):
    def test_the_hashes_match_the_prototype_in_rust(self):
        self.assertEqual(zkid.leaf(S0, LIFE).hex(), RUST["leaf"])
        x5 = zkid.walk(S0, 5)
        self.assertEqual(x5.hex(), RUST["x5"])
        self.assertEqual(zkid.leaf_from(x5, START + 5, START, LIFE).hex(), RUST["leaf"])
        self.assertEqual(zkid.nullifier(x5, START + 5, b"\x11" * 32).hex(), RUST["nullifier"])

    def test_a_later_secret_does_not_fold_to_an_earlier_epochs_leaf(self):
        x6 = zkid.walk(S0, 6)
        self.assertNotEqual(zkid.leaf_from(x6, START + 5, START, LIFE).hex(), RUST["leaf"])

    def test_epochs_outside_the_tree_are_refused(self):
        with self.assertRaises(ValueError):
            zkid.leaf_from(S0, START - 1, START, LIFE)
        with self.assertRaises(ValueError):
            zkid.leaf_from(S0, START + LIFE + 1, START, LIFE)


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "id"

    def tearDown(self):
        self.tmp.cleanup()

    def open(self, day):
        return zkid.Identity(self.dir, SECRET, META, clock=lambda: day * DAY)

    def test_enrol_returns_the_leaf_and_holds_the_start_epoch(self):
        leaf = zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        self.assertEqual(leaf.hex(), RUST["leaf"])
        with self.open(START) as ident:
            self.assertEqual(ident.epoch, START)
            self.assertEqual(ident.secret(), S0)

    def test_stepping_forward_erases_the_earlier_secret_from_the_store(self):
        zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        with self.open(START + 5) as ident:
            self.assertEqual(ident.secret().hex(), RUST["x5"])
        # Reopened: the store now holds epoch 5 and cannot give any earlier secret.
        with self.open(START + 5) as ident:
            self.assertEqual(ident.epoch, START + 5)
            for e in (START, START + 4):
                with self.assertRaises(ValueError):
                    ident.secret(e)
            stored = bytes.fromhex(ident.info["state"]["x"])
        self.assertEqual(stored.hex(), RUST["x5"])
        for k in range(5):
            self.assertNotEqual(stored, zkid.walk(S0, k))

    def test_the_store_is_saved_before_the_secret_is_returned(self):
        zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        seen = []
        real = padbook._save
        with mock.patch.object(
            padbook, "_save", side_effect=lambda *a: (seen.append(a[3]["state"]["epoch"]), real(*a))
        ):
            with self.open(START + 3) as ident:
                x = ident.secret()
        self.assertEqual(seen, [START + 3])
        self.assertEqual(x, zkid.walk(S0, 3))

    def test_the_tree_end_is_refused(self):
        zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        with self.open(START + LIFE + 1) as ident:
            with self.assertRaises(ValueError):
                ident.secret()

    def test_late_enrolment_keeps_nothing_before_today(self):
        leaf = zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=(START + 10) * DAY)
        self.assertEqual(leaf.hex(), RUST["leaf"])
        with self.open(START + 10) as ident:
            self.assertEqual(ident.epoch, START + 10)
            self.assertEqual(ident.secret(), zkid.walk(S0, 10))

    def test_nothing_readable_at_rest_and_another_key_opens_nothing(self):
        zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        blob = (self.dir / padbook.BOOK_FILE).read_bytes()
        for needle in (zkid.KIND.encode(), b'"lifetime"', b'"epoch"', S0, S0.hex().encode(), b"%d" % START):
            self.assertNotIn(needle, blob)
        with self.assertRaises(Exception):
            zkid.Identity(self.dir, bytes(32), META)

    def test_a_padbook_book_is_not_an_identity(self):
        self.dir.mkdir(mode=0o700)
        salt = b"x" * padbook.SALT
        padbook._save(self.dir, salt, padbook.file_keys(SECRET, META, salt), dict(book=dict(kind="book"), state={}))
        with self.assertRaises(ValueError):
            zkid.Identity(self.dir, SECRET, META)

    def test_enrol_refuses_an_existing_store_and_an_ended_tree(self):
        zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        with self.assertRaises(FileExistsError):
            zkid.enrol(self.dir, START, LIFE, SECRET, META, s0=S0, now=START * DAY)
        with self.assertRaises(ValueError):
            zkid.enrol(Path(self.tmp.name) / "late", START, LIFE, SECRET, META, s0=S0, now=(START + LIFE + 1) * DAY)

    def test_enrol_draws_s0_from_the_hardware_sources_by_default(self):
        with mock.patch.object(padbook, "contribution_bytes", return_value=S0) as draw:
            leaf = zkid.enrol(self.dir, START, LIFE, SECRET, META, now=START * DAY)
        draw.assert_called_once_with(32)
        self.assertEqual(leaf.hex(), RUST["leaf"])


if __name__ == "__main__":
    unittest.main()

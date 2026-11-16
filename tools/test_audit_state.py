"""Audit regressions: global one-use state, stale handles and durable replacement."""

import base64
import concurrent.futures
import json
import multiprocessing
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import keyguard
import padbook
import padstore
import zkid

SECRET = bytes(range(32))
META = dict(salt=base64.b64encode(b"s" * 32).decode(), credential=base64.b64encode(b"credential").decode())
NOW = 1_800_000_000.0
ROUND = padbook.round_now(NOW)


def consume(path, kind, barrier, results):
    """A separate process opens before racing its first consumption."""
    cls = padbook.Chain if kind == "chain" else padbook.Book
    with cls(path, SECRET, META, clock=lambda: NOW) as handle:
        barrier.wait(timeout=15)
        try:
            handle.take(ROUND)
            results.put("pad")
        except ValueError:
            results.put("refused")


class StateTransactions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "state"

    def chain(self):
        padbook.write_chain(self.path, padbook.chain_header(7, "alice", "bob", ROUND), {}, b"x" * 32, SECRET, META)

    def book(self):
        padbook.write_book(
            self.path, padbook.header(7, "alice", "bob", ROUND, 8), {}, os.urandom(8 * 64), SECRET, META, b"x" * 32
        )

    def test_two_preopened_chain_handles_cannot_reuse_a_round(self):
        self.chain()
        with (
            padbook.Chain(self.path, SECRET, META, clock=lambda: NOW) as a,
            padbook.Chain(self.path, SECRET, META, clock=lambda: NOW) as b,
        ):
            a.take(ROUND)
            with self.assertRaises(ValueError):
                b.take(ROUND)
            self.assertEqual(b.state["next"], 1)

    def test_stale_identity_cannot_overwrite_newer_durable_epoch(self):
        zkid.enrol(self.path, 20400, 365, SECRET, META, s0=b"z" * 32, now=20400 * 86400)
        with zkid.Identity(self.path, SECRET, META) as a, zkid.Identity(self.path, SECRET, META) as b:
            a.secret(20410)
            with self.assertRaises(ValueError):
                b.secret(20405)
            self.assertEqual(b.epoch, 20410)

    def test_book_consumers_serialize_the_read_advance_and_erase(self):
        self.book()
        with (
            padbook.Book(self.path, SECRET, META, clock=lambda: NOW) as a,
            padbook.Book(self.path, SECRET, META, clock=lambda: NOW) as b,
        ):
            ready, release, entered = threading.Event(), threading.Event(), threading.Event()
            advance = a._advance

            def slow(*args):
                ready.set()
                if not release.wait(5):
                    raise TimeoutError("test coordination")
                advance(*args)

            a._advance = slow

            def second():
                entered.set()
                try:
                    b.take(ROUND)
                    return "pad"
                except ValueError:
                    return "refused"

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                one = pool.submit(a.take, ROUND)
                self.assertTrue(ready.wait(5))
                two = pool.submit(second)
                self.assertTrue(entered.wait(5))
                try:
                    with self.assertRaises(concurrent.futures.TimeoutError):
                        two.result(timeout=0.2)
                finally:
                    release.set()
                self.assertEqual(len(one.result(timeout=5)), 64)
                self.assertEqual(two.result(timeout=5), "refused")

    def test_multiprocess_consumers_release_exactly_one_pad(self):
        for kind in ["chain", "book"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                self.path = Path(temp) / "state"
                self.chain() if kind == "chain" else self.book()
                ctx = multiprocessing.get_context("spawn")
                barrier, results = ctx.Barrier(4), ctx.Queue()
                workers = [ctx.Process(target=consume, args=(self.path, kind, barrier, results)) for _ in range(4)]
                for worker in workers:
                    worker.start()
                try:
                    answers = [results.get(timeout=20) for _ in workers]
                    self.assertEqual(answers.count("pad"), 1)
                    self.assertEqual(answers.count("refused"), 3)
                finally:
                    for worker in workers:
                        worker.join(timeout=10)
                        if worker.is_alive():
                            worker.kill()
                            worker.join()
                        self.assertEqual(worker.exitcode, 0)
                    results.close()

    def test_atomic_replacement_syncs_the_directory_after_rename(self):
        file = Path(self.tmp.name) / "file"
        events = []
        sync, replace = keyguard.os.fsync, keyguard.os.replace

        def synced(fd):
            events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return sync(fd)

        def renamed(*args):
            events.append("rename")
            return replace(*args)

        with (
            mock.patch.object(keyguard.os, "fsync", side_effect=synced),
            mock.patch.object(keyguard.os, "replace", side_effect=renamed),
        ):
            keyguard.atomic(file, b"new")
        self.assertEqual(events, ["file", "rename", "directory"])

    def test_failed_durable_commit_releases_no_pad(self):
        self.chain()
        with padbook.Chain(self.path, SECRET, META, clock=lambda: NOW) as a:
            with mock.patch.object(keyguard, "atomic", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    a.take(ROUND)
            # No successful consumption occurred; the durable original is reloaded.
            self.assertEqual(len(a.take(ROUND)), 64)
            with self.assertRaises(ValueError):
                a.take(ROUND)


class ContainerRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "store"
        padstore.create(self.path, mib=1)
        self.store = padstore.Store(self.path)
        self.layer = self.store.first_layer(SECRET)
        self.layer.write("f", b"original")

    def test_torn_inactive_header_preserves_prior_root(self):
        write = self.store._write

        def torn(offset, data):
            if offset < padstore.SLOTS * padstore.SLOT:
                write(offset, data[: len(data) // 2])
                raise OSError("power loss during header write")
            write(offset, data)

        with mock.patch.object(self.store, "_write", side_effect=torn):
            with self.assertRaises(OSError):
                self.layer.write("f", b"replacement")
        try:
            recovered = padstore.Store(self.path).open(SECRET).read("f")
        except (LookupError, ValueError):
            recovered = None
        self.assertEqual(recovered, b"original")

    def test_failure_at_each_write_or_sync_boundary_keeps_a_valid_file(self):
        # Restore the byte-exact same fixture for each cut; synthetic secrets only.
        original = self.path.read_bytes()
        for method in ["_write", "_sync"]:
            count = [0]
            real = getattr(self.store, method)

            def counted(*args, real=real, count=count):
                count[0] += 1
                return real(*args)

            with mock.patch.object(self.store, method, side_effect=counted):
                self.layer.write("f", b"next")
            for stop in range(1, count[0] + 1):
                with self.subTest(method=method, stop=stop):
                    self.path.write_bytes(original)
                    lay = self.store.open(SECRET)
                    seen = [0]

                    def cut(*args, stop=stop, real=real, seen=seen):
                        seen[0] += 1
                        if seen[0] == stop:
                            raise OSError("simulated crash")
                        return real(*args)

                    with mock.patch.object(self.store, method, side_effect=cut):
                        with self.assertRaises(OSError):
                            lay.write("f", b"next")
                    self.assertIn(padstore.Store(self.path).open(SECRET).read("f"), [b"original", b"next"])
            self.path.write_bytes(original)

    def test_partial_write_is_cow_and_preserves_file_order(self):
        value = os.urandom(4 * padstore.PAYLOAD)
        self.layer.write("large", value)
        replacement = b"X" * (padstore.PAYLOAD + 10)
        offset = padstore.PAYLOAD - 5
        self.layer.write_at("large", offset, replacement)
        self.assertEqual(self.layer.read("large"), value[:offset] + replacement + value[offset + len(replacement) :])

    def test_container_books_also_reject_stale_consumers(self):
        files = padstore.LayerFiles(self.layer, "book")
        padbook.write_chain(files, padbook.chain_header(7, "a", "b", ROUND), {}, b"x" * 32, SECRET, META)
        other = padstore.LayerFiles(padstore.Store(self.path).open(SECRET), "book")
        with (
            padbook.Chain(files, SECRET, META, clock=lambda: NOW) as a,
            padbook.Chain(other, SECRET, META, clock=lambda: NOW) as b,
        ):
            a.take(ROUND)
            with self.assertRaises(ValueError):
                b.take(ROUND)

    def test_independent_header_salts_do_not_expose_pairing(self):
        self.layer.write("f", b"next")
        salts = [self.store._read(i * padstore.SLOT, padstore.SALT) for i in range(padstore.SLOTS)]
        self.assertEqual(len(set(salts)), len(salts))

    def test_unsupported_v1_headers_are_not_rewritten(self):
        # An authenticated old-format header, using the actual v1 KDF and AAD.
        salt, nonce = os.urandom(32), os.urandom(12)
        header = dict(v=1, level=0, data=bytes(64).hex(), files={}, lower=[])
        blob = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        plain = len(blob).to_bytes(4, "big") + blob
        plain = plain.ljust(padstore.HEADER, b"\0")
        keys = padbook._hkdf(SECRET + salt, b"padstore/slot", 64)
        old = salt + nonce + padbook.cascade_seal(keys, nonce, plain, b"padstore/slot")
        self.path.write_bytes(old + os.urandom(self.path.stat().st_size - len(old)))
        before = self.path.read_bytes()
        with self.assertRaises(LookupError):
            self.store.open(SECRET)
        self.assertEqual(self.path.read_bytes(), before)

    def test_torn_partial_data_write_preserves_the_entire_prior_file(self):
        value = os.urandom(3 * padstore.PAYLOAD)
        self.layer.write("large", value)
        write = self.store._write

        def torn(offset, data):
            write(offset, data[: len(data) // 2])
            raise OSError("partial data write")

        with mock.patch.object(self.store, "_write", side_effect=torn):
            with self.assertRaises(OSError):
                self.layer.write_at("large", padstore.PAYLOAD - 4, b"X" * 30)
        try:
            recovered = padstore.Store(self.path).open(SECRET).read("large")
        except Exception:
            recovered = None
        self.assertEqual(recovered, value)

    def test_completed_commit_retires_old_authenticated_root_and_data(self):
        old_active = self.layer.active
        old_blocks = padstore._owned(self.layer.header)
        before = {
            b: self.store._read(padstore.SLOTS * padstore.SLOT + b * padstore.BLOCK, padstore.BLOCK) for b in old_blocks
        }
        self.layer.write("f", b"new")
        self.assertIsNone(self.store._try_slot(old_active, SECRET))
        self.assertIsNotNone(self.store._try_slot(self.layer.active, SECRET))
        for b in old_blocks:
            self.assertNotEqual(
                self.store._read(padstore.SLOTS * padstore.SLOT + b * padstore.BLOCK, padstore.BLOCK), before[b]
            )

    def test_full_store_refuses_a_replacement_without_losing_its_root(self):
        free = self.store.blocks - len(self.layer.used())
        self.layer.write("full", bytes(free * padstore.PAYLOAD))
        with self.assertRaises(RuntimeError):
            self.layer.write("f", b"new")
        self.assertEqual(self.layer.read("f"), b"original")

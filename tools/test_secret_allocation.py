"""Tests for the disjoint, durably consumed secret-material allocation
(tools/secret_allocation.py) - ROADMAP section 6's "Allocate disjoint, durably
consumed material to DC-net masks and session PSKs", the in-sandbox half of
the research review's "pad and transport domains must be disjoint" correction.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import secret_allocation as sa  # noqa: E402

MASTER = bytes(range(32)) * 2  # 64 bytes of test master material


class DomainTests(unittest.TestCase):
    def test_the_two_planes_and_the_blind_half_have_disjoint_domains(self):
        self.assertIn("dcnet-mask", sa.DOMAINS)
        self.assertIn("session-psk", sa.DOMAINS)
        for a in sa.DOMAINS:
            for b in sa.DOMAINS:
                if a != b:
                    self.assertFalse(a.startswith(b) or b.startswith(a), f"prefix domains {a!r} / {b!r}")

    def test_a_prefix_domain_is_refused_at_import_time(self):
        saved = sa.DOMAINS
        try:
            sa.DOMAINS = ("dcnet-mask", "dcnet-mask-v2")
            with self.assertRaisesRegex(sa.Refused, "pairwise non-prefix"):
                sa._check_domains()
        finally:
            sa.DOMAINS = saved

    def test_unknown_domains_are_refused(self):
        for bad in ("transport", "dcnet", "", "DCNET-MASK"):
            with self.assertRaises(sa.Refused):
                sa.allocate(MASTER, bad, 1)


class AllocationTests(unittest.TestCase):
    def test_domains_never_share_material_for_the_same_window(self):
        """The structural disjointness the review demands: every domain's
        derivation carries its own tag inside the KDF info, so two domains
        never agree on a window - not by policy, by derivation."""
        for window in (1, 2, 17, 4096):
            seen = {domain: sa.allocate(MASTER, domain, window) for domain in sa.DOMAINS}
            values = list(seen.values())
            self.assertEqual(len(values), len(set(values)), window)
            self.assertEqual({len(v) for v in values}, {sa.WINDOW_BYTES})

    def test_windows_and_generations_are_distinct_within_a_domain(self):
        first = {sa.allocate(MASTER, "dcnet-mask", w) for w in range(1, 33)}
        self.assertEqual(len(first), 32)
        g1 = sa.allocate(MASTER, "dcnet-mask", 1, generation=1)
        g2 = sa.allocate(MASTER, "dcnet-mask", 1, generation=2)
        self.assertNotEqual(g1, g2)  # a rekey is a rekey, never a reuse

    def test_the_master_never_appears_in_any_derived_window(self):
        for domain in sa.DOMAINS:
            for window in (1, 2, 3):
                material = sa.allocate(MASTER, domain, window)
                self.assertNotEqual(material, MASTER[: sa.WINDOW_BYTES])
                self.assertNotIn(material, (MASTER, MASTER[::-1]))

    def test_bad_masters_windows_and_generations_are_refused(self):
        for master in (b"", b"short", 42, None):
            with self.assertRaises(sa.Refused):
                sa.allocate(master, "dcnet-mask", 1)
        for window in (0, -1, True, "1", 1.5, None):
            with self.assertRaises(sa.Refused):
                sa.allocate(MASTER, "dcnet-mask", window)
        for generation in (0, -1, True, "1", None):
            with self.assertRaises(sa.Refused):
                sa.allocate(MASTER, "dcnet-mask", 1, generation=generation)


class RatchetTests(unittest.TestCase):
    def test_a_ratchet_is_forward_only_and_finite(self):
        r = sa.Ratchet(windows=4)
        self.assertEqual([r.next() for _ in range(3)], [1, 2, 3])
        self.assertTrue(r.exhausted)
        with self.assertRaisesRegex(sa.Refused, "rekey_required"):
            r.next()  # "never runs out" is refused: the fourth window needs a rekey
        self.assertEqual(r.remaining, 0)

    def test_a_ratchet_never_wraps_or_reuses(self):
        r = sa.Ratchet(generation=7, windows=3)
        r.next()
        r.next()
        with self.assertRaises(sa.Refused):
            r.next()
        self.assertEqual((r.generation, r.position), (7, 2))  # no wraparound

    def test_ratchet_bounds_are_enforced(self):
        for bad in (0, -1, 1_000_001, True):
            with self.assertRaises(sa.Refused):
                sa.Ratchet(windows=bad)
        with self.assertRaises(sa.Refused):
            sa.Ratchet(windows=4, position=4)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "consumed.jsonl"

    def test_consumption_is_durable_across_a_reload(self):
        ledger = sa.ConsumptionLedger(self.path)
        material = sa.allocate(MASTER, "session-psk", 1)
        ledger.consume("session-psk", 1, 1, material)
        reopened = sa.ConsumptionLedger(self.path)  # a later process
        self.assertTrue(reopened.consumed("session-psk", 1, 1))
        with self.assertRaisesRegex(sa.Refused, "window_already_consumed"):
            reopened.consume("session-psk", 1, 1, material)

    def test_the_ledger_stores_digests_never_material(self):
        ledger = sa.ConsumptionLedger(self.path)
        material = sa.allocate(MASTER, "dcnet-mask", 5)
        ledger.consume("dcnet-mask", 5, 1, material)
        raw = self.path.read_text()
        self.assertNotIn(material.hex(), raw)
        row = json.loads(raw.strip())
        self.assertEqual(row["digest"], sa.window_digest("dcnet-mask", 5, 1, material))
        self.assertEqual(row["schema"], 1)

    def test_unsafe_and_malformed_ledgers_are_refused(self):
        ledger = sa.ConsumptionLedger(self.path)
        ledger.consume("dcnet-mask", 1, 1, sa.allocate(MASTER, "dcnet-mask", 1))
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(sa.Refused, "unsafe_ledger_file"):
            sa.ConsumptionLedger(self.path)
        os.chmod(self.path, 0o600)
        self.path.write_text("{not json}\n")
        with self.assertRaisesRegex(sa.Refused, "malformed_ledger_row"):
            sa.ConsumptionLedger(self.path)
        self.path.write_text(json.dumps({"schema": 2, "digest": "x" * 64}) + "\n")
        with self.assertRaisesRegex(sa.Refused, "malformed_ledger_row"):
            sa.ConsumptionLedger(self.path)

    def test_a_doubled_digest_in_the_file_is_refused_not_merged(self):
        ledger = sa.ConsumptionLedger(self.path)
        material = sa.allocate(MASTER, "dcnet-mask", 9)
        row = ledger.consume("dcnet-mask", 9, 1, material)
        with open(self.path, "a") as handle:  # a tampered duplicate line
            handle.write(json.dumps(row) + "\n")
        with self.assertRaisesRegex(sa.Refused, "digest_replayed"):
            sa.ConsumptionLedger(self.path)


class ComposedTests(unittest.TestCase):
    def test_allocate_fresh_hands_each_window_to_exactly_one_consumer(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ledger = sa.ConsumptionLedger(Path(tmp.name) / "consumed.jsonl")
        ratchet = sa.Ratchet(generation=3, windows=8)
        seen = []
        for _ in range(4):
            material = sa.allocate_fresh(MASTER, "dcnet-mask", ratchet, ledger)
            seen.append(material)
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(ratchet.position, 4)
        # the consumption is already durable: a second consumer of the same
        # windows, through a fresh ledger object on the same file, is refused
        reopened = sa.ConsumptionLedger(Path(tmp.name) / "consumed.jsonl")
        for window in range(1, 5):
            with self.assertRaisesRegex(sa.Refused, "window_already_consumed"):
                reopened.consume("dcnet-mask", window, 3, sa.allocate(MASTER, "dcnet-mask", window, generation=3))

    def test_exhaustion_stops_the_plane_instead_of_wrapping(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ledger = sa.ConsumptionLedger(Path(tmp.name) / "consumed.jsonl")
        ratchet = sa.Ratchet(windows=3)
        sa.allocate_fresh(MASTER, "session-psk", ratchet, ledger)
        sa.allocate_fresh(MASTER, "session-psk", ratchet, ledger)
        with self.assertRaisesRegex(sa.Refused, "rekey_required"):
            sa.allocate_fresh(MASTER, "session-psk", ratchet, ledger)
        # the honest answer is a rekey with fresh master material, never a wrap
        new_generation = sa.Ratchet(generation=ratchet.generation + 1, windows=3)
        material = sa.allocate_fresh(MASTER, "session-psk", new_generation, ledger)
        self.assertEqual(len(material), sa.WINDOW_BYTES)


if __name__ == "__main__":
    unittest.main()

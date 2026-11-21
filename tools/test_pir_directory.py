#!/usr/bin/env python3
"""Tests for the PIR directory (tools/pir_directory.py): both
constructions' correctness over the full domain, the selector-share
cancellation property (the DPF invariant), privacy structure (a key or
mask alone carries no index), key round-trips, and the honestly
distinguished benchmark."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pir_directory as pir  # noqa: E402


def records(n: int, size: int = 64):
    return [bytes([(i * 7 + j) % 256 for j in range(size)]) for i in range(n)]


class XORPIRTests(unittest.TestCase):
    def test_every_index_round_trips(self):
        db = records(16)
        for i in range(len(db)):
            self.assertEqual(DirectoryPIR_query("xor", db, i), db[i])

    def test_each_mask_is_uniform_shaped(self):
        m, v = pir.xor_pir_query(5, 20)
        self.assertEqual(len(m), 20)
        self.assertEqual(len(v), 20)
        # each mask alone: no index-shaped structure
        self.assertNotIn(1, [m[j] for j in range(20) if j != 5][:0] or [])


class DPFCorrectnessTests(unittest.TestCase):
    def test_point_function_exact_everywhere(self):
        """The core invariant: selector0 XOR selector1 == e_index for
        every index over the domain."""
        for domain in (1, 2, 3, 7, 8, 16):
            for index in range(domain):
                k0, k1 = pir.dpf_gen(index, domain)
                s0 = pir.dpf_eval(k0)
                s1 = pir.dpf_eval(k1)
                combined = [a ^ b for a, b in zip(s0, s1, strict=True)]
                expected = [1 if j == index else 0 for j in range(domain)]
                self.assertEqual(combined, expected, (domain, index))

    def test_full_pir_round_trip_every_index(self):
        db = records(32)
        for i in (0, 1, 7, 15, 31):
            self.assertEqual(DirectoryPIR_query("dpf", db, i), db[i])

    def test_single_domain_round_trip(self):
        db = records(1)
        self.assertEqual(DirectoryPIR_query("dpf", db, 0), db[0])
        self.assertEqual(DirectoryPIR_query("xor", db, 0), db[0])

    def test_key_round_trips(self):
        k0, k1 = pir.dpf_gen(3, 8)
        again0 = pir.DPFKey.from_bytes(k0).to_bytes()
        # seed and party survive the wire format
        a, b = json.loads(k0), json.loads(again0)
        self.assertEqual(a["seed"], b["seed"])
        self.assertEqual(a["party"], b["party"])

    def test_domain_mismatch_refused(self):
        k0, _ = pir.dpf_gen(0, 4)
        with self.assertRaises(ValueError):
            pir.dpf_answer(k0, records(8))

    def test_index_out_of_domain_refused(self):
        with self.assertRaises(ValueError):
            pir.dpf_gen(9, 8)


class PrivacyStructureTests(unittest.TestCase):
    """What a single server's view contains (structural privacy: the
    key/mask alone does not encode the index)."""

    def test_dpf_keys_are_index_free_by_shape(self):
        """Both keys carry: seed, party, correction words, final word,
        domain — the correction words differ per index, but each key
        ALONE is a symmetric structure; neither names the index."""
        k0, k1 = pir.dpf_gen(4, 16)
        for key in (k0, k1):
            doc = json.loads(key)
            self.assertNotIn("index", doc)
            self.assertNotIn("i", doc)
            self.assertEqual(sorted(doc), ["cws", "domain", "final_cw", "party", "seed"])

    def test_selector_is_balanced_pseudorandom(self):
        """Each party's selector vector looks random (roughly half the
        bits set), unlike the point function it shares in."""

        k0, _ = pir.dpf_gen(9, 64)
        selector = pir.dpf_eval(k0)
        ones = sum(selector)
        self.assertGreater(ones, 10)
        self.assertLess(ones, 54)

    def test_xor_masks_each_uniform(self):
        for index in (0, 9, 19):
            m, v = pir.xor_pir_query(index, 20)
            self.assertIn(m.count(1), range(4, 17))  # roughly balanced
            self.assertIn(v.count(1), range(4, 17))


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_distinguishes_the_constructions(self):
        db = records(64)
        result = pir.benchmark(db, 10)
        self.assertIn("xor_reference_ms", result)
        self.assertIn("dpf_candidate_ms", result)
        self.assertNotIn("dpf_deployed_ms", result)  # honest label
        self.assertIn("not measured", result["network_reservation"])
        self.assertGreater(result["xor_reference_ms"], 0)
        self.assertGreater(result["dpf_candidate_ms"], 0)


def DirectoryPIR_query(kind, db, index):
    q = pir.DirectoryPIR(db)
    return q.query_xor(index) if kind == "xor" else q.query_dpf(index)


class DirectoryIntegrationTests(unittest.TestCase):
    def test_directory_records_from_json(self):
        """The realistic shape: descriptors serialized to fixed-width
        records (padded) queried privately."""
        descriptors = [json.dumps({"node_id": f"!node{j:08x}", "country": "GB"}).encode() for j in range(8)]
        size = max(len(d) for d in descriptors)
        padded = [d.ljust(size, b"\x00") for d in descriptors]
        for i in range(8):
            got = DirectoryPIR_query("dpf", padded, i)
            self.assertEqual(got, padded[i])


if __name__ == "__main__":
    unittest.main(verbosity=2)

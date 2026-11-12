#!/usr/bin/env python3
"""Tests for the ephemeral defense database generator (tools/defense_db.py)."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import defense_db as ddb  # noqa: E402


class GenerateTests(unittest.TestCase):
    def test_seeded_generation_is_deterministic(self):
        a = ddb.generate(7, 1_000_000, 4, 3600)
        b = ddb.generate(7, 1_000_000, 4, 3600)
        a_ids = [p.pop("id") for p in a["profiles"]]
        for p in b["profiles"]:
            p.pop("id")
        self.assertEqual(a, b)  # ids are secrets; everything else is seeded
        self.assertTrue(all(len(i) == 16 for i in a_ids))

    def test_every_generated_profile_passes_validation(self):
        db = ddb.generate(1, 1_000_000, 32, 3600)
        for p in db["profiles"]:
            self.assertEqual(ddb.validate_profile(p), [], p)

    def test_windows_are_contiguous(self):
        db = ddb.generate(2, 1_000_000, 8, 600)
        ws = [(p["not_before"], p["not_after"]) for p in db["profiles"]]
        for (_, a1), (b0, _) in zip(ws, ws[1:], strict=False):
            self.assertEqual(a1, b0)

    def test_cover_clock_equals_tamaraw_clock_everywhere(self):
        db = ddb.generate(3, 1_000_000, 16, 3600)
        for p in db["profiles"]:
            self.assertEqual(p["cover_interval_seconds"], p["tamaraw_interval_seconds"])

    def test_fields_match_the_rust_struct_exactly(self):
        p = ddb.generate(4, 1_000_000, 1, 3600)["profiles"][0]
        self.assertEqual(set(p), set(ddb.PROFILE_FIELDS))


class ValidateTests(unittest.TestCase):
    def base(self):
        return ddb.generate(5, 1_000_000, 1, 3600)["profiles"][0]

    def test_out_of_range_values_are_refused_never_clamped(self):
        p = self.base()
        p["tamaraw_interval_seconds"] = 0.5
        self.assertTrue(ddb.validate_profile(p))

    def test_mismatched_cover_clock_is_refused(self):
        p = self.base()
        p["cover_interval_seconds"] = p["tamaraw_interval_seconds"] + 0.01
        self.assertIn("cover clock must equal the tamaraw clock", ddb.validate_profile(p))

    def test_extra_fields_are_refused(self):
        p = self.base()
        p["surprise"] = 1
        self.assertTrue(ddb.validate_profile(p))


class SelectTests(unittest.TestCase):
    def test_select_picks_the_window_containing_now(self):
        db = ddb.generate(6, 1_000_000, 3, 100)
        ps = db["profiles"]
        self.assertIs(ddb.select(ps, 1_000_050), ps[0])
        self.assertIs(ddb.select(ps, 1_000_150), ps[1])
        self.assertIs(ddb.select(ps, 1_000_200), ps[2])  # boundary: next window
        self.assertIsNone(ddb.select(ps, 1_000_300))  # nothing in force: refuse

    def test_load_rejects_a_bad_schema(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "db.json"
            f.write_text(json.dumps({"schema": 999, "profiles": []}))
            with self.assertRaises(SystemExit):
                ddb.load(f)


class CliTests(unittest.TestCase):
    def test_generate_then_current_round_trip(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "db.json"
            subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).parent / "defense_db.py"),
                    "generate",
                    "--out",
                    str(out),
                    "--seed",
                    "11",
                    "--start",
                    "1000000",
                    "--count",
                    "2",
                    "--step",
                    "100",
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            r = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).parent / "defense_db.py"),
                    "current",
                    "--db",
                    str(out),
                    "--now",
                    "1000050",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            profile = json.loads(r.stdout.strip().splitlines()[-1])["profile"]
            self.assertEqual(profile["not_before"], 1000000)
            r = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).parent / "defense_db.py"),
                    "current",
                    "--db",
                    str(out),
                    "--now",
                    "1000200",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 1, "no profile in force must fail closed")


if __name__ == "__main__":
    unittest.main()

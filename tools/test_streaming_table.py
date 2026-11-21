#!/usr/bin/env python3
"""Tests for the streaming-eligibility table generator
(tools/streaming_table.py): measured rows from records, visible expiry,
unmeasured class seeds that never masquerade as results, and the claim
format attached to every table."""

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import streaming_table as st  # noqa: E402


def write_record(evidence: Path, service: str, exit_id: str, result: str, checked: str, region="GB", transport="cloak"):
    safe = exit_id.lower()
    path = evidence / f"{service}-{safe}.json"
    history = []
    if path.exists():
        history = json.loads(path.read_text()).get("history", [])
    history.append(
        {
            "schema": 1,
            "service": service,
            "exit": exit_id,
            "result": result,
            "region": region,
            "checked": checked,
            "transport_profile": transport,
            "markers_seen": [],
            "statuses": [200],
            "pages": 1,
            "fetch_errors": [],
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": 1, "service": service, "exit": exit_id, "history": history}))


class TableTests(unittest.TestCase):
    def test_measured_row_from_record(self):
        table = st.build_table(
            [
                {
                    "schema": 1,
                    "service": "netflix",
                    "exit": "oci-uk-1",
                    "result": "blocked",
                    "region": "GB",
                    "checked": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "transport_profile": "cloak",
                }
            ]
        )
        measured = [r for r in table["rows"] if r["kind"] == "measured"]
        self.assertEqual(len(measured), 1)
        self.assertEqual(measured[0]["exit"], "oci-uk-1")
        self.assertFalse(measured[0]["stale"])
        self.assertEqual(measured[0]["transport_profile"], "cloak")

    def test_stale_rows_marked_not_dropped(self):
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=45)).isoformat()
        table = st.build_table(
            [
                {
                    "schema": 1,
                    "service": "netflix",
                    "exit": "exit-a",
                    "result": "eligible",
                    "region": "GB",
                    "checked": old,
                    "transport_profile": "cloak",
                }
            ]
        )
        row = table["rows"][0]
        self.assertTrue(row["stale"])

    def test_class_seeds_are_unmeasured(self):
        table = st.build_table([])
        seeds = [r for r in table["rows"] if r["kind"] == "class-knowledge"]
        self.assertTrue(len(seeds) >= 5)
        for seed in seeds:
            self.assertTrue(seed["unmeasured"])
            self.assertIn("unmeasured", seed["result"])
            self.assertIsNone(seed["checked"])

    def test_measurement_does_not_collide_with_seed_results(self):
        """A measured row and the class seeds coexist: the measured row
        is a fact with a date; the seed stays labelled unmeasured."""
        table = st.build_table(
            [
                {
                    "schema": 1,
                    "service": "netflix",
                    "exit": "small-uk-1",
                    "result": "eligible",
                    "region": "GB",
                    "checked": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "transport_profile": "tcp443",
                }
            ]
        )
        measured = [r for r in table["rows"] if r["kind"] == "measured"]
        seeds = [r for r in table["rows"] if r["kind"] == "class-knowledge"]
        self.assertEqual(measured[0]["result"], "eligible")
        self.assertTrue(all(s["unmeasured"] for s in seeds))

    def test_claim_format_attached(self):
        table = st.build_table([])
        self.assertIn("avpn stream-check", table["claim"])
        self.assertIn("No blanket", table["claim"])

    def test_version_pinned(self):
        table = st.build_table([])
        self.assertEqual(table["schema"], 1)
        self.assertTrue(table["version"])
        self.assertEqual(table["stale_after_days"], st.STALE_DAYS)


class RecordLoadingTests(unittest.TestCase):
    def test_latest_record_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).isoformat()
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            write_record(evidence, "netflix", "exit-a", "eligible", old)
            write_record(evidence, "netflix", "exit-a", "blocked", now)
            records = st.load_records(evidence)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["result"], "blocked")

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(st.load_records(Path(tmp)), [])

    def test_bad_json_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            (evidence / "junk.json").write_text("{not json")
            self.assertEqual(st.load_records(evidence), [])


class MarkdownTests(unittest.TestCase):
    def test_rendering_has_both_sections(self):
        table = st.build_table(
            [
                {
                    "schema": 1,
                    "service": "dazn",
                    "exit": "exit-x",
                    "result": "eligible",
                    "region": "DE",
                    "checked": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "transport_profile": "cloak",
                }
            ]
        )
        md = st.render_markdown(table)
        self.assertIn("## Measured", md)
        self.assertIn("## Class knowledge", md)
        self.assertIn("exit-x", md)
        self.assertIn("DAZN", md)
        self.assertIn("unmeasured", md)

    def test_no_measurements_placeholder(self):
        md = st.render_markdown(st.build_table([]))
        self.assertIn("no measurements yet", md)


class CLITests(unittest.TestCase):
    def test_end_to_end_generate(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "ev"
            evidence.mkdir()
            write_record(evidence, "netflix", "exit-e2e", "eligible", dt.datetime.now(dt.timezone.utc).isoformat())
            out = Path(tmp) / "table.json"
            md = Path(tmp) / "table.md"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = st.main(["--evidence-dir", str(evidence), "--out", str(out), "--markdown", str(md)])
            self.assertEqual(rc, 0)
            doc = json.loads(out.read_text())
            self.assertEqual(doc["rows"][0]["exit"], "exit-e2e")
            self.assertIn("exit-e2e", md.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)

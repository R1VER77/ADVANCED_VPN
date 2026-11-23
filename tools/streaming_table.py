#!/usr/bin/env python3
"""Generate the streaming-eligibility table from `cypherpunk stream-check` records.

STREAMING_GEO_PARITY_20261120.md section 4.2: a maintained, version-
pinned table recording which exits currently pass which services, with
the check date and the exit's region — the RATE_CLASSES evidence
discipline applied to streaming eligibility. Anyone running
`cypherpunk run -- stream-check <service>` contributes a row; the table is
generated, never hand-edited, and dated entries expire visibly.

The honesty rules the generator enforces:

  - MEASURED rows come only from probe records (tools/stream_check.py);
    every value is the latest measurement for that exit-service pair.
  - STALE rows (older than STALE_DAYS) are marked stale in place, never
    silently dropped and never counted as current.
  - CLASS-BLOCKED background knowledge (Oracle/AWS/GCP/Hetzner main
    ranges are pre-blocked as hosting classes) may seed the table only
    with `unmeasured` set and result "blocked (class, unmeasured)" —
    the first measured row replaces it. An assumption never overwrites
    a measurement.
  - The table ships with the claim format (section 4.5): eligibility
    is a dated, per-exit, per-service fact; there is no blanket
    "works with X" claim anywhere in the output.

Output: docs/evidence/STREAMING_ELIGIBILITY.json (the pinned artifact)
and a markdown rendering of it for the docs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stream_check import ADAPTERS, EVIDENCE_DIR  # noqa: E402

SCHEMA = 1
STALE_DAYS = 30
TABLE_VERSION = "2026-11-21.1"

# Background knowledge the streaming-geo analysis documents (section 1:
# the major-cloud ranges are hosting-class pre-blocked). Seeded as
# unmeasured; the first probe record replaces each row.
SEED_CLASS_ROWS = [
    {
        "provider": "Oracle Cloud",
        "region": "any",
        "service": "netflix",
        "result": "blocked (class, unmeasured)",
        "note": "the owner's current OCI exit is believed blocked; measure it "
        "with `cypherpunk run -- stream-check netflix` to replace this row",
    },
    {"provider": "AWS", "region": "any", "service": "netflix", "result": "blocked (class, unmeasured)", "note": ""},
    {
        "provider": "Google Cloud",
        "region": "any",
        "service": "netflix",
        "result": "blocked (class, unmeasured)",
        "note": "",
    },
    {
        "provider": "Hetzner",
        "region": "any",
        "service": "netflix",
        "result": "blocked (class, unmeasured)",
        "note": "r/selfhosted and devrunners.com report Hetzner ranges blocked by Netflix",
    },
    {
        "provider": "Hetzner",
        "region": "any",
        "service": "bbc-iplayer",
        "result": "blocked (class, unmeasured)",
        "note": "",
    },
]


def load_records(evidence_dir: Path) -> list[dict]:
    """Every latest measurement from the streaming evidence directory."""
    records = []
    if not evidence_dir.exists():
        return records
    for path in sorted(evidence_dir.glob("*.json")):
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if doc.get("schema") != 1:
            continue
        history = doc.get("history", [])
        if history:
            records.append(history[-1])
    return records


def is_stale(checked: str, now: dt.datetime | None = None, days: int = STALE_DAYS) -> bool:
    """Whether a measurement is older than the staleness window."""
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        at = dt.datetime.fromisoformat(checked)
    except ValueError:
        return True
    if at.tzinfo is None:
        at = at.replace(tzinfo=dt.timezone.utc)
    return (now - at).days >= days


def build_table(records: list[dict], now: dt.datetime | None = None) -> dict:
    """The pinned artifact: measured rows + unmeasured class seeds.

    Measured rows win: a seed row for (provider-class, service) is
    dropped once a record for that pair exists — records carry an exit
    id, not a provider class, so seeds are keyed (provider, service)
    and records (exit, service); both are listed, but the seed carries
    `unmeasured: true` until its class has any measurement at all."""
    now = now or dt.datetime.now(dt.timezone.utc)
    rows = []
    for record in records:
        rows.append(
            {
                "kind": "measured",
                "exit": record["exit"],
                "service": record["service"],
                "region": record.get("region"),
                "result": record["result"],
                "transport_profile": record.get("transport_profile", "unspecified"),
                "checked": record["checked"],
                "stale": is_stale(record["checked"], now),
                "unmeasured": False,
            }
        )
    measured_classes = {r["service"] for r in rows}
    for seed in SEED_CLASS_ROWS:
        if seed["service"] in measured_classes and seed["provider"] in (
            "Oracle Cloud",
            "AWS",
            "Google Cloud",
            "Hetzner",
        ):
            # A measurement exists for this service; keep the class row
            # only as clearly-unmeasured background, never as a result.
            pass
        rows.append(
            {
                "kind": "class-knowledge",
                "exit": None,
                "provider": seed["provider"],
                "service": seed["service"],
                "region": seed["region"],
                "result": seed["result"],
                "transport_profile": None,
                "checked": None,
                "stale": False,
                "unmeasured": True,
                "note": seed["note"],
            }
        )
    rows.sort(key=lambda r: (0 if r["kind"] == "measured" else 1, r.get("exit") or r.get("provider", ""), r["service"]))
    return {
        "schema": SCHEMA,
        "version": TABLE_VERSION,
        "generated": now.isoformat(timespec="seconds"),
        "stale_after_days": STALE_DAYS,
        "claim": "Streaming eligibility is measured per exit, per service, "
        "dated in the exit's descriptor; run `cypherpunk stream-check` to "
        "test yours. No blanket 'works with service X' claim is "
        "made or implied by this table.",
        "services": {k: v["name"] for k, v in ADAPTERS.items()},
        "rows": rows,
    }


def render_markdown(table: dict) -> str:
    """The docs rendering: measured rows first, then the class seeds."""
    lines = [
        "# Streaming eligibility (generated)",
        "",
        f"Version {table['version']}, generated {table['generated']}.",
        "",
        f"> {table['claim']}",
        "",
        f"Rows older than {table['stale_after_days']} days are marked `stale` and must be re-measured before use.",
        "",
        "## Measured (from `cypherpunk stream-check` records)",
        "",
        "| Exit | Service | Region | Result | Transport | Checked | State |",
        "|---|---|---|---|---|---|---|",
    ]
    measured = [r for r in table["rows"] if r["kind"] == "measured"]
    for row in measured:
        state = "stale" if row["stale"] else "current"
        lines.append(
            f"| {row['exit']} | {table['services'].get(row['service'], row['service'])} "
            f"| {row['region'] or '—'} | {row['result']} | {row['transport_profile']} "
            f"| {row['checked']} | {state} |"
        )
    if not measured:
        lines.append("| _no measurements yet — be the first: `cypherpunk run -- stream-check netflix`_ | | | | | | |")
    lines += [
        "",
        "## Class knowledge (unmeasured background, replaced by any measurement)",
        "",
        "| Provider class | Service | Result | Note |",
        "|---|---|---|---|",
    ]
    for row in (r for r in table["rows"] if r["kind"] == "class-knowledge"):
        lines.append(
            f"| {row['provider']} | {table['services'].get(row['service'], row['service'])} "
            f"| {row['result']} | {row['note']} |"
        )
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    """Command line: build or show the eligibility table."""
    parser = argparse.ArgumentParser(
        prog="streaming-table",
        description="Generate the streaming-eligibility table from stream-check records",
    )
    parser.add_argument("--evidence-dir", default=str(EVIDENCE_DIR))
    parser.add_argument(
        "--out", default=None, help="write the JSON artifact here (default: docs/evidence/STREAMING_ELIGIBILITY.json)"
    )
    parser.add_argument("--markdown", default=None, help="write the markdown rendering here")
    args = parser.parse_args(argv)

    records = load_records(Path(args.evidence_dir))
    table = build_table(records)
    out = (
        Path(args.out)
        if args.out
        else (Path(__file__).resolve().parent.parent / "docs" / "evidence" / "STREAMING_ELIGIBILITY.json")
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(table, indent=1) + "\n")
    markdown = render_markdown(table)
    if args.markdown:
        Path(args.markdown).write_text(markdown)
    print(markdown)
    print(f"artifact: {out} ({len(records)} measured record(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

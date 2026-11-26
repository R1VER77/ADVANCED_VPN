#!/usr/bin/env python3
"""Qualify repeated timing-margin trials from aggregate holdout reports."""

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import random


OBSERVERS = ("timing_sensitivity", "prior_timing_sensitivity", "combined_timing_sensitivity")
REGIONS = frozenset({"us-central1", "europe-west3", "asia-southeast1"})
BOOTSTRAP_SAMPLES = 10000


def trial_day(report):
    """Use the recorded UTC day even when a runner reports a local offset."""
    started = datetime.fromisoformat(report["timing_margin_trial"]["started"].replace("Z", "+00:00"))
    if started.utcoffset() is None:
        raise ValueError("trial start requires a UTC offset")
    return started.astimezone(timezone.utc).date()


def upper_bound(captures):
    """Conservative maximum of one-sided Wilson and whole-capture bootstrap estimates."""
    total_hits = sum(hits for hits, _ in captures)
    attempts = sum(events for _, events in captures)
    score = total_hits / attempts
    z = 1.6448536269514722
    z2 = z * z
    wilson = (score + z2 / (2 * attempts) + z * math.sqrt((score * (1 - score) + z2 / (4 * attempts)) / attempts)) / (
        1 + z2 / attempts
    )
    rng = random.Random(0)  # noqa: S311 - reproducible resampling
    samples = []
    for _ in range(BOOTSTRAP_SAMPLES):
        sample = rng.choices(captures, k=len(captures))
        samples.append(sum(hits for hits, _ in sample) / sum(events for _, events in sample))
    samples.sort()
    return dict(top1=score, events=attempts, upper_95=max(wilson, samples[math.ceil(0.95 * BOOTSTRAP_SAMPLES) - 1]))


def qualify(trials):
    """Aggregate run evidence without treating repeated or sparse trials as qualification."""
    if not trials:
        raise ValueError("at least one trial is required")
    rows = [trial["report"] for trial in trials]
    if len({report["capture_sha256"] for report in rows}) != len(rows):
        raise ValueError("duplicate capture")
    checks = {
        "three_days": len({trial_day(report) for report in rows}) >= 3,
        "distinct_seeds": len({report["timing_margin_trial"]["seed"] for report in rows}) == len(rows),
        "gcp_regions": REGIONS <= {trial["region"] for trial in trials},
        "720_requests_each": all(report["mix"]["request_count"] >= 720 for report in rows),
        "single_trial_gates": all(report["timing_margin_trial"]["passed"] for report in rows),
    }
    observers = {}
    for observer in OBSERVERS:
        blocks_by_run = [report["mix"][observer]["time_blocks"] for report in rows]
        captures = []
        block_margin = True
        for blocks, report in zip(blocks_by_run, rows, strict=True):
            hits = sum(block["top1_hits"] for block in blocks)
            events = sum(block["events"] for block in blocks)
            if events != report["mix"]["arrivals"] or not 0 <= hits <= events or not events:
                raise ValueError("invalid observer aggregate")
            captures.append((hits, events))
            block_margin &= len(blocks) == 5 and all(
                b["events"] >= 50 and 0 <= b["top1_hits"] <= 0.08 * b["events"] for b in blocks
            )
        result = upper_bound(captures)
        result["each_block_at_most_8_percent"] = block_margin
        result["passed"] = block_margin and result["upper_95"] < 0.1
        observers[observer] = result
    return dict(
        schema=1,
        scope="timing-margin mix pilot; GCP remains one provider",
        trials=len(rows),
        checks=checks,
        observers=observers,
        passed=all(checks.values()) and all(result["passed"] for result in observers.values()),
    )


def main():
    """Read a manifest of region and report paths and write an aggregate result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="JSON list of objects with region and report path")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    trials = [
        dict(region=row["region"], report=json.loads((args.manifest.parent / row["report"]).read_text()))
        for row in manifest
    ]
    result = qualify(trials)
    with args.out.open("x") as out:
        out.write(json.dumps(result, indent=2) + "\n")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

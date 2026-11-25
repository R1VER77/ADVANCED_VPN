#!/usr/bin/env python3
"""Transfer frozen, archived website classifiers to a separately collected pilot."""

import argparse
from collections import Counter
import json
import math
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

import wf_ab
import wf_deep
import wf_replication
from wf_validity import capture_window, protection_window


def jsonl(path):
    """Load a private metadata stream."""
    return [json.loads(line) for line in path.read_text().splitlines()]


def measure(worker, model, expected_sites, threshold, defended):
    """Score all valid fixed windows and report invalid or missing windows explicitly."""
    loads = jsonl(worker / "loads.jsonl")
    if Counter(row["site"] for row in loads) != Counter(expected_sites):
        raise ValueError("pilot did not attempt each planned site exactly once")
    capture = json.loads((worker / "capture.json").read_text())
    heartbeats = jsonl(worker / "capture-heartbeats.jsonl")
    observations = jsonl(worker / "protection.jsonl")
    packet_path = worker / "packets.bin"
    if packet_path.stat().st_size % wf_deep.RECORD.itemsize:
        raise ValueError("truncated pilot capture")
    packets = np.fromfile(packet_path, dtype=wf_deep.RECORD)
    if (
        not np.isfinite(packets["t"]).all()
        or np.any(packets["n"] == 0)
        or np.any(np.abs(packets["n"].astype("i8")) > 65535)
    ):
        raise ValueError("invalid pilot packet metadata")
    packets = packets[np.argsort(packets["t"], kind="stable")]
    width = len(wf_deep.kfp_features([np.array([[0.0, 1.0, 0.0]])])[0])
    invalid, totals = Counter(), Counter()
    for row in loads:
        known = row["site"] in model.classes_
        category = "known" if known else "unknown"
        totals[category + "_attempted"] += 1
        start = row.get("start")
        if not isinstance(start, (int, float)) or isinstance(start, bool) or not math.isfinite(start):
            invalid["no_valid_browser_start"] += 1
            continue
        stop = start + wf_deep.WINDOW
        window = capture_window(capture, heartbeats, start, stop)
        if not window["valid"]:
            invalid[window["reason"]] += 1
            continue
        protection = protection_window(observations, start, stop, defended)
        expected_state = "all_samples_protected" if defended else "control_samples_valid"
        totals["windows_with_unexpected_protection_samples"] += not protection.get(expected_state)
        lo, hi = np.searchsorted(packets["t"], [start, stop])
        part = packets[lo:hi]
        trace = np.column_stack([part["t"] - start, np.sign(part["n"]), np.abs(part["n"])]).astype(float)
        vector = wf_deep.kfp_features([wf_deep.wire_packets(trace)])[0] if len(trace) else np.zeros(width)
        scores = model.predict_proba([vector])[0]
        best = int(np.argmax(scores))
        totals[category + "_evaluated"] += 1
        totals[category + "_above_threshold"] += scores[best] >= threshold
        if known:
            correct = model.classes_[best] == row["site"]
            totals["known_correct"] += correct
            totals["known_correct_above_threshold"] += correct and scores[best] >= threshold
    return dict(
        counts={name: int(n) for name, n in totals.items()},
        invalid_windows=dict(invalid),
        browser_counts=dict(Counter(row["status"] for row in loads)),
        capture={key: capture[key] for key in ("clean_stop", "drops", "malformed", "unexpected_outgoing")},
    )


def main():
    """Emit aggregate transfer and open-set results without site names or packet data."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("pilot", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    site_path = args.pilot / "local-transfer-sites.json"
    sites = json.loads(site_path.read_text())
    manifest = json.loads((args.pilot / "local-transfer-manifest.json").read_text())
    recorded = json.loads((args.pilot / "local-transfer-run.json").read_text())
    known, unknown = map(set, (sites["monitored"], sites["open_world"]))
    if wf_ab.sha256(site_path) != manifest["hashes"].get(str(site_path.resolve())):
        raise ValueError("pilot site set differs from the frozen manifest")
    if len(known) != manifest["known"] or len(unknown) != manifest["unknown"] or known & unknown or sites["loads"] != 1:
        raise ValueError("pilot needs disjoint known and unseen site sets and one attempt per site")
    threshold = manifest["known_acceptance_threshold"]
    if not 0 < threshold <= 1:
        raise ValueError("invalid pilot confidence threshold")
    result = dict(
        schema=1,
        scope="one archived training environment and one separate test environment",
        threshold=threshold,
        archive_manifest_sha256=wf_ab.sha256(args.archive / "manifest.json"),
        pilot_manifest_sha256=wf_ab.sha256(args.pilot / "local-transfer-manifest.json"),
        variants={},
    )
    for arm in ("undefended", "relay30"):
        if recorded[arm]["status"] != "complete":
            raise ValueError(f"pilot arm {arm} did not complete")
        views, _, groups, rows, _, excluded, _ = wf_replication.load(args.archive, arm)
        cells = Counter((row["round"], row["site"]) for row in rows)
        if (
            excluded
            or set(groups) != set(range(1, 7))
            or {row["site"] for row in rows} != known
            or len(cells) != 6 * len(known)
            or set(cells.values()) != {2}
        ):
            raise ValueError(f"training arm {arm} differs from the six-round known-site plan")
        model = RandomForestClassifier(n_estimators=500, random_state=0, n_jobs=1)
        model.fit(views["both"], [row["site"] for row in rows])
        result["variants"][arm] = dict(
            train_windows=len(rows),
            **measure(
                args.pilot / f"local-transfer-{arm}" / "w0", model, known | unknown, threshold, arm != "undefended"
            ),
        )
    control = result["variants"]["undefended"]
    result["transfer_control_met_80_percent"] = (
        not control["invalid_windows"]
        and not control["counts"].get("windows_with_unexpected_protection_samples", 0)
        and control["counts"].get("known_correct", 0) >= 0.8 * len(known)
    )
    with args.out.open("x") as out:
        out.write(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()

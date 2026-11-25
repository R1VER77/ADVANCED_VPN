#!/usr/bin/env python3
"""Rescore the mix lab's private capture on later observations using an earlier delay model."""

import argparse
from collections import Counter, defaultdict
import hashlib
from itertools import pairwise
import json
from pathlib import Path
import random

import gpa
from mix_lab import BASELINE_PORT, TIMING_MARGIN_CLIENTS, TIMING_MARGIN_PROFILE, events


def requests(root, phase, clients):
    """Read request ground truth from the lab's per-client workload records."""
    rows = []
    for client in range(clients):
        path = root / f"{phase}{client}.jsonl"
        rows.extend(dict(json.loads(line), client=client) for line in path.read_text().splitlines())
    if not rows:
        raise ValueError(f"no requests in the {phase} phase")
    return sorted(rows, key=lambda row: row["sent"])


def align(rows, lookups):
    """Keep DNS events that fall inside exactly one matching request's lifetime."""
    by_site = defaultdict(list)
    for row in rows:
        by_site[row["site"]].append(row)
    matched, skipped = [], 0
    used = set()
    for stamp, site in lookups:
        eligible = [row for row in by_site.get(site, ()) if row["sent"] <= stamp <= row["done"]]
        if len(eligible) != 1:
            skipped += 1
            continue
        row = eligible[0]
        key = (row["client"], row["sent"], site)
        if key not in used:
            matched.append((stamp, row["client"], row["sent"]))
            used.add(key)
    return matched, skipped


def timing_sensitivity(arrivals, scores, start, stop, clients, permutations=10_000):
    """Measure five equal-duration blocks and relabel whole sender groups."""
    blocks = [[] for _ in range(5)]
    weights = [[[0.0] * clients for _ in range(clients)] for _ in blocks]
    for (arrival, _), (tied, truth, entropy) in zip(arrivals, scores, strict=True):
        block = min(4, int(5 * (arrival - start) / (stop - start)))
        blocks[block].append((tied, truth, entropy))
        for guess in tied:
            weights[block][truth][guess] += 1 / len(tied)

    block_scores = [
        dict(events=len(block), accuracy=gpa.summary(block, clients)["top1_accuracy"] if block else None)
        for block in blocks
    ]
    populated = [(matrix, len(block)) for matrix, block in zip(weights, blocks, strict=True) if block]
    observed_hits = [sum(matrix[sender][sender] for sender in range(clients)) for matrix, _ in populated]
    observed = sum(observed_hits)
    worst = max(hits / size for hits, (_, size) in zip(observed_hits, populated, strict=True))
    seed = 0
    rng = random.Random(seed)  # noqa: S311 - reproducible statistical sampling
    labels = list(range(clients))
    exceedances = 0
    worst_exceedances = 0
    for _ in range(permutations):
        rng.shuffle(labels)
        hits = [sum(matrix[sender][label] for sender, label in enumerate(labels)) for matrix, _ in populated]
        exceedances += sum(hits) >= observed - 1e-12
        worst_exceedances += max(hit / size for hit, (_, size) in zip(hits, populated, strict=True)) >= worst - 1e-12
    return dict(
        time_blocks=block_scores,
        identity_permutation_exceedance=(exceedances + 1) / (permutations + 1),
        worst_block_permutation_exceedance=(worst_exceedances + 1) / (permutations + 1),
        identity_permutations=permutations,
        identity_permutation_seed=seed,
    )


def score_phase(phase, rows, capture, start, stop, clients, cover_clients=0):
    """Split by elapsed time and fit the delay histogram only to earlier DNS events."""
    sends = {client: [] for client in range(clients)}
    lookups = []
    for line in capture:
        kind, *fields = line.split()
        if kind == "c":
            client, stamp, port, _ = fields
            if (int(port) == BASELINE_PORT) == (phase == "baseline") and start <= float(stamp) < stop:
                sender = int(client)
                if sender in sends:
                    sends[sender].append(float(stamp))
                elif not clients <= sender < clients + cover_clients:
                    raise ValueError(f"capture contains undeclared client {sender}")
        elif kind == "d":
            stamp, site = fields
            if start <= float(stamp) < stop:
                lookups.append((float(stamp), site))
    matched, skipped = align(rows, sorted(lookups))
    split = (start + stop) / 2
    training = [(stamp - sent, client) for stamp, client, sent in matched if stamp < split]
    test = [(stamp, client) for stamp, client, sent in matched if sent >= split]
    sends = {client: [stamp for stamp in events(times) if stamp >= split] for client, times in sends.items()}
    model = gpa.DelayModel([delay for delay, _ in training])
    scores = gpa.attack(sends, test, model)
    counts = Counter(client for _, client in training)
    prior_sender = max(sends, key=counts.__getitem__)
    prior = [([prior_sender], client, 0.0) for _, client in test]
    checkpoints = [split + index * (stop - split) / 5 for index in range(6)]
    checkpoints[-1] = stop
    return dict(
        request_count=len(rows),
        heldout_requests=sum(row["sent"] >= split for row in rows),
        successful_requests=sum(row.get("status") is not None and 200 <= row["status"] < 500 for row in rows),
        training_arrivals=len(training),
        split_crossing_arrivals=len(matched) - len(training) - len(test),
        unmatched_or_ambiguous_dns_events=skipped,
        heldout_senders=len({client for _, client in test}),
        active_senders_per_block=[
            sum(any(left <= stamp < right for stamp in stamps) for stamps in sends.values())
            for left, right in pairwise(checkpoints)
        ],
        **gpa.summary(scores, clients),
        timing_sensitivity=timing_sensitivity(test, scores, split, stop, clients),
        prior_top1_accuracy=gpa.summary(prior, clients)["top1_accuracy"],
        prior_timing_sensitivity=timing_sensitivity(test, prior, split, stop, clients),
    )


def margin_checks(paper, mix, baseline):
    """Check the empirical margin for one frozen trial."""
    params = paper.get("katzenpost_parameters", {})
    return {
        "fixed_profile": (
            paper.get("profile") == TIMING_MARGIN_PROFILE
            and paper["clients"] == paper.get("clients_ready") == TIMING_MARGIN_CLIENTS
            and paper.get("cover_clients") == 0
            and type(paper.get("workload_seed")) is int
            and paper.get("lane") == "katzenpost"
            and paper.get("pki_scheme") == "Ed25519 Sphincs+"
            and paper.get("sphinx", {}).get("PacketLength") == "22458"
            and paper.get("fetch_plugin") == "tools/kp_pq_fetch.py (PQ-only)"
            and params.get("Mu") == 0.01
            and params.get("LambdaP") == 0.001
            and params.get("LambdaL") == 0.0005
        ),
        "positive_control": baseline["arrivals"] >= 60 and baseline["top1_accuracy"] >= 0.8,
        "coverage": (
            mix["heldout_senders"] == TIMING_MARGIN_CLIENTS
            and all(n == TIMING_MARGIN_CLIENTS for n in mix["active_senders_per_block"])
            and all(b["events"] >= 50 for b in mix["timing_sensitivity"]["time_blocks"])
            and mix["arrivals"] >= 0.75 * mix["heldout_requests"]
        ),
        "live_fetch_success": (
            mix["successful_requests"] / mix["request_count"] >= 0.9
            and mix["successful_requests"] / mix["request_count"]
            >= baseline["successful_requests"] / baseline["request_count"] - 0.05
        ),
        "overall_margin": max(mix["chance"], mix["top1_accuracy"], mix["prior_top1_accuracy"]) <= 0.08,
        "worst_window_margin": all(
            block["accuracy"] is not None and block["accuracy"] <= 0.08
            for name in ("timing_sensitivity", "prior_timing_sensitivity")
            for block in mix[name]["time_blocks"]
        ),
    }


def main():
    """Write aggregates without including source addresses, queried names or timestamps."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-margin", action="store_true", help="exit nonzero on a failed timing-margin trial")
    args = parser.parse_args()
    paper = json.loads((args.run / "MIX_LANE.json").read_text())
    clients = paper["clients"]
    cover = paper.get("cover_clients", 0)
    mix, baseline = (requests(args.run, phase, clients) for phase in ("mix", "baseline"))
    mix_start, baseline_start = mix[0]["sent"], baseline[0]["sent"]
    mix_stop, baseline_stop = (max(row["done"] for row in rows) for rows in (mix, baseline))
    if not mix_start < mix_stop <= baseline_start < baseline_stop:
        raise ValueError("expected nonoverlapping mix and baseline workload phases")
    raw = (args.run / "capture.txt").read_bytes()
    capture = raw.decode().splitlines()
    result = dict(
        schema=1,
        capture_sha256=hashlib.sha256(raw).hexdigest(),
        scope="same-run temporal holdout; ingress send events and egress DNS in an isolated lab",
        cover_clients_excluded=cover,
        mix=score_phase("mix", mix, capture, mix_start, mix_stop, clients, cover),
        baseline=score_phase("baseline", baseline, capture, baseline_start, baseline_stop, clients, cover),
    )
    if paper.get("profile") == TIMING_MARGIN_PROFILE or args.require_margin:
        checks = margin_checks(paper, result["mix"], result["baseline"])
        result["timing_margin_trial"] = dict(
            passed=all(checks.values()), checks=checks, started=paper.get("started"), seed=paper.get("workload_seed")
        )
    with args.out.open("x") as out:
        out.write(json.dumps(result, indent=2) + "\n")
    if args.require_margin and not result["timing_margin_trial"]["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

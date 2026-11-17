#!/usr/bin/env python3
"""Analyze interleaved clock A/B collections without treating neighboring loads as independent.

Use the existing fixed-window k-FP features. Report legacy stratified CV alongside
leave-one-round-out scores and a within-round label-map permutation null. Browser
success/cost uses every attempted load, separately from classifier trace filtering.
Requires the optional numpy/scikit-learn analysis environment; never contacts a site.
"""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import time


def round_number(path):
    """Read the numeric round so r10 cannot sort before r2."""
    match = re.fullmatch(r"r([1-9][0-9]*)-(.+)", Path(path).name)
    if not match:
        raise ValueError("expected an rN-variant collection directory")
    return int(match[1])


def resource_medians(rows):
    """The existing loader's per-site browser-resource reference counts."""
    counts = collections.defaultdict(list)
    for row in rows:
        if row.get("resources") is not None:
            counts[row["site"]].append(row["resources"])
    return {site: statistics.median(values) for site, values in counts.items()}


def accepted(row, usual, minimum=0.25):
    """Keep complete capture attempts, including timeouts, with the declared resource filter."""
    return row.get("status") in ("ok", "TimeoutException") and not (
        row.get("resources") is not None and usual.get(row["site"]) and row["resources"] < minimum * usual[row["site"]]
    )


def paired_rows(left, right):
    """Pair repeat index within each round/site, refusing missing or extra attempts."""

    def indexed(rows):
        counts = collections.Counter()
        out = {}
        for row in rows:
            group = row["round"], row["site"]
            key = (*group, counts[group])
            counts[group] += 1
            out[key] = row
        return out

    a, b = indexed(left), indexed(right)
    if a.keys() != b.keys():
        raise ValueError("A/B attempts are not matched by round/site/repeat")
    return [(a[key], b[key]) for key in sorted(a)]


def sha256(path):
    """Hash a large capture without loading it all into memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_features(root, variant):
    """One capture at a time; retain feature vectors rather than all raw traces in RAM."""
    import numpy as np
    import wf_deep

    rows, sources = [], []
    directories = sorted(root.glob("r*-" + variant), key=round_number)
    if len(directories) < 2:
        raise ValueError("at least two rounds required")
    for directory in directories:
        if any(path.is_dir() and path.name != "w0" for path in directory.glob("w[0-9]*")):
            raise ValueError("this A/B analyzer requires single-worker collections; refusing to omit other workers")
        worker = directory / "w0"
        settings = json.loads((worker / "settings.json").read_text())
        if settings.get("wire_clock_relay_ms") != variant.removeprefix("relay"):
            raise ValueError("variant does not match the recorded relay look-ahead")
        batch = [
            dict(json.loads(line), round=round_number(directory))
            for line in (worker / "loads.jsonl").read_text().splitlines()
        ]
        rows.extend(batch)
        sources.append(
            dict(
                round=round_number(directory),
                settings=settings,
                loads_sha256=sha256(worker / "loads.jsonl"),
                packets_sha256=sha256(worker / "packets.bin"),
            )
        )
    usual = resource_medians(rows)
    features = {name: [] for name in ("both", "upstream_only", "downstream_only")}
    labels, groups, filtered, kept_rows = [], [], [], []
    for directory in directories:
        capture = np.memmap(directory / "w0/packets.bin", dtype=wf_deep.RECORD, mode="r")
        if np.any(capture["t"][1:] < capture["t"][:-1]):
            capture = capture[np.argsort(capture["t"], kind="stable")]
        for row in (r for r in rows if r["round"] == round_number(directory)):
            if int(row["label"]) < 0 or not accepted(row, usual, minimum=0):
                continue
            if len(capture) == 0 or capture["t"][-1] < row["start"] + wf_deep.WINDOW:
                raise ValueError("capture ends before the full fixed observation window")
            lo, hi = np.searchsorted(capture["t"], [row["start"], row["start"] + wf_deep.WINDOW])
            part = capture[lo:hi]
            if len(part) < 2:
                continue
            trace = np.column_stack([part["t"] - row["start"], np.sign(part["n"]), np.abs(part["n"])]).astype(float)
            trace = wf_deep.wire_packets(trace)
            for name, keep in (("both", None), ("upstream_only", 1), ("downstream_only", -1)):
                subset = trace if keep is None else trace[trace[:, 1] == keep]
                if len(subset) < 2:
                    subset = np.array([[0.0, 1.0, 100.0], [0.0, -1.0, 100.0]])
                features[name].append(wf_deep.kfp_features([subset])[0])
            labels.append(int(row["label"]))
            groups.append(row["round"])
            filtered.append(accepted(row, usual))
            kept_rows.append(row)
        del capture
    return (
        {key: np.asarray(value) for key, value in features.items()},
        np.asarray(labels),
        np.asarray(groups),
        np.asarray(filtered),
        rows,
        kept_rows,
        sources,
    )


def cv_score(x, y, groups, mode):
    """Fixed-seed forest accuracy; whole rounds stay out of training in the primary split."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold

    if mode == "round_holdout":
        splits = LeaveOneGroupOut().split(x, y, groups)
    elif mode == "legacy_stratified":
        folds = min(5, min(collections.Counter(y).values()))
        if folds < 2:
            raise ValueError("too few samples per class")
        splits = StratifiedKFold(folds, shuffle=True, random_state=0).split(x, y)
    else:
        raise ValueError("unknown split mode")
    correct = np.zeros(len(y), dtype=bool)
    for fold, (train, test) in enumerate(splits):
        if mode == "round_holdout" and set(groups[train]) & set(groups[test]):
            raise AssertionError("a held-out round entered training")
        model = RandomForestClassifier(n_estimators=500, random_state=fold, n_jobs=1)
        model.fit(x[train], y[train])
        correct[test] = model.predict(x[test]) == y[test]
    return float(correct.mean()), {
        str(g): dict(correct=int(correct[groups == g].sum()), loads=int((groups == g).sum()))
        for g in sorted(set(groups))
    }


def permute_round_labels(y, groups, seed):
    """Keep each round's repeated site loads together; destroy site identity across rounds."""
    import numpy as np

    rng = np.random.default_rng(seed)
    out = y.copy()
    for group in sorted(set(groups)):
        mask = groups == group
        labels = np.unique(y[mask])
        mapping = dict(zip(labels, rng.permutation(labels), strict=True))
        out[mask] = [mapping[label] for label in y[mask]]
    return out


def null_score(x, y, groups, seed):
    """One round-block permutation, repeating the entire train/test procedure."""
    return cv_score(x, permute_round_labels(y, groups, seed), groups, "round_holdout")[0]


def cost(rows):
    """Count every browser attempt, separately from classifier inclusion."""
    import numpy as np

    ok = [r for r in rows if r["status"] == "ok"]
    seconds = [r["loaded"] - r["start"] for r in ok]
    return dict(
        attempts=len(rows),
        success=len(ok),
        success_rate=len(ok) / len(rows),
        status_counts=dict(collections.Counter(r["status"] for r in rows)),
        successful_load_seconds_median=float(np.median(seconds)),
        successful_load_seconds_p90=float(np.percentile(seconds, 90)),
    )


def paired_cost(left, right):
    """Uncertainty resamples site clusters, retaining all of a site's round/repeat pairs."""
    import numpy as np

    pairs = paired_rows(left, right)
    by_site = collections.defaultdict(list)
    deltas = []
    gains = losses = 0
    for a, b in pairs:
        a_ok, b_ok = a["status"] == "ok", b["status"] == "ok"
        by_site[a["site"]].append(int(b_ok) - int(a_ok))
        gains += int(b_ok and not a_ok)
        losses += int(a_ok and not b_ok)
        if a_ok and b_ok:
            deltas.append((b["loaded"] - b["start"]) - (a["loaded"] - a["start"]))
    sites = sorted(by_site)
    rng = np.random.default_rng(0)
    boot = [
        np.mean([d for site in rng.choice(sites, size=len(sites), replace=True) for d in by_site[site]])
        for _ in range(10000)
    ]
    return dict(
        pairs=len(pairs),
        success_gains=gains,
        success_losses=losses,
        success_difference=(gains - losses) / len(pairs),
        success_difference_site_cluster_bootstrap_ci95=list(map(float, np.percentile(boot, [2.5, 97.5]))),
        both_successful_pairs=len(deltas),
        paired_success_latency_difference_median=float(np.median(deltas)),
    )


def holm(p_values):
    """Holm family-wise adjustment, returned in the original comparison order."""
    order = sorted(range(len(p_values)), key=p_values.__getitem__)
    adjusted, previous = [0.0] * len(order), 0.0
    for rank, index in enumerate(order):
        previous = max(previous, min(1.0, (len(order) - rank) * p_values[index]))
        adjusted[index] = previous
    return adjusted


def main():
    """Extract bounded-memory features, score both views and save partial progress."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--permutations", type=int, default=100)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 4 or args.permutations < 1:
        parser.error("use 1..4 workers and a positive permutation count")
    os.nice(15)
    import numpy as np
    import sklearn
    from joblib import Parallel, delayed, parallel_config

    result = dict(
        schema=1,
        analysis="relay look-ahead A/B",
        status="running",
        variants={},
        versions=dict(numpy=np.__version__, sklearn=sklearn.__version__),
        method=dict(
            trees=500,
            window_seconds=12,
            resource_filter=0.25,
            permutation="independent site-label map in each round; repeats kept together",
            permutations=args.permutations,
            baseline="No fresh undefended control in this A/B run",
        ),
        limitations=[
            "20-site closed world on one host/network; no open-world or neural attack claim",
            "Fixed variant order within each round; not randomized/counterbalanced",
            "Resource filtering uses collection-wide browser counts and can bias the retained set",
            "Hardware tests, short Python checks, documentation publishing and desktop activity overlapped collection",
            "A non-significant test is not proof of absence of leakage",
        ],
    )

    def save():
        args.out.write_text(json.dumps(result, indent=2) + "\n")

    rows_by_variant = {}
    for variant in ("relay30", "relay5"):
        print("Extracting " + variant, flush=True)
        x, y, groups, filtered, rows, _, sources = load_features(args.run, variant)
        rows_by_variant[variant] = rows
        stats = result["variants"][variant] = dict(
            cost=cost(rows),
            retained_loads=int(filtered.sum()),
            captured_monitored_windows=len(y),
            sites=len(set(y)),
            chance=1 / len(set(y)),
            sources=sources,
            views={},
        )
        for name in x:
            started = time.monotonic()
            real, by_round = cv_score(x[name][filtered], y[filtered], groups[filtered], "round_holdout")
            legacy, _ = cv_score(x[name][filtered], y[filtered], groups[filtered], "legacy_stratified")
            sensitivity, _ = cv_score(x[name], y, groups, "round_holdout")
            print(variant, name, "legacy", round(legacy, 4), "held-out-round", round(real, 4), flush=True)
            with parallel_config(backend="loky", inner_max_num_threads=1):
                null = Parallel(n_jobs=args.jobs)(
                    delayed(null_score)(x[name][filtered], y[filtered], groups[filtered], seed)
                    for seed in range(1, args.permutations + 1)
                )
            stats["views"][name] = dict(
                legacy_stratified_accuracy=legacy,
                round_holdout_accuracy=real,
                by_round=by_round,
                all_valid_windows_round_holdout_accuracy=sensitivity,
                null_mean=float(np.mean(null)),
                null_p95=float(np.percentile(null, 95)),
                p_value=(1 + sum(v >= real for v in null)) / (1 + len(null)),
                null_scores=null,
                seconds=round(time.monotonic() - started, 1),
            )
            save()
            print(variant, name, "complete", round(time.monotonic() - started, 1), "seconds", flush=True)
    result["paired_cost_relay5_minus_relay30"] = paired_cost(rows_by_variant["relay30"], rows_by_variant["relay5"])
    comparisons = [view for variant in result["variants"].values() for view in variant["views"].values()]
    for view, adjusted in zip(comparisons, holm([v["p_value"] for v in comparisons]), strict=True):
        view["p_holm_all_six_views"] = adjusted
    primary = [v["views"]["both"] for v in result["variants"].values()]
    for view, adjusted in zip(primary, holm([v["p_value"] for v in primary]), strict=True):
        view["p_holm_primary_both_views"] = adjusted
    result["status"] = "complete"
    save()


if __name__ == "__main__":
    main()

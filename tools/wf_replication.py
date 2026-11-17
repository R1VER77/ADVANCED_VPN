#!/usr/bin/env python3
"""Analyze a fresh three-variant replication; keep the historical A/B analyzer intact.

The primary analysis includes every monitored attempt with a packet-bracketed fixed
window, irrespective of browser status/resources. Resource filtering is secondary;
each held-out fold uses reference counts fitted on training rounds only. This tool
does not collect traffic or claim continuous protection from final snapshots.
"""

import argparse
import collections
import json
import math
from pathlib import Path
import statistics
import time

import wf_ab

VARIANTS = ("undefended", "relay30", "relay5")
ROUND_SEEDS = (1475067252, 929854378, 1997314573, 3200583649, 1259733358, 1713829992)


def validate_settings(settings, variant):
    """Do not mistake an unshaped positive control for another defended clock arm."""
    if variant not in VARIANTS:
        raise ValueError("unknown replication variant")
    if variant == "undefended":
        if settings.get("config") != "undefended" or settings.get("wire_clock_pps"):
            raise ValueError("positive control must be undefended with no wire clock")
    elif not (
        settings.get("config") == "fast"
        and str(settings.get("wire_clock_pps")) == "4000"
        and settings.get("wire_clock_downstream") is True
        and str(settings.get("wire_clock_relay_ms")) == variant.removeprefix("relay")
    ):
        raise ValueError("defended arm must record fast, 4000 pps, both directions and the matching relay clock")


def training_filter(rows, train, test, minimum=0.25):
    """Fit site references only on training rows; return retained train/test indices."""
    usual = wf_ab.resource_medians([rows[int(i)] for i in train])

    def keep(indices):
        return [int(i) for i in indices if wf_ab.accepted(rows[int(i)], usual, minimum)]

    return keep(train), keep(test), usual


def score(x, y, groups, rows, filtered=False):
    """Whole-round holdouts, with explicit exclusions and no held-out preprocessing fit."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import LeaveOneGroupOut

    if len(set(groups)) < 2:
        raise ValueError("at least two complete rounds required")
    correct = np.zeros(len(y), dtype=bool)
    evaluated = np.zeros(len(y), dtype=bool)
    folds = []
    for fold, (train, test) in enumerate(LeaveOneGroupOut().split(x, y, groups)):
        refs = {}
        if filtered:
            train, test, refs = training_filter(rows, train, test)
        if not len(train) or not len(test) or set(y[train]) != set(y):
            raise ValueError("a fold lost training classes or all training/test rows")
        model = RandomForestClassifier(n_estimators=500, random_state=fold, n_jobs=1)
        model.fit(x[train], y[train])
        correct[test] = model.predict(x[test]) == y[test]
        evaluated[test] = True
        folds.append(dict(round=int(groups[test[0]]), train=len(train), test=len(test), resource_references=refs))
    by_round = {
        str(g): dict(
            correct=int(correct[groups == g].sum()),
            evaluated=int(evaluated[groups == g].sum()),
            available=int((groups == g).sum()),
        )
        for g in sorted(set(groups))
    }
    return dict(
        accuracy=float(correct[evaluated].mean()),
        evaluated=int(evaluated.sum()),
        excluded=int((~evaluated).sum()),
        by_round=by_round,
        folds=folds,
    )


def accuracy_interval(by_round, seed=0):
    """Descriptive round-cluster bootstrap; six clusters cannot establish portability."""
    import numpy as np

    counts = np.array([(r["correct"], r["evaluated"]) for r in by_round.values()])
    rng = np.random.default_rng(seed)
    samples = counts[rng.integers(len(counts), size=(10000, len(counts)))].sum(axis=1)
    return list(map(float, np.percentile(samples[:, 0] / samples[:, 1], [2.5, 97.5])))


def load(root, variant):
    """Read one metadata-only capture at a time; retain failed browser attempts.

    Coverage presently requires observed packets bracketing each window. This is
    conservative for sparse/idle captures: excluded attempts remain in all-attempt
    costs and exclusion counts. Collector-level readiness/stop evidence is still
    needed to distinguish a genuinely silent interval from a stopped recorder.
    """
    import numpy as np
    import wf_deep

    # Infer encoder width without inventing packets for an empty observed trace.
    empty_features = np.zeros_like(wf_deep.kfp_features([np.array([[0.0, 1.0, 0.0]])])[0])
    features = {name: [] for name in ("both", "upstream_only", "downstream_only")}
    attempts, retained, excluded, sources = [], [], [], []
    directories = sorted(root.glob("r*-" + variant), key=wf_ab.round_number)
    for directory in directories:
        if sorted(p.name for p in directory.glob("w[0-9]*") if p.is_dir()) != ["w0"]:
            raise ValueError("replication requires exactly one worker per arm")
        worker = directory / "w0"
        settings = json.loads((worker / "settings.json").read_text())
        validate_settings(settings, variant)
        rows = [
            dict(json.loads(line), round=wf_ab.round_number(directory))
            for line in (worker / "loads.jsonl").read_text().splitlines()
        ]
        attempts.extend(rows)
        sources.append(
            dict(
                round=wf_ab.round_number(directory),
                settings=settings,
                loads_sha256=wf_ab.sha256(worker / "loads.jsonl"),
                packets_sha256=wf_ab.sha256(worker / "packets.bin"),
            )
        )
        path = worker / "packets.bin"
        if path.stat().st_size % wf_deep.RECORD.itemsize:
            raise ValueError("truncated capture record")
        capture = (
            np.memmap(path, dtype=wf_deep.RECORD, mode="r") if path.stat().st_size else np.empty(0, wf_deep.RECORD)
        )
        if len(capture) and (
            not np.isfinite(capture["t"]).all()
            or np.any(capture["n"] == 0)
            or np.any(capture["n"] > 65535)
            or np.any(capture["n"] < -65535)
        ):
            raise ValueError("invalid packet metadata")
        if np.any(capture["t"][1:] < capture["t"][:-1]):
            capture = capture[np.argsort(capture["t"], kind="stable")]
        for row in rows:
            reason = None
            if int(row["label"]) < 0:
                reason = "unmonitored"
            elif not isinstance(row.get("start"), (int, float)) or not math.isfinite(row["start"]):
                reason = "no_valid_browser_start"
            elif not len(capture) or capture["t"][0] > row["start"] or capture["t"][-1] < row["start"] + wf_deep.WINDOW:
                reason = "capture_does_not_bracket_fixed_window"
            if reason:
                excluded.append(dict(round=row["round"], site=row["site"], status=row.get("status"), reason=reason))
                continue
            lo, hi = np.searchsorted(capture["t"], [row["start"], row["start"] + wf_deep.WINDOW])
            part = capture[lo:hi]
            trace = np.column_stack([part["t"] - row["start"], np.sign(part["n"]), np.abs(part["n"])]).astype(float)
            trace = wf_deep.wire_packets(trace)
            for name, direction in (("both", None), ("upstream_only", 1), ("downstream_only", -1)):
                subset = trace if direction is None else trace[trace[:, 1] == direction]
                # The encoder needs a nonempty trace. Empty observations use an explicit
                # zero feature vector, never fabricated packets in the absent direction.
                vector = wf_deep.kfp_features([subset])[0] if len(subset) else empty_features.copy()
                features[name].append(vector)
            retained.append(row)
        del capture
    if not retained:
        raise ValueError("no bracketed monitored windows")
    return (
        {name: np.asarray(vectors) for name, vectors in features.items()},
        np.array([r["label"] for r in retained]),
        np.array([r["round"] for r in retained]),
        retained,
        attempts,
        excluded,
        sources,
    )


def costs(rows):
    """Every attempt counts even if it failed before a browser timestamp existed."""
    durations = [r["loaded"] - r["start"] for r in rows if r.get("status") == "ok" and "loaded" in r and "start" in r]
    return dict(
        attempts=len(rows),
        success=sum(r.get("status") == "ok" for r in rows),
        status_counts=dict(collections.Counter(r.get("status", "unknown") for r in rows)),
        successful_load_seconds_median=statistics.median(durations) if durations else None,
    )


def validate_matching(arms):
    """Require matched attempt order/seeds/rounds and one consistent site-label map."""
    reference = None
    labels, sites = {}, {}
    for rows, sources in arms:
        settings = {source["round"]: source["settings"] for source in sources}
        identity = []
        for row in rows:
            site, label = row["site"], row["label"]
            if site in labels and labels[site] != label or label >= 0 and label in sites and sites[label] != site:
                raise ValueError("inconsistent site-label mapping")
            labels[site] = label
            if label >= 0:
                sites[label] = site
            identity.append((row["round"], site, label, settings[row["round"]].get("load_order_seed")))
        if reference is not None and identity != reference:
            raise ValueError("variants differ in round/site/repeat order or recorded seed")
        reference = identity
    seeds = [s["settings"].get("load_order_seed") for s in arms[0][1]]
    if any(not isinstance(seed, int) for seed in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError("each round needs a distinct integer site-order seed")


def main():
    """Analyze the prespecified six-round experiment without overwriting prior results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--permutations", type=int, default=1000)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.permutations < 1000 or not 1 <= args.jobs <= 4:
        parser.error("use at least 1000 permutations and 1..4 jobs")
    # Reserve the output without overwriting an earlier result, including on failure.
    with args.out.open("x") as out:
        out.write(json.dumps(dict(status="loading", schema=1)) + "\n")
    import numpy as np
    import sklearn
    from joblib import Parallel, delayed, parallel_config

    data = {variant: load(args.run, variant) for variant in VARIANTS}
    validate_matching([(item[4], item[6]) for item in data.values()])
    for _, y, groups, _, attempts, _, sources in data.values():
        counts = collections.Counter((r["round"], r["label"]) for r in attempts)
        if (
            len(attempts) != 240
            or set(y) != set(range(20))
            or set(groups) != set(range(1, 7))
            or set(counts.values()) != {2}
        ):
            raise ValueError(
                "the prespecified experiment requires six rounds, 20 sites and two attempts per arm/site/round"
            )
        if [s["settings"]["load_order_seed"] for s in sources] != list(ROUND_SEEDS):
            raise ValueError("round seeds differ from the saved collection plan")
    result = dict(
        schema=1,
        status="running",
        analysis="fresh-control replication",
        variants={},
        versions=dict(numpy=np.__version__, sklearn=sklearn.__version__),
        analysis_sources={
            name: wf_ab.sha256(Path(__file__).with_name(name))
            for name in ("wf_replication.py", "wf_ab.py", "wf_deep.py", "wf_attack.py")
        },
        method=dict(
            primary="all bracketed monitored windows, including browser failures",
            secondary="resource filter fitted on training rounds only",
            permutations=args.permutations,
        ),
        limitations=[
            "Single host/network; round-bootstrap interval has few clusters",
            "Packet bracketing is conservative; no recorder liveness proof",
            "Final protection snapshots do not prove a continuously protected interval",
            "Counterbalanced arm timing/provenance must also be verified before interpreting results",
        ],
    )

    def save():
        args.out.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")

    primary_views = []
    for variant, (views, y, groups, rows, attempts, excluded, sources) in data.items():
        stats = result["variants"][variant] = dict(
            cost=costs(attempts),
            windows=len(rows),
            excluded=excluded,
            sources=sources,
            sites=len(set(y)),
            chance=1 / len(set(y)),
            views={},
        )
        for name, x in views.items():
            started = time.monotonic()
            primary = score(x, y, groups, rows)
            try:
                secondary = score(x, y, groups, rows, filtered=True)
            except ValueError as error:
                secondary = dict(status="unavailable", reason=str(error))
            with parallel_config(backend="loky", inner_max_num_threads=1):
                null = Parallel(n_jobs=args.jobs)(
                    delayed(wf_ab.null_score)(x, y, groups, seed) for seed in range(1, args.permutations + 1)
                )
            primary.update(
                ci95_round_bootstrap=accuracy_interval(primary["by_round"]),
                null_scores=null,
                p_value=(1 + sum(v >= primary["accuracy"] for v in null)) / (1 + len(null)),
            )
            stats["views"][name] = dict(
                primary=primary, secondary=secondary, seconds=round(time.monotonic() - started, 1)
            )
            primary_views.append(primary)
            save()
            print(variant, name, primary["accuracy"], flush=True)
    for view, p in zip(primary_views, wf_ab.holm([v["p_value"] for v in primary_views]), strict=True):
        view["p_holm_all_nine_primary_views"] = p
    result["status"] = "complete"
    save()


if __name__ == "__main__":
    main()

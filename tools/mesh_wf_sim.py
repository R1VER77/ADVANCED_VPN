#!/usr/bin/env python3
"""mesh_wf_sim: website-fingerprinting simulation for the AVPN/Mesh defense design.

Reproduces the mechanism comparison behind docs/MESH_DESIGN.md, measured on the
exit-side link (the vantage first-link-only defenses such as Mullvad's DAITA do
not protect): an observer there sees timing + direction of constant-size
packets after two hops of queueing jitter.

Defenses compared:
  none            - no shaping
  client_only     - constant-rate shaping at the client only (DAITA-style
                    placement); downstream jitter erodes the clock
  per_hop_grace   - per-hop re-shaping, cover only after an idle grace
  per_hop_full    - per-hop full constant-rate cover (duration quantum Qs)
  bidir_const_Qs  - bidirectional constant-rate streams on every link,
                    duration rounded to a Q-second quantum (Q in {4, 8, 16})

Requires numpy and scikit-learn (lab tool only; not part of the install).
Usage: python3 tools/mesh_wf_sim.py [--sites N] [--traces N] [--json]
"""

import argparse
import json

GRID_MS = 20.0  # constant-rate clock (matches daita.rs TAMARAW/COVER interval)
COVER_GRACE_MS = 400.0
ROUND_MS = 2000.0
JITTER_SIGMA = 12.0  # queueing noise per traversed hop


def make_sites(rng, n_sites):
    """Synthetic site profiles (burst counts, lengths, gaps)."""
    return [
        {
            "n_bursts_lam": rng.uniform(3, 10),
            "burst_len_mu": rng.uniform(0.8, 2.2),
            "burst_len_sig": rng.uniform(0.3, 0.7),
            "pkt_rate_ms": rng.uniform(1.5, 8.0),
            "gap_mu_ms": rng.uniform(80, 600),
            "gap_sig": rng.uniform(0.4, 0.9),
        }
        for _ in range(n_sites)
    ]


def gen_trace(rng, site):
    """One synthetic page-load trace (times, directions) for a site."""
    times, dirs, t, direction = [], [], 0.0, 1
    for _ in range(int(rng.poisson(site["n_bursts_lam"]) + 1) * 2):
        n = max(1, int(rng.lognormal(site["burst_len_mu"], site["burst_len_sig"])))
        for _ in range(n):
            t += rng.exponential(site["pkt_rate_ms"])
            times.append(t)
            dirs.append(direction)
        t += abs(rng.normal(site["gap_mu_ms"], site["gap_mu_ms"] * site["gap_sig"]))
        direction *= -1
    return times, dirs


def defense_none(rng, np, times, dirs):
    """No defense: the trace after two hops of queueing jitter."""
    t = np.array(times) + rng.normal(0, JITTER_SIGMA, len(times)) * np.sqrt(2)
    return t, np.array(dirs)


def defense_client_only(rng, np, times, dirs):
    """Constant-rate shaping at the client only."""
    tq = np.round(np.array(times) / GRID_MS) * GRID_MS
    for k in range(1, len(tq)):
        if tq[k] <= tq[k - 1]:
            tq[k] = tq[k - 1] + GRID_MS
    d = np.array(dirs)
    target = int(np.ceil(len(tq) / 100.0) * 100)
    while len(tq) < target:
        tq = np.append(tq, tq[-1] + GRID_MS)
        d = np.append(d, d[-1])
    return tq + rng.normal(0, JITTER_SIGMA, len(tq)) * np.sqrt(2), d


def defense_per_hop_grace(rng, np, times, dirs):
    """Per-hop re-shaping, cover only after an idle grace."""
    t, d = np.array(times, dtype=float), list(dirs)
    for _ in range(2):
        t = np.round(t / GRID_MS) * GRID_MS
        for k in range(1, len(t)):
            if t[k] <= t[k - 1]:
                t[k] = t[k - 1] + GRID_MS
        ft, fd = [t[0]], [d[0]]
        for k in range(1, len(t)):
            gap = t[k] - ft[-1]
            if gap > COVER_GRACE_MS:
                for _ in range(int((gap - COVER_GRACE_MS) // GRID_MS)):
                    ft.append(ft[-1] + GRID_MS)
                    fd.append(-fd[-1] if rng.random() < 0.5 else fd[-1])
            ft.append(t[k])
            fd.append(d[k])
        t, d = np.array(ft), fd
    end = np.ceil(t[-1] / ROUND_MS) * ROUND_MS
    while t[-1] < end:
        t = np.append(t, t[-1] + GRID_MS)
        d.append(-d[-1])
    return t + rng.normal(0, 1.0, len(t)), np.array(d)


def defense_per_hop_full(rng, np, times, dirs, quant_ms=4000.0):
    """Per-hop full constant-rate cover, duration rounded to a quantum."""
    end = np.ceil(times[-1] / quant_ms) * quant_ms
    n_slots = int(end / GRID_MS)
    grid_t = np.arange(1, n_slots + 1) * GRID_MS
    grid_d = rng.choice([-1, 1], size=n_slots)
    slot_of = np.minimum(np.ceil(np.array(times) / GRID_MS).astype(int), n_slots)
    for s in sorted(set(slot_of.tolist())):
        grid_d[s - 1] = dirs[list(slot_of).index(s)]
    return grid_t + rng.normal(0, 1.0, n_slots), grid_d


def defense_bidir_const(rng, np, times, dirs, quant_ms):
    """Bidirectional constant-rate streams, duration rounded to a quantum."""
    end = np.ceil(times[-1] / quant_ms) * quant_ms
    n_slots = int(end / GRID_MS)
    grid_t = np.arange(1, n_slots + 1) * GRID_MS
    out_t, out_d = [], []
    for direction in (1, -1):  # both directions always full: direction carries no info
        for s in range(n_slots):
            out_t.append(grid_t[s])
            out_d.append(direction)
    return np.array(out_t) + rng.normal(0, 1.0, len(out_t)), np.array(out_d)


def features(np, times, dirs, bins=40, bin_ms=150.0):
    """Timing and direction features for the classifier."""
    order = np.argsort(times)
    t, d = times[order], dirs[order]
    iat = np.diff(t) if len(t) > 1 else np.array([0.0])
    switches = np.where(np.diff(d) != 0)[0]
    runs = np.diff(switches) if len(switches) > 1 else np.array([len(d)])
    counts, _ = np.histogram(t, bins=bins, range=(0, bins * bin_ms))
    base = [
        len(t),
        t[-1] - t[0] if len(t) > 1 else 0,
        iat.mean(),
        iat.std() if len(iat) > 1 else 0,
        np.median(iat),
        (iat < 25).mean(),
        (iat > 100).sum(),
        (iat > 400).sum(),
        (d > 0).mean(),
        len(runs),
        runs.max() if len(runs) else 0,
    ]
    return np.concatenate([base, counts])


DEFENSES = {
    "none": defense_none,
    "client_only": defense_client_only,
    "per_hop_grace": defense_per_hop_grace,
    "per_hop_full": defense_per_hop_full,
    "bidir_const_4s": lambda r, n, t, d: defense_bidir_const(r, n, t, d, 4000.0),
    "bidir_const_8s": lambda r, n, t, d: defense_bidir_const(r, n, t, d, 8000.0),
    "bidir_const_16s": lambda r, n, t, d: defense_bidir_const(r, n, t, d, 16000.0),
}


def run(n_sites=10, n_traces=80, seed=42, defenses=None):
    """Score every defense with a random forest; returns accuracies and overheads."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score

    rng = np.random.default_rng(seed)
    sites = make_sites(rng, n_sites)
    names = defenses or list(DEFENSES)
    results = {}
    for name in names:
        fn = DEFENSES[name]
        X, y, overhead = [], [], []
        for s in range(n_sites):
            for _ in range(n_traces):
                raw = gen_trace(rng, sites[s])
                tt, dd = fn(rng, np, *raw)
                X.append(features(np, tt, dd))
                y.append(s)
                overhead.append(len(tt) / max(1, len(raw[0])))
        X, y = np.array(X), np.array(y)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.35, random_state=1, stratify=y)
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=1).fit(Xtr, ytr)
        results[name] = {
            "accuracy": round(float(accuracy_score(yte, clf.predict(Xte))), 4),
            "overhead_x": round(float(np.mean(overhead)), 1),
        }
    return {"sites": n_sites, "traces_per_site": n_traces, "chance": round(1 / n_sites, 4), "results": results}


def main():
    """Command-line entry point."""
    p = argparse.ArgumentParser()
    p.add_argument("--sites", type=int, default=10)
    p.add_argument("--traces", type=int, default=80)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    out = run(args.sites, args.traces, args.seed)
    if args.json:
        print(json.dumps(out))
    else:
        print(f"closed-world WF, exit-side vantage, chance = {out['chance']:.0%}")
        for name, r in out["results"].items():
            print(f"  {name:<18} accuracy {r['accuracy']:.1%}   overhead {r['overhead_x']}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

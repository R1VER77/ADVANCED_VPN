#!/usr/bin/env python3
"""Closed-world website-fingerprinting attack on a tools/daita_lab.py run.

Decodes both captures with tshark (Wireshark), cuts out every page load, turns each into
a k-FP-style feature vector (counts, directions, bursts, ordering, timing, packets per
0.25 s) plus CUMUL (cumulative signed size at 50 points), and scores a 500-tree random
forest with stratified 5-fold cross-validation. It attacks two views of the same loads:
  inner link  relay <-> exit QUIC: constant cells, no DAITA (GSO super-frames split)
  carrier     client <-> relay WireGuard + DAITA: what the client's ISP sees

Windows: by default each load runs from its true start to its true end plus --tail
seconds, which hands the attacker where every page ended. --fixed S instead gives every
load the same S seconds from its true start, the fairer view of a constant-rate stream.

usage: wf_attack.py RUN_DIR [RUN_DIR ...] [--tail 3] [--fixed 6]
Needs scikit-learn, numpy and Docker with an image `avpn-tshark:1` that has tshark
(Debian trixie-slim plus the tshark package). Not run in CI.
"""

import argparse
import collections
import json
from pathlib import Path
import subprocess

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict

UP = {"192.0.2.2", "198.51.100.1"}


def packets(run, pcap):
    """(time, direction, UDP length) of every UDP packet; GSO super-frames split into wire packets."""
    cmd = ["docker", "run", "--rm", "-v", "%s:/d:ro" % run, "avpn-tshark:1", "tshark", "-r", "/d/" + pcap,
           "-Y", "udp && !icmp", "-T", "fields", "-E", "separator=,", "-E", "occurrence=f",
           "-e", "frame.time_epoch", "-e", "ip.src", "-e", "udp.length"]  # fmt: skip
    rows = []
    for line in subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines():
        t, src, n = line.split(",")
        rows.append((float(t), 1 if src in UP else -1, int(n)))
    big = [n for _, _, n in rows if 1000 < n <= 1500]
    seg = collections.Counter(big).most_common(1)[0][0] if big else 1500
    out = []
    for t, d, n in rows:
        k = -(-(n - 8) // (seg - 8)) if n > 1500 else 1
        out += [(t, d, seg if k > 1 else n)] * k
    out.sort()
    return np.array(out)


def features(tr):
    """k-FP-style features and CUMUL for one trace of (time, direction, size) rows."""
    t, d, n = tr[:, 0] - tr[0, 0], tr[:, 1], tr[:, 2]
    up, dn = d > 0, d < 0
    f = [len(d), up.sum(), dn.sum(), up.mean(), (n * up).sum(), (n * dn).sum(), t[-1]]
    f += [up[:30].sum(), dn[:30].sum(), up[-30:].sum(), dn[-30:].sum()]
    runs, cur = [], 1  # bursts: runs of the same direction
    for i in range(1, len(d)):
        if d[i] == d[i - 1]:
            cur += 1
        else:
            runs.append(cur * d[i - 1])
            cur = 1
    runs.append(cur * d[-1])
    runs = np.array(runs)
    for r in (-runs[runs < 0], runs[runs > 0]):
        f += [len(r), r.max(initial=0), r.mean() if len(r) else 0, r.std() if len(r) else 0]
    pos = np.nonzero(up)[0]
    f += [pos.mean() if len(pos) else 0, pos.std() if len(pos) else 0]
    for m in (np.ones_like(up), up, dn):
        g = np.diff(t[m]) if m.sum() > 1 else np.zeros(1)
        f += [g.mean(), g.std(), g.max(), *np.percentile(g, [25, 50, 75])]
    chunks = [c.sum() for c in np.array_split(up.astype(int), max(1, len(up) // 20))]
    f += [np.mean(chunks), np.std(chunks), np.max(chunks)]
    f += list(np.histogram(t, bins=40, range=(0, 10))[0])
    cum = np.cumsum(d * n)
    f += list(np.interp(np.linspace(0, len(cum) - 1, 50), np.arange(len(cum)), cum))
    return f


def attack(run, tail, fixed):
    """Cross-validated accuracy of the attack on both views of one lab run."""
    run = Path(run).resolve()
    meta = json.loads((run / "phases.json").read_text())
    loads = [p for p in meta["phases"] if p.get("site")]
    res = dict(defense=meta["defense"], loads=len(loads), sites=len({p["site"] for p in loads}),
               window="fixed %g s" % fixed if fixed else "true end + %g s" % tail)  # fmt: skip
    for name, pcap in (("inner link (no DAITA)", "inner_link.pcap"), ("carrier (DAITA)", "client_link.pcap")):
        pk = packets(run, pcap)
        X, y = [], []
        for p in loads:
            end = p["load_start"] + fixed if fixed else p["load_end"] + tail
            w = pk[(pk[:, 0] >= p["load_start"] - 0.05) & (pk[:, 0] <= end)]
            if len(w) > 1:
                X.append(features(w))
                y.append(p["site"])
        X, y = np.array(X, dtype=float), np.array(y)
        rf = RandomForestClassifier(n_estimators=500, random_state=0, n_jobs=-1)
        pred = cross_val_predict(rf, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=0))
        res[name] = dict(
            accuracy=round(float((pred == y).mean()), 3),
            chance=round(1 / len(set(y)), 3),
            per_site={s: round(float((pred[y == s] == s).mean()), 2) for s in sorted(set(y))},
        )
    res["mean_load_seconds"] = round(float(np.mean([p["load_end"] - p["load_start"] for p in loads])), 2)
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--tail", type=float, default=3.0)
    ap.add_argument("--fixed", type=float, default=0.0)
    a = ap.parse_args()
    for r in a.runs:
        print(json.dumps(attack(r, a.tail, a.fixed), indent=1))

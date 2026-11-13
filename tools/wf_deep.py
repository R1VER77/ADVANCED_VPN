#!/usr/bin/env python3
"""Website fingerprinting on real browser traces: the attacks.

Reads collections made by tools/wf_real.py (per worker: packets.bin, the (time, signed
size) of every packet on the client's link, and loads.jsonl, one row per page load) and
attacks them the ways the literature does:

  k-FP      random forest on k-FP-style features + CUMUL (tools/wf_attack.py features)
  DF        Deep Fingerprinting (Sirinam et al., CCS 2018): a 1-D CNN on the direction
            sequence, first 5,000 packets
  Tik-Tok   (Rahman et al., PETS 2020): the same network on direction x timestamp

Closed world: the monitored sites only, stratified 5-fold cross-validation; chance is
1 / number of sites. Open world: the monitored loads plus loads of unmonitored sites (one
extra class); reported as the true-positive rate (a monitored load named as its own site)
and false-positive rate (an unmonitored load named as any monitored site), with precision.

Validity gate: an attack's numbers on a defended configuration are reported only if the
same attack first wins on the undefended baseline (closed-world accuracy >= --gate). An
attack that cannot fingerprint the undefended tunnel proves nothing about a defence.

DeepCorr (flow correlation) needs the same flows captured at entry and exit; these
collections capture the client's link only, so it is not run here.

usage: wf_deep.py --run undefended=DIR [--run fast=DIR ...] --out RESULT.json
           [--gate 0.8] [--epochs 30] [--attacks kfp,df,tiktok]
Needs numpy, scikit-learn and (DF, Tik-Tok) PyTorch. Not run in CI.
"""

import argparse
import json
from pathlib import Path
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

WINDOW = 12.0  # tools/wf_real.py keeps each load's first 12 s
SEQ = 5000  # DF / Tik-Tok input length (packets)
RECORD = np.dtype([("t", "<f8"), ("n", "<i4")])


def load_run(run, window=WINDOW, min_resources=0.25):
    """[(label, site, trace)] for every successful load in a collection. trace rows are
    (seconds since the load started, direction +1 out / -1 in, IP length).

    A load the browser itself saw fail is dropped: fewer resources than `min_resources`
    of its site's median in this collection (the browser's count, not the wire's, so the
    rule is the same with or without a defence). Rows without the count are kept."""
    out, rows = [], []
    for w in sorted(Path(run).glob("w*")):
        pk, lj = w / "packets.bin", w / "loads.jsonl"
        if not pk.exists() or not lj.exists():
            continue
        p = np.fromfile(pk, dtype=RECORD)
        p = p[np.argsort(p["t"], kind="stable")]
        for line in lj.read_text().splitlines():
            rows.append((p, json.loads(line)))
    usual = {}
    for site in {r["site"] for _, r in rows}:
        counts = [r["resources"] for _, r in rows if r["site"] == site and r.get("resources") is not None]
        usual[site] = float(np.median(counts)) if counts else None
    for p, r in rows:
        # A load still in progress when the browser stopped waiting (30 s) captured its
        # whole fixed window all the same; only browser failures carry no trace.
        if r.get("status") not in ("ok", "TimeoutException"):
            continue
        if r.get("resources") is not None and usual[r["site"]] and r["resources"] < min_resources * usual[r["site"]]:
            continue
        lo, hi = np.searchsorted(p["t"], [r["start"], r["start"] + window])
        seg = p[lo:hi]
        if len(seg) < 2:
            continue
        tr = np.column_stack([seg["t"] - r["start"], np.sign(seg["n"]), np.abs(seg["n"])]).astype(float)
        out.append((int(r["label"]), r["site"], tr))
    return out


def direction_seq(tr, n=SEQ):
    """DF input: packet directions, zero-padded or cut to n."""
    x = np.zeros(n, dtype=np.float32)
    d = tr[:n, 1]
    x[: len(d)] = d
    return x


def tiktok_seq(tr, n=SEQ):
    """Tik-Tok input: direction x timestamp (seconds since the load started)."""
    x = np.zeros(n, dtype=np.float32)
    d = tr[:n, 1] * np.maximum(tr[:n, 0], 1e-3)
    x[: len(d)] = d
    return x


def df_model(classes, length=SEQ):
    """The DF network (Sirinam et al. 2018, Table 3), in PyTorch."""
    import torch.nn as nn

    def block(cin, cout, act):
        return [
            nn.Conv1d(cin, cout, 8, padding="same"), nn.BatchNorm1d(cout), act(),
            nn.Conv1d(cout, cout, 8, padding="same"), nn.BatchNorm1d(cout), act(),
            nn.MaxPool1d(8, stride=4, padding=2), nn.Dropout(0.1),
        ]  # fmt: skip

    layers = block(1, 32, nn.ELU) + block(32, 64, nn.ReLU) + block(64, 128, nn.ReLU) + block(128, 256, nn.ReLU)
    n = length
    for _ in range(4):
        n = (n + 2 * 2 - 8) // 4 + 1
    return nn.Sequential(
        *layers, nn.Flatten(),
        nn.Linear(256 * n, 512), nn.BatchNorm1d(512), nn.ReLU(), nn.Dropout(0.7),
        nn.Linear(512, 512), nn.BatchNorm1d(512), nn.ReLU(), nn.Dropout(0.5),
        nn.Linear(512, classes),
    )  # fmt: skip


def train_predict_nn(xtr, ytr, xte, classes, epochs, seed=0):
    """Train DF on (xtr, ytr); class probabilities for xte."""
    import torch

    torch.manual_seed(seed)
    torch.set_num_threads(max(1, torch.get_num_threads()))
    model = df_model(classes, xtr.shape[1])
    opt = torch.optim.Adamax(model.parameters(), lr=0.002)
    loss = torch.nn.CrossEntropyLoss()
    xt, yt = torch.from_numpy(xtr[:, None, :]), torch.from_numpy(ytr.astype(np.int64))
    g = torch.Generator().manual_seed(seed)
    for _ in range(epochs):
        model.train()
        # At least four optimizer steps per epoch: with fewer samples than one batch, DF
        # takes one step an epoch and cannot fit even its own training set.
        for idx in torch.randperm(len(xt), generator=g).split(max(8, min(64, len(xt) // 4))):
            if len(idx) < 2:
                continue
            opt.zero_grad()
            loss(model(xt[idx]), yt[idx]).backward()
            opt.step()
    model.eval()
    with torch.no_grad():
        return torch.softmax(model(torch.from_numpy(xte[:, None, :])), 1).numpy()


def train_predict_rf(xtr, ytr, xte, classes, epochs=None, seed=0):
    """k-FP's random forest; class probabilities for xte (all classes, in order)."""
    from sklearn.ensemble import RandomForestClassifier

    rf = RandomForestClassifier(n_estimators=500, random_state=seed, n_jobs=-1).fit(xtr, ytr)
    p = np.zeros((len(xte), classes))
    p[:, rf.classes_] = rf.predict_proba(xte)
    return p


def kfp_features(traces, seq=None):
    """k-FP features + CUMUL per trace (tools/wf_attack.py), NaN-free."""
    from wf_attack import features

    return np.nan_to_num(np.array([features(tr) for tr in traces], dtype=float))


ATTACKS = {
    "kfp": (kfp_features, train_predict_rf),
    "df": (lambda trs, seq=SEQ: np.stack([direction_seq(t, seq) for t in trs]), train_predict_nn),
    "tiktok": (lambda trs, seq=SEQ: np.stack([tiktok_seq(t, seq) for t in trs]), train_predict_nn),
}


def cross_validate(x, y, classes, fit, epochs, folds=5):
    """Out-of-fold class probabilities for every sample (stratified k-fold)."""
    from sklearn.model_selection import StratifiedKFold

    prob = np.zeros((len(y), classes))
    for k, (tr, te) in enumerate(StratifiedKFold(folds, shuffle=True, random_state=0).split(x, y)):
        prob[te] = fit(x[tr], y[tr], x[te], classes, epochs=epochs, seed=k)
    return prob


def evaluate(loads, attack, epochs, seq=SEQ):
    """Closed- and open-world results of one attack on one collection. `seq` is the DF /
    Tik-Tok input length (5,000 as published; shorter only for short synthetic traces)."""
    feats, fit = ATTACKS[attack]
    mon = [(lb, tr) for lb, _, tr in loads if lb >= 0]
    unmon = [tr for lb, _, tr in loads if lb < 0]
    sites = sorted({lb for lb, _ in mon})
    index = {s: i for i, s in enumerate(sites)}
    y = np.array([index[lb] for lb, _ in mon])
    counts = np.bincount(y)
    folds = int(min(5, counts.min())) if len(counts) else 0
    if len(sites) < 2 or folds < 2:
        return dict(error="too few loads")
    x = feats([tr for _, tr in mon], seq)
    t0 = time.time()
    prob = cross_validate(x, y, len(sites), fit, epochs, folds)
    res = dict(
        sites=len(sites), loads=len(y), folds=folds, chance=round(1 / len(sites), 4),
        closed_world_accuracy=round(float((prob.argmax(1) == y).mean()), 4),
    )  # fmt: skip
    if unmon:
        xo = np.concatenate([x, feats(unmon, seq)])
        yo = np.concatenate([y, np.full(len(unmon), len(sites))])  # the extra class: unmonitored
        po = cross_validate(xo, yo, len(sites) + 1, fit, epochs, folds)
        pred = po.argmax(1)
        is_mon = yo < len(sites)
        said_mon = pred < len(sites)
        tp = int((said_mon & is_mon & (pred == yo)).sum())
        fp = int((said_mon & ~is_mon).sum())
        wrong = int((said_mon & is_mon & (pred != yo)).sum())
        res["open_world"] = dict(
            unmonitored_loads=len(unmon),
            tpr=round(tp / is_mon.sum(), 4),
            fpr=round(fp / max(1, (~is_mon).sum()), 4),
            precision=round(tp / max(1, tp + fp + wrong), 4),
        )
    res["seconds"] = round(time.time() - t0, 1)
    return res


def main():
    """Command line: attack every run, the undefended baseline first."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--run", action="append", required=True, help="NAME=DIR (one must be 'undefended')")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--gate", type=float, default=0.8, help="undefended closed-world accuracy an attack must reach")
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--attacks", default="kfp,df,tiktok")
    a = p.parse_args()
    runs = dict(r.split("=", 1) for r in a.run)
    if "undefended" not in runs:
        raise SystemExit("an undefended baseline run is required: the attacks must win there first")
    attacks = a.attacks.split(",")
    result = dict(window_seconds=WINDOW, gate=a.gate, attacks=attacks, configs={},
                  deepcorr="not run: needs entry and exit captures of the same flows")  # fmt: skip
    order = ["undefended"] + [n for n in runs if n != "undefended"]
    valid = {}
    for name in order:
        loads = load_run(runs[name])
        row = dict(loads=len(loads), monitored=sum(lb >= 0 for lb, _, _ in loads))
        for atk in attacks:
            r = evaluate(loads, atk, a.epochs)
            if name == "undefended":
                valid[atk] = r.get("closed_world_accuracy", 0) >= a.gate
                r["passes_baseline_gate"] = valid[atk]
            elif not valid[atk]:
                r = dict(withheld="attack did not win on the undefended baseline", **r)
            row[atk] = r
            print(name, atk, json.dumps(r), flush=True)
        result["configs"][name] = row
    a.out.write_text(json.dumps(result, indent=1) + "\n")


if __name__ == "__main__":
    main()

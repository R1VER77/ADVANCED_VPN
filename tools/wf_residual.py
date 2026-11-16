#!/usr/bin/env python3
"""Where is a defence's residual k-FP signal? Each direction alone and both, each against
shuffled-label runs, plus the features the forest leans on.

Scores one variant of a real-website collection (tools/wf_real.py, combined as
rerun_analyze does: DIR/all-VARIANT/w1..wN) with the pipeline of tools/wf_deep.py, and
writes DIR/RESIDUAL_VARIANT.json. Feature indices are tools/wf_attack.py `features`
(21-26 all-packet gaps, 27-32 upstream gaps, 33-38 downstream gaps: mean, sd, max, p25,
p50, p75). Not CI: needs a collection and numpy/scikit-learn.

usage: python3 tools/wf_residual.py RUN_DIR [--variant clock] [--permutations 100]
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wf_deep  # noqa: E402


def score(x, y, classes):
    """Out-of-fold closed-world accuracy (wf_deep's random forest)."""
    return float((wf_deep.cross_validate(x, y, classes, wf_deep.train_predict_rf, None).argmax(1) == y).mean())


def main():
    """Command line."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("run", type=Path)
    p.add_argument("--variant", default="clock")
    p.add_argument("--permutations", type=int, default=100)
    a = p.parse_args()
    loads = wf_deep.load_run(str(a.run / ("all-" + a.variant)))
    mon = [(lb, tr) for lb, _, tr in loads if lb >= 0]
    sites = sorted({lb for lb, _ in mon})
    index = {s: i for i, s in enumerate(sites)}
    y = np.array([index[lb] for lb, _ in mon])
    out = dict(run=str(a.run), variant=a.variant, loads=len(y), sites=len(sites), permutations=a.permutations)
    for label, keep in (("both", None), ("upstream_only", 1), ("downstream_only", -1)):
        trs = [tr if keep is None else tr[tr[:, 1] == keep] for _, tr in mon]
        # k-FP needs both directions present: the removed one becomes one dummy packet.
        trs = [t if len(t) > 1 else np.array([[0.0, 1.0, 100.0], [0.0, -1.0, 100.0]]) for t in trs]
        x = wf_deep.kfp_features(trs)
        real = score(x, y, len(sites))
        rng = np.random.default_rng(1)
        perms = [score(x, rng.permutation(y), len(sites)) for _ in range(a.permutations)]
        rf = RandomForestClassifier(n_estimators=500, random_state=0, n_jobs=4).fit(x, y)
        top = np.argsort(rf.feature_importances_)[::-1][:8]
        out[label] = dict(
            real=round(real, 4),
            perm_mean=round(float(np.mean(perms)), 4),
            perm_p95=round(float(np.percentile(perms, 95)), 4),
            perm_max=round(max(perms), 4),
            p_value=round((1 + sum(v >= real for v in perms)) / (a.permutations + 1), 4),
            top_features=[(int(i), round(float(rf.feature_importances_[i]), 4)) for i in top],
        )
        print(label, out[label], flush=True)
    (a.run / ("RESIDUAL_%s.json" % a.variant)).write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()

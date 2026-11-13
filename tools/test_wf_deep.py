"""wf_deep: trace extraction from a collection, the encoders, and that each attack wins on
separable traces and falls to chance when the labels carry no information."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
HAVE = {m: importlib.util.find_spec(m) is not None for m in ("numpy", "sklearn", "torch")}

if HAVE["numpy"]:
    import numpy as np

    import wf_deep


def write_collection(root, sites=4, loads=10, unmonitored=0, shuffle_labels=False, seed=1):
    """A synthetic collection: site k's loads send (k+1)-packet bursts of a site-specific
    size, at a site-specific pace. Loads follow each other in one capture, as a worker's do."""
    rng = np.random.default_rng(seed)
    w = Path(root) / "w0"
    w.mkdir(parents=True)
    recs, rows, t = [], [], 1_000_000.0
    plan = [(k, k) for k in range(sites) for _ in range(loads)] + [(sites + i, -1) for i in range(unmonitored)]
    for kind, label in plan:
        start = t
        n_pk = 300 + 60 * (kind % 7)
        times = start + np.sort(rng.uniform(0, 3 + kind % 5, n_pk))
        for i, tt in enumerate(times):
            up = (i // (kind % 4 + 1)) % 3 == 0
            recs.append((tt, (200 + 40 * kind) if up else -(1400 - 37 * kind)))
        lab = label
        if shuffle_labels and label >= 0:
            lab = int(rng.integers(sites))
        rows.append(dict(site="s%d.test" % kind, label=lab, start=start, end=start + 12, status="ok"))
        t += 20
    rows.append(dict(site="fail.test", label=0, start=t, end=t + 12, status="WebDriverException"))
    recs.append((t + 1, 100))
    arr = np.array(recs, dtype=wf_deep.RECORD)
    rng.shuffle(arr)  # capture order is not trusted: the loader sorts by time
    arr.tofile(w / "packets.bin")
    (w / "loads.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


@unittest.skipUnless(HAVE["numpy"], "needs numpy")
class LoaderTests(unittest.TestCase):
    def test_a_load_the_browser_saw_fail_is_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            write_collection(d, sites=2, loads=3)
            lj = Path(d) / "w0" / "loads.jsonl"
            rows = [json.loads(x) for x in lj.read_text().splitlines()]
            for i, r in enumerate(rows):
                r["resources"] = 3 if i == 0 else 40  # load 0: the browser got almost nothing
            lj.write_text("".join(json.dumps(r) + "\n" for r in rows))
            kept = wf_deep.load_run(d)
            everything = wf_deep.load_run(d, min_resources=0)
        self.assertEqual(len(everything), 6)
        self.assertEqual(len(kept), 5)

    def test_windows_failed_loads_and_encoders(self):
        with tempfile.TemporaryDirectory() as d:
            write_collection(d, sites=2, loads=2)
            loads = wf_deep.load_run(d)
        self.assertEqual(len(loads), 4)  # the failed load is dropped
        for label, site, tr in loads:
            self.assertEqual(site, "s%d.test" % label)
            self.assertTrue((tr[:, 0] >= 0).all() and (tr[:, 0] < wf_deep.WINDOW).all())
            self.assertTrue((np.diff(tr[:, 0]) >= 0).all())
            self.assertEqual(set(np.unique(tr[:, 1])), {-1.0, 1.0})
            d = wf_deep.direction_seq(tr)
            self.assertEqual(d.shape, (wf_deep.SEQ,))
            self.assertTrue((d[: len(tr)] == tr[:, 1]).all() and not d[len(tr) :].any())
            k = wf_deep.tiktok_seq(tr)
            self.assertTrue((np.sign(k[: len(tr)]) == tr[:, 1]).all())


def run(attack, epochs=8, seq=1024, **k):
    # seq: the synthetic traces are under 700 packets, so 1,024 inputs hold all of them.
    with tempfile.TemporaryDirectory() as d:
        write_collection(d, **k)
        return wf_deep.evaluate(wf_deep.load_run(d), attack, epochs=epochs, seq=seq)


@unittest.skipUnless(HAVE["numpy"] and HAVE["sklearn"], "needs numpy and scikit-learn")
class KfpTests(unittest.TestCase):
    def test_wins_on_separable_traces_and_in_the_open_world(self):
        r = run("kfp", unmonitored=12)
        self.assertGreaterEqual(r["closed_world_accuracy"], 0.9)
        self.assertGreaterEqual(r["open_world"]["tpr"], 0.8)
        self.assertLessEqual(r["open_world"]["fpr"], 0.2)

    def test_falls_to_chance_when_labels_carry_nothing(self):
        r = run("kfp", shuffle_labels=True)
        self.assertLess(r["closed_world_accuracy"], 0.5)


@unittest.skipUnless(HAVE["numpy"] and HAVE["sklearn"] and HAVE["torch"], "needs numpy, scikit-learn, torch")
class NeuralTests(unittest.TestCase):
    # The pilot's scale: 30 loads per site (DF needs data; at 10 per site it underfits).
    def test_df_and_tiktok_win_on_separable_traces(self):
        for attack in ("df", "tiktok"):
            r = run(attack, epochs=20, loads=30)
            self.assertGreaterEqual(r["closed_world_accuracy"], 0.9, (attack, r))

    def test_df_falls_to_chance_when_labels_carry_nothing(self):
        r = run("df", epochs=20, loads=30, shuffle_labels=True)
        self.assertLess(r["closed_world_accuracy"], 0.5)


if __name__ == "__main__":
    unittest.main()

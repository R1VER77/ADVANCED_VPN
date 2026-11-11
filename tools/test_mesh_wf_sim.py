#!/usr/bin/env python3
"""Tests for tools/mesh_wf_sim.py: the mechanism ordering must hold.

Skipped when numpy/scikit-learn are unavailable (lab-only dependencies).
Keeps the corpus small so it runs in seconds.
"""

import importlib.util
import unittest

HAVE_DEPS = all(importlib.util.find_spec(m) for m in ("numpy", "sklearn"))


@unittest.skipUnless(HAVE_DEPS, "numpy/scikit-learn not installed (lab tool deps)")
class TestWfSim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import mesh_wf_sim
        cls.out = mesh_wf_sim.run(n_sites=5, n_traces=24, seed=7)

    def acc(self, name):
        return self.out["results"][name]["accuracy"]

    def test_chance_level_reported(self):
        self.assertAlmostEqual(self.out["chance"], 0.2, places=3)

    def test_undefended_is_highly_visible(self):
        self.assertGreater(self.acc("none"), 0.5)

    def test_client_only_shaping_fails_at_the_exit_vantage(self):
        # DAITA-style placement: shaping only at the client does not survive
        # two hops of queueing jitter. It must stay far above chance.
        self.assertGreater(self.acc("client_only"), self.out["chance"] + 0.2)

    def test_per_hop_cover_beats_client_only(self):
        self.assertLess(self.acc("per_hop_full"), self.acc("client_only"))

    def test_bidirectional_constant_rate_approaches_chance(self):
        # The design target: at a 16 s duration quantum the classifier must be
        # within 15 points of chance (5 sites here; docs show 10-site runs).
        self.assertLess(self.acc("bidir_const_16s"), self.out["chance"] + 0.15)

    def test_bidirectional_beats_single_stream_cover(self):
        self.assertLess(self.acc("bidir_const_16s"), self.acc("per_hop_full"))

    def test_cover_costs_bandwidth(self):
        self.assertGreater(self.out["results"]["bidir_const_16s"]["overhead_x"], 5)


if __name__ == "__main__":
    unittest.main()

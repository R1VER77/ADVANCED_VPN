"""The busy-CPU leak probe's scoring (`throughput_bench.py --cpu-probe`).

On a busy CPU the shaper skips grid ticks it misses, so the client's wire rate dips while
the CPU is loaded: the leak behind 81% k-FP accuracy on real sites (WF_REAL_PILOT.json).
The probe loads the client's cores on a random schedule and scores how well per-window
packet counts reveal it. These tests prove the scoring finds a planted dip, finds nothing
in a constant stream, and that its shuffled-label control sits at chance.
"""

import json
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from throughput_bench import (
    WIRE_SEGMENT,
    carrier_health,
    clock_windows,
    leak_score,
    load_schedule,
    window_counts,
    window_timing,
)

WINDOW = 1.0
RATE = 4000  # packets/s, the `fast` class


def bunch(t, start, period=0.05, stall=0.02):
    """Catch-up's signature: nothing is sent during a stall at the start of each period,
    then the missed packets go out together when the clock catches up."""
    slot, offset = divmod(t - start, period)
    return start + slot * period + stall if offset < stall else t


def stream(schedule, drop, rng, start=100.0, jitter=0.02, noise=0.01, bunched=False):
    """Synthetic first-hop records (time, IPv4 size, outgoing flag): a constant-rate
    stream whose rate falls by `drop` in loaded windows, with timing jitter and an
    independent `noise` (standard deviation) in each window's count. The
    hop's own sends (outgoing=1) never change: they are not on the loaded CPU."""
    records = []
    for k, loaded in enumerate(schedule):
        n = int(RATE * WINDOW * (1 - drop if loaded else 1) * (1 + rng.gauss(0, noise)))
        for i in range(n):
            t = start + k * WINDOW + (i + 0.5) * WINDOW / n + rng.uniform(-jitter, jitter) / RATE
            if bunched and loaded:
                t = bunch(t, start)
            records.append((t, WIRE_SEGMENT + 28, 0))
        for i in range(RATE):
            records.append((start + k * WINDOW + i / RATE, WIRE_SEGMENT + 28, 1))
    return records


class LeakScoreTests(unittest.TestCase):
    def score(self, drop, seed=1, windows=60):
        rng = random.Random(seed)
        schedule = load_schedule(windows, rng)
        counts = window_counts(stream(schedule, drop, rng), 100.0, WINDOW, windows)
        return schedule, leak_score(counts, schedule, random.Random(seed + 1), permutations=500)

    def test_the_schedule_is_balanced_and_random(self):
        a = load_schedule(60, random.Random(1))
        b = load_schedule(60, random.Random(2))
        self.assertEqual((sum(a), len(a)), (30, 60))
        self.assertNotEqual(a, b)

    def test_a_dip_under_load_is_found(self):
        _, s = self.score(drop=0.15)
        self.assertGreater(s["auc"], 0.95)
        self.assertLess(s["p_value"], 0.01)
        self.assertAlmostEqual(s["drop_under_load"], 0.15, places=2)

    def test_a_small_dip_is_still_found(self):
        # 2% fewer packets per loaded window is invisible by eye and must still show.
        _, s = self.score(drop=0.02)
        self.assertLess(s["p_value"], 0.01)

    def test_a_constant_stream_shows_nothing(self):
        _, s = self.score(drop=0.0)
        self.assertGreater(s["p_value"], 0.05)
        self.assertLess(abs(s["auc"] - 0.5), 0.1)

    def test_the_shuffled_label_control_sits_at_chance(self):
        _, s = self.score(drop=0.15)
        self.assertLess(abs(s["control_auc_mean"] - 0.5), 0.03)

    def test_only_the_clients_direction_is_counted_and_edges_are_trimmed(self):
        rng = random.Random(3)
        schedule = [1, 0]
        records = stream(schedule, 0.5, rng, noise=0)
        counts = window_counts(records, 100.0, WINDOW, 2)
        # Middle 80% of each window: 0.8 x 2000 loaded, 0.8 x 4000 idle (the hop's own
        # 4000 pps in the other direction are not counted).
        self.assertAlmostEqual(counts[0], 1600, delta=5)
        self.assertAlmostEqual(counts[1], 3200, delta=5)

    def full_score(self, drop, bunched, seed=1, windows=60):
        rng = random.Random(seed)
        schedule = load_schedule(windows, rng)
        records = stream(schedule, drop, rng, bunched=bunched)
        counts = window_counts(records, 100.0, WINDOW, windows)
        timing = window_timing(records, 100.0, WINDOW, windows)
        return leak_score(counts, schedule, random.Random(seed + 1), permutations=500, timing=timing)

    def test_catch_up_keeps_the_count_but_its_timing_is_caught(self):
        # Measured locally (CPU_LEAK_PROBE.json): with AVPN_CATCH_UP_MS=50 the count per
        # window is restored while the gap spread still gives the load away.
        s = self.full_score(drop=0.0, bunched=True)
        self.assertGreater(s["p_value"], 0.01, "the count alone must not see it")
        self.assertLess(s["gap_sd"]["p_value"], 0.01)
        self.assertTrue(s["leak"])

    def test_a_constant_stream_shows_nothing_on_any_feature(self):
        for seed in (1, 2, 3):
            s = self.full_score(drop=0.0, bunched=False, seed=seed)
            self.assertFalse(s["leak"], s)
            self.assertLess(abs(s["gap_sd"]["control_auc_mean"] - 0.5), 0.03)

    def test_the_clock_trace_is_summed_per_probe_window(self):
        # 100 ms buckets on CLOCK_MONOTONIC; the probe started at monotonic 50.0 s.
        trace = [
            [500, 400, 1, 0, 1, 600, 0],  # 50.0 s: window 0
            [509, 400, 2, 0, 3, 900, 0],  # 50.9 s: window 0
            [510, 380, 0, 20, 7, 4500, 1],  # 51.0 s: window 1
            [499, 400, 0, 0, 0, 0, 0],  # before the probe: ignored
            [530, 400, 0, 0, 0, 0, 0],  # after it: ignored
        ]
        w = clock_windows(trace, 50.0, 1.0, 2)
        self.assertEqual(w["fed"], [800, 380])
        self.assertEqual(w["skipped"], [0, 20])
        self.assertEqual(w["late"], [4, 7])
        self.assertEqual(w["late_max_us"], [900, 4500], "the largest lateness, not a sum")
        self.assertEqual(w["unslotted"], [0, 1])

    def test_gso_super_frames_count_as_the_segments_they_carry(self):
        records = [(100.5, 28 + 4 * WIRE_SEGMENT, 0)]
        self.assertEqual(window_counts(records, 100.0, WINDOW, 1), [4])


class CarrierHealthTests(unittest.TestCase):
    def test_both_directions_and_the_clients_reconnects_are_reported(self):
        from avpnctl import runtime_dir

        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"AVPN_RUNTIME_ROOT": tmp + "/run"}):
            state = Path(tmp) / "state"
            for role, sent, received in [("client", 10, 400), ("relay", 4000, 12)]:
                (state / role).mkdir(parents=True)
                rt = runtime_dir(state / role)
                (rt / "cloak-status.json").write_text(
                    json.dumps(dict(role=role, sent=sent, received=received, dropped=0, sessions=1, clock=None))
                )
            (runtime_dir(state / "client") / "core.lab.log").write_text(
                '{"event":"tunnel_ready"}\n{"event":"reconnecting"}\n{"event":"reconnecting"}\n'
            )
            (state / "exit").mkdir()  # no cloak: left out
            h = carrier_health(state)
        self.assertEqual(h["relay"]["sent"], 4000)
        self.assertEqual(h["client"]["received"], 400)
        self.assertEqual(h["client_reconnects"], 2)
        self.assertNotIn("exit", h)


if __name__ == "__main__":
    unittest.main()

"""The timing attacker works where it should and fails where mixing and cover deny it."""

from pathlib import Path
import random
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gpa  # noqa: E402

N = 10
DURATION = 1200.0


def poisson(rng, rate, end):
    t, out = 0.0, []
    while True:
        t += rng.expovariate(rate)
        if t >= end:
            return out
        out.append(t)


def mix_delay(rng, hops=5, mu=5.0):
    """Five Poisson mix delays (the gateway, three layers, the service node), mean 0.2 s each."""
    return sum(rng.expovariate(mu) for _ in range(hops)) + 0.01


class AttackTests(unittest.TestCase):
    def test_a_low_latency_path_gives_the_sender_away(self):
        rng = random.Random(1)
        sends, arrivals, delays = {}, [], []
        for c in range(N):
            sends[c] = poisson(rng, 1 / 20, DURATION)  # only real requests, as a VPN carries them
            for s in sends[c]:
                d = rng.gauss(0.05, 0.01)
                delays.append(d)
                arrivals.append((s + d, c))
        r = gpa.summary(gpa.attack(sends, arrivals, gpa.DelayModel(delays)), N)
        self.assertGreater(r["top1_accuracy"], 0.95, r)
        self.assertLess(r["effective_anonymity_set"], 1.3, r)

    @staticmethod
    def covered(seed, mu):
        rng = random.Random(seed)
        sends, arrivals, delays = {}, [], []
        for c in range(N):
            # Every client sends at 1/s whatever it has (real-or-drop); a real request
            # takes a slot when one is waiting.
            slots = poisson(rng, 1.0, DURATION)
            sends[c] = slots
            for s in rng.sample(slots, len(slots) // 20):
                d = mix_delay(rng, mu=mu)
                delays.append(d)
                arrivals.append((s + d, c))
        return gpa.summary(gpa.attack(sends, arrivals, gpa.DelayModel(delays)), N)

    def test_mixing_with_cover_leaves_a_wide_anonymity_set(self):
        # Poisson mixing is probabilistic: the attacker still uses where each client's
        # sends happened to fall, so it stays above chance, but far from a low-latency path.
        r = self.covered(2, 5.0)
        self.assertLess(r["top1_accuracy"], 0.35, r)
        self.assertGreater(r["effective_anonymity_set"], 6, r)

    def test_longer_mixing_delays_weaken_the_attacker(self):
        short, long_ = self.covered(4, 5.0), self.covered(4, 1.0)
        self.assertLess(long_["top1_accuracy"], short["top1_accuracy"])
        self.assertGreater(long_["effective_anonymity_set"], short["effective_anonymity_set"])
        self.assertLess(long_["top1_accuracy"], 0.2, long_)

    def test_mixing_without_cover_still_leaks(self):
        # The control: delays alone, with clients sending only when they have something,
        # leave the attacker well above chance. Cover traffic is what closes it.
        rng = random.Random(3)
        sends, arrivals, delays = {}, [], []
        for c in range(N):
            sends[c] = poisson(rng, 1 / 20, DURATION)
            for s in sends[c]:
                d = mix_delay(rng)
                delays.append(d)
                arrivals.append((s + d, c))
        r = gpa.summary(gpa.attack(sends, arrivals, gpa.DelayModel(delays)), N)
        self.assertGreater(r["top1_accuracy"], 0.5, r)

    def test_summary_shares_ties(self):
        r = gpa.summary([([0, 1], 0, 1.0), ([2], 1, 0.0)], 4)
        self.assertEqual(r["top1_accuracy"], 0.25)


if __name__ == "__main__":
    unittest.main()

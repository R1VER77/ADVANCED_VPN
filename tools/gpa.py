"""A global passive adversary's end-to-end timing attack.

It sees every client's link (when each client sends, never what) and every request that
leaves the network towards a destination (when, never who sent it), and it knows the
network's delay distribution exactly (learned from the lab's ground truth, the strongest
assumption). For each request it scores every client by how well that client's sends
explain the request's arrival, then guesses the best-scoring client.

On a low-latency path a request leaves shortly after its sender sent it, so the sender
stands out. On a mixnet every client sends at the same Poisson rate whether or not it has
anything to say (cover traffic) and each hop holds packets for a random time, so no client
stands out: accuracy falls towards 1/N and the posterior's entropy towards log2(N).
"""

import bisect
import math


class DelayModel:
    """A delay density estimated from observed delays (seconds): a histogram on a fixed
    grid with a small floor, so an unseen delay is unlikely but never impossible."""

    def __init__(self, delays, bins=200, floor=1e-6):
        delays = sorted(d for d in delays if d >= 0)
        if not delays:
            raise ValueError("no delays to learn from")
        self.width = max(delays[int(0.999 * (len(delays) - 1))], 1e-3) * 1.2
        self.bins = bins
        counts = [0] * bins
        for d in delays:
            if d < self.width:
                counts[int(d / self.width * bins)] += 1
        step = self.width / bins
        total = sum(counts) or 1
        self.density = [max(c / total / step, floor) for c in counts]
        self.floor = floor

    def pdf(self, d):
        """Density of delay `d` seconds."""
        if d < 0 or d >= self.width:
            return 0.0
        return self.density[int(d / self.width * self.bins)]


def attack(sends, arrivals, model):
    """`sends`: client -> sorted send times; `arrivals`: [(time, true client)].
    Returns per-arrival (guess, truth, posterior entropy in bits)."""
    out = []
    clients = sorted(sends)
    for t, truth in arrivals:
        scores = {}
        for c in clients:
            times = sends[c]
            lo = bisect.bisect_left(times, t - model.width)
            hi = bisect.bisect_right(times, t)
            scores[c] = sum(model.pdf(t - s) for s in times[lo:hi])
        total = sum(scores.values())
        if total <= 0:
            # Nothing explains it: every client is equally likely.
            post = {c: 1 / len(clients) for c in clients}
        else:
            post = {c: v / total for c, v in scores.items()}
        best = max(post.values())
        # Ties are broken uniformly: credit the attacker 1/k when the truth is among k tied.
        tied = [c for c, v in post.items() if v == best]
        entropy = -sum(p * math.log2(p) for p in post.values() if p > 0)
        out.append((tied, truth, entropy))
    return out


def summary(results, n_clients):
    """Top-1 accuracy (ties shared), chance, mean entropy and effective anonymity set."""
    if not results:
        raise ValueError("no arrivals")
    hits = sum((1 / len(tied)) if truth in tied else 0 for tied, truth, _ in results)
    entropy = sum(h for _, _, h in results) / len(results)
    return dict(
        arrivals=len(results),
        clients=n_clients,
        top1_accuracy=round(hits / len(results), 4),
        chance=round(1 / n_clients, 4),
        mean_entropy_bits=round(entropy, 3),
        max_entropy_bits=round(math.log2(n_clients), 3),
        effective_anonymity_set=round(2**entropy, 2),
    )

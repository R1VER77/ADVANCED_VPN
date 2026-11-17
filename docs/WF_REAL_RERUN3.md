# Relay look-ahead: real-website A/B, 17 November 2026

A 5 ms relay look-ahead improved observed page-load success and latency compared with
30 ms, but missed substantially more clock slots and did not establish privacy parity.
Both settings retain a classification signal in this collection. Keep the wire clock
experimental and its defaults unchanged pending a better controlled replication.

The complete numbers, null scores, input hashes and analysis-source hashes are in
[`evidence/WF_REAL_RERUN3.json`](evidence/WF_REAL_RERUN3.json).

## Collection and comparison

Five rounds each collected 40 page loads under each setting: 20 monitored sites, two
loads per site, 400 attempts total. The browser and client shared CPU IDs 0–1; the relay,
exit and capture used CPU IDs 2–3. The host was on mains power with the powersave governor.
Both variants used the client and relay wire clocks; only the relay look-ahead changed.
The client setting was held constant; the launch script supplied no override of its
30 ms code default. That global setting was not explicitly recorded in this collection;
future collection settings now record it.

Collection used `cfd79af` plus the experimental override/metadata patch later committed
as `448ab4f`. The setup implementation was integrated after collection, and installed
release binaries were not upgraded. Analysis source is `9164507`; its exact hashes and
the optional analysis environment versions are recorded in the evidence file.

| Measure | Relay 30 ms | Relay 5 ms |
|---|---:|---:|
| Browser attempts | 200 | 200 |
| Successful page loads | 182 (91.0%) | 193 (96.5%) |
| Successful-load median | 8.97 s | 8.39 s |
| Successful-load p90 | 18.10 s | 17.45 s |
| Captured monitored windows | 199 | 200 |
| Windows retained by the legacy resource filter | 192 | 198 |
| Legacy random-fold full-trace classification | 8.85% | 10.61% |
| Whole-round holdout full-trace classification | 10.94% | 15.15% |
| Final-protected-snapshot subset classification | 12.23% | 13.71% |
| Relay skipped clock-slot fraction | 0.00145% | 0.572% |

Among 200 matched attempts, 5 ms gained 16 successes and lost five: an observed gain of
5.5 percentage points. Resampling the 20 site clusters gives a 95% bootstrap interval
of 0–12.5 points, so improvement across sites remains uncertain. Among the 177 pairs
that succeeded under both settings, the median latency change was −0.514 seconds.
Successful-only latency excludes failed loads and is reported separately from success.

## Fingerprinting method and uncertainty

The analysis reuses the project's k-FP-style 500-tree random forest, features and
12-second fixed observation windows. GSO super-frames are expanded with the existing
loader. These are virtual-link captures of real browser loads, not a new independent
attack implementation or a physical-NIC validation.

Two split methods are reported. The existing stratified random-fold score preserves
comparability with earlier reports. The added leave-one-round-out score keeps every
test round out of training. A synthetic memorization control shows why this matters:
random splits can learn round-local tokens that fail on a new round.

Each whole-round score is compared with 100 complete retrainings after independently
permuting site-label maps within each round. Repeated loads of a site stay together.
The two full-trace scores exceed all 100 corresponding null scores: empirical
one-sided p = 1/101 each, or 0.0198 after Holm adjustment across those two full-trace
tests. This detects label-associated structure in this collection; it does not identify
its cause or test the difference between the two variants' attack accuracies.

Direction-only views are exploratory. Adjusting across all six views gives a smallest
p of 0.0594, which does not meet a six-view family-wise 5% threshold. The 100-permutation
budget limits resolution. Per-round counts, per-site descriptive scores and an
all-valid-window sensitivity check accompany the aggregate scores. A global accuracy
near 1/20 would not by itself establish that every site is hidden.

## Collection limitations

- Every capture reused the same shuffled site/repeat order because the collector used
  seed 7 on every invocation. Holding out rounds cannot remove an artifact that repeats
  with that order. Future runs must vary the seed between rounds and record it.
- Variant order was always 30 ms then 5 ms. It was interleaved, but neither randomized
  nor counterbalanced. There was no fresh undefended positive control in this A/B run.
- Four 30 ms loads and one 5 ms load ended with a blocked/reconnecting snapshot, all for
  the same site label. One of those 5 ms loads nevertheless had browser status `ok`:
  browser success is not a protection verdict. All five passed the resource filter. Excluding them does not
  remove the full-trace classification signal, but that exclusion is post-hoc and the
  snapshot is not continuous evidence for the entire observation window.
- The legacy filter uses per-site browser-resource medians from the whole collection.
  It can change the retained sample mix. Results with every valid captured window are
  therefore also reported. Browser failures remain in all usage-cost denominators.
- Hardware tests, short Python checks, documentation publishing and desktop activity
  overlapped collection. Measured binaries/controller source were frozen, but the host
  was not completely idle.
- This remains a 20-site closed world on one host/network. There is no new open-world,
  neural-attack, held-out-day, held-out-device or cross-link-correlation result.

## Interpretation and next gate

The relay feeder skipped 110,658 slots at 5 ms versus 291 at 30 ms, normalized in the
table by fed plus skipped slots. The source defines a skipped slot as a feeder deadline
miss. A shorter buffer leaves less room for scheduling stalls, consistent with these
counters. Skipped cover slots are not necessarily lost data packets, and aggregate
counters do not prove the classifier's mechanism.

The present result does not justify promoting 5 ms. It also prevents treating the
earlier single-run chance-level score as a general guarantee for 30 ms. Defaults remain
unchanged.

The prepared follow-up uses six counterbalanced rounds of `undefended`, `relay30` and
`relay5`, with a different recorded site-order seed per round and the same seed across
variants within a round. It includes a fresh positive control, explicit failed-load and
snapshot reporting, stable collection conditions, and the same held-out-round checks.
That is 720 attempts; it has **not** been started. Broader sites, days, networks and
devices remain necessary before a deployment claim.

The collector now accepts and propagates `--seed`, records the seed and fails the parent
command if any worker fails. Its default seed stays 7 for reproduction of old runs.
Use different explicit seeds for new rounds. This A/B analyzer reads single-worker
collections and now refuses multi-worker inputs rather than silently scoring only `w0`.

To reproduce the offline scoring with the optional numpy/scikit-learn environment:

```sh
python tools/wf_ab.py /path/to/rerun3 --out RESULT.json --permutations 100 --jobs 2
```

This command reads captures only. It does not visit websites, provision servers, modify
VPN settings or activate a new defense default.

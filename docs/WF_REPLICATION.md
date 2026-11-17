# Fresh-control replication analysis

Implementation-plan task 2, started 17 November 2026. The collection has not started;
this document records analysis tooling, not a passed traffic-resistance gate.

`tools/wf_replication.py` analyzes the six-round, three-variant experiment recorded in
[the implementation plan](IMPLEMENTATION_PLAN_20261117.md). The historical
`tools/wf_ab.py` and published prior results retain their original semantics.

```sh
/path/to/analysis-environment/bin/python tools/wf_replication.py \
    /private/path/to/collection --out /private/path/to/new-result.json \
    --permutations 1000 --jobs 2
```

The output path must not exist. Raw captures and browser errors remain private.
The analyzer makes no network requests.

Implemented:

- Fresh `undefended` control plus `relay30`/`relay5`; recorded defended settings must
  identify `fast`, 4000 pps, downstream shaping and the matching relay look-ahead.
- One worker per arm; six rounds, 20 labels, two attempts per site/arm/round; the
  recorded site-order seeds must match the saved plan. Attempts and label/site maps
  must match across arms.
- Primary whole-round holdouts include all monitored attempts with a bracketed
  12-second capture window, including browser exceptions and low resource counts.
  Every attempted load stays in browser costs; capture exclusions have reasons.
- Packet metadata only; reject partial records and invalid metadata. Empty observed
  directions have zero feature vectors rather than invented packets.
- Secondary resource references are fitted on training rounds and applied to the
  held-out round. An unavailable secondary analysis does not suppress the primary.
- Fixed 500-tree forest; at least 1,000 round-grouped label-map permutations;
  Holm adjustment across the nine primary variant/direction comparisons.
- Descriptive round-cluster bootstrap intervals; six clusters are insufficient to
  establish generalization across days, networks or devices.

Still required before collection/interpretation:

- Recorder readiness, stop evidence and coverage checks. Packet bracketing is a
  conservative interim check: sparse windows can be excluded even when recording
  ran, and it does not prove absence of a mid-window recorder stall or packet drops.
- Protection observations throughout each load and a separate metadata-only escape
  audit. Final snapshots cannot establish continuous protection.
- A runner that freezes source/binary/browser/tool hashes, enforces all six arm
  permutations, records arm start/stop times, prevents overlap and checks the 2 GiB
  free-space reserve. Load-order seeds do not prove arm-order counterbalancing.
- Paired control-relative success/latency uncertainty, source/protection validity
  reporting, and the prespecified operational acceptance-gate evaluation. Accuracy,
  confidence intervals and corrected p-values alone do not close the gate.
- A full positive-control and classifier-permutation execution on collected data.
  Unit fixtures do not qualify the attack on real websites.

Local regression cases exercise held-out reference poisoning, active-clock control
mislabeling, failed loads without timestamps, complete failed-browser windows,
missing capture directions and unfiltered-versus-secondary evaluation counts.
All six new cases passed in the optional numerical environment, as did the seven
historical A/B cases. The ordinary Python suite ran 610 tests successfully with 21
explicit skips; numerical cases are run separately because NumPy/scikit-learn are
optional research dependencies. Ruff and formatting checks passed.

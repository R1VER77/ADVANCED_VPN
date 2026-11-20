# Fresh-control replication analysis

Implementation-plan task 2, started 17 November 2026. Recorder and browser smoke
tests have passed; controlled replication remains a separate measurement gate.

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

Prepare a private, new experiment directory after completing builds and smoke tests:

```sh
.venv/bin/python tools/wf_experiment.py prepare \
    --out /private/new-experiment --sites /private/twenty-sites-two-loads.json \
    --bin-dir target/release --pasta /path/to/pasta \
    --geckodriver /path/to/geckodriver --browser-python /path/to/browser-venv/bin/python \
    --ethtool /path/to/ethtool --firefox /usr/bin/firefox-esr
.venv/bin/python tools/wf_experiment.py run /private/new-experiment
```

The runner records hashes of frozen tools/binaries, browser/interpreter executables
and package inventories, the tracked source diff and its source commit. A host lock
prevents overlapping experiments. It enforces the counterbalanced order, checks its
2 GiB reserve and records host/power/pressure conditions. Changed inputs, active
builds, battery operation and failed arms stop the run while preserving evidence.

Implemented collection and analysis:

- Fresh `undefended` control plus `relay30`/`relay5`; recorded defended settings must
  identify `fast`, 4000 pps, downstream shaping and the matching relay look-ahead.
- One worker per arm; six rounds, 20 labels, two attempts per site/arm/round; the
  recorded site-order seeds must match the saved plan. Attempts and label/site maps
  must match across arms.
- Primary whole-round holdouts include all monitored attempts with a verified
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
- Kernel time64 packet timestamps, explicit recorder readiness/clean stop, heartbeat
  coverage and packet-socket drop counters. Missing coverage or drops invalidate the
  corresponding capture gate; genuinely silent, covered windows remain included.
- Read-only controller observations throughout loads, with private-inode freshness,
  process-identity and evidence-age checks. Unknown samples remain visible.
- An underlay metadata allowlist for the configured peer/port, ARP and narrowly bounded
  link-local IPv6 router solicitations. Unexpected outgoing traffic fails the arm.
- Actual arm timing/order checks, frozen-analysis matching, per-site results,
  control-relative latency/success and uncertainty resampling both rounds and sites.
- Explicit local acceptance checks for attackable controls, classifier upper bounds,
  corrected signals, availability, capture validity and sampled protection. Full-view
  control accuracy must reach 80%; directional controls must exceed chance by five
  percentage points with corrected significance. Defaults remain unchanged.

Interpretation and remaining gates:

- Half-second protection observations do not establish continuous protection between
  samples. Metadata allowlisting is not a proof about application-payload secrecy.
- The existing fallback packet-bracketing loader supports historical inspection only;
  it cannot qualify a fresh replication lacking the new recorder/protocol evidence.
- A local pass cannot replace the required three days, two networks and two physical
  devices, larger/open-world datasets, cross-link analysis or independent review.
- A full positive-control and classifier-permutation execution on collected data.
  Unit fixtures do not qualify the attack on real websites.

Local regression cases exercise held-out reference poisoning, active-clock control
mislabeling, failed loads without timestamps, complete failed-browser windows,
missing capture directions and unfiltered-versus-secondary evaluation counts.
The historical first analysis batch passed six then-new cases and seven A/B cases;
its ordinary suite ran 610 tests with 21 explicit skips. The expanded recorder,
protocol and acceptance cases are recorded with the main implementation progress.
Numerical cases need the optional NumPy/scikit-learn environment. Unit fixtures do
not replace positive-control measurements.

## Result: the frozen run of 20 November 2026 (cloud host)

The full six-round, 720-attempt schedule ran to completion on one GCP VM (europe-west4,
one network), frozen from source commit `efb2bc4` (manifest `2a500356…`, run `3a593e94…`),
then analysed with 1,000 permutations (NumPy 2.5.4, scikit-learn 1.9.1). Every capture
window was valid: kernel timestamps, zero drops, bracketed heartbeats, underlay audit
passed. Raw captures stay private (an archive is kept with the owner).

| Arm | Both directions | Upstream only | Downstream only | Loads succeeded | Median load |
|---|---|---|---|---|---|
| undefended | **100%** (Holm p 0.009) | 97.1% (0.009) | 99.6% (0.009) | 240/240 | 1.24 s |
| relay30 | 3.8% [2.9, 4.6] (1.0) | 8.3% [5.0, **12.1**] (0.18) | 5.8% [2.9, 9.2] (0.92) | 235/240 | 3.27 s |
| relay5 | 8.3% [5.4, **11.7**] (0.18) | 7.1% [4.2, **10.4**] (0.52) | 3.8% [2.9, 4.6] (1.0) | 234/240 | 2.70 s |

Primary k-FP accuracy over 20 sites (chance 5%), with the round-bootstrap 95% interval and
the Holm-adjusted p value across the nine primary views.

What it shows:
- The attack works on this setup: the undefended control is identified almost perfectly in
  every view, so the defended results are not a weak classifier.
- Both defended arms bring accuracy to near chance, and no defended view keeps a
  statistically significant signal after correction (all Holm p ≥ 0.18).

The frozen local acceptance gate nevertheless **failed**, on three checks for each arm:
- **Classifier upper bound** (the 95% upper bound must not exceed chance + 5 points, 10%):
  relay30 upstream reaches 12.1%; relay5 both-directions 11.7% and upstream 10.4%. A faint
  residual signal cannot be excluded at this sample size.
- **Load success non-inferiority** (the lower bound of the success difference must be
  ≥ −5 points): relay30 −6.3, relay5 −7.1 points. The defence loses about 2–3% of loads, and
  adds a median 1.4–1.9 s per load.
- **Sampled protection**: one window per arm had unprotected samples, 2 and 1 of 6,232.

So defaults stay unchanged (`promotes_default: false`), and this run does not qualify as an
external replication: one host, one network and closed-world sites remain the limits listed
above.


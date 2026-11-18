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

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

## Follow-up on 25 November 2026

The three unexpected samples in the frozen capture were `blocked`, with the
kill switch reported active, a fresh status generation, and live supervisor and
child identities. In the `relay30` window the old observer reported `blocked`
once while the controller lifecycle still read `connected`, followed by one
`reconnecting` sample. The `relay5` window had one `reconnecting` sample. The
underlay metadata audit found zero unexpected outgoing packets. This evidence
leaves the sampled-protection gate failed. The sample interval and metadata
scope limit what it can establish about continuous protection or application
payloads. The observer now records both the controller verdict and the
freshness of cloak, carrier and path-probe evidence. A monitored attempt
without a valid browser start now fails the capture gate.

### Cross-link timing in the mix lab

Re-scored five archived ten-client mix-lab captures with
[`tools/mix_holdout.py`](../tools/mix_holdout.py). Each phase uses one delay
histogram fitted on DNS events in its first half and measures sender ranking
only on requests sent in its second half. DNS events must align with exactly one
logged request for the name. Each matched request contributes at most one event.
The observed lab links are client ingress and exit DNS, with no packet payloads
used for sender ranking.

| Archived configuration | Low-latency proxy top-1 | Mix lane top-1 |
| --- | ---: | ---: |
| X-Wing with post-quantum PKI (`xwing-pq`) | 97.2% (65 events) | 6.8% (148 events) |
| Earlier X-Wing configuration (`xwing`) | 97.7% (77 events) | 14.4% (139 events) |
| Post-quantum PKI sweep, base | 95.7% (62 events) | 9.6% (141 events) |
| Post-quantum PKI sweep, base-r2 | 95.6% (73 events) | 12.5% (144 events) |
| Post-quantum PKI sweep, base-r3 | 98.7% (67 events) | 7.0% (142 events) |

Random ranking is 10% for ten candidates. In an exploratory split into five
equal-duration held-out time blocks, the earlier X-Wing mix lane scored 9/25,
3/34, 1/26, 5/29 and 2/25. The first block reached 36%. The three sweep
runs match the recorded `xwing-pq` PKI, fetch plugin, Sphinx packet geometry
and delay and cover parameters. Their highest blocks reached 19.4%, 24.0%
and 14.8%, respectively. All five blocks in the original `xwing-pq` run were
below 10%. Relabeling sender identities globally across the held-out
events preserves repeated-sender groups. Of 10,000 sampled relabelings, with
the standard plus-one correction, 6.4% matched or exceeded the earlier X-Wing
overall score. When taking the maximum of the same five blocks on each draw,
0.25% reached the observed 36%. The relabeling assumes exchangeable sender
labels. The block analysis was added after collection. All five runs come from
the same day and leave the size, cause and repeatability of the higher scores
uncertain.

Keep sender unlinkability unqualified pending a controlled repeat. Freeze the
overall and worst-window criteria before collecting independent runs of the same
configuration, retain the low-latency positive control, and capture queue
occupancy, cover traffic and workload bursts to help isolate the cause if the
elevated block recurs. Cross-link correlation of the default low-latency VPN on
independent WAN paths requires its own measurement.

#### Timing-margin candidate

Ten plausible senders give an informed observer a 10% floor from random
guessing alone. A below-10% requirement needs a larger plausible sender
pool. Identifiable cover clients contribute traffic but are excluded from
the sender count. A score under the random-guessing floor can reflect a weak
classifier or sampling variation.

The archived 100 ms, full-rate runs reached 4.5%, 7.9% and 5.0% on the
held-out half of each capture. Their worst blocks reached 8.3%, 15.8% and
10.8%. Across the two runs with ten identifiable extra cover clients, the
observer could still reach 12.9% and 10.3% in the worst blocks when it
ranked the ten measured clients. These same-day results select a candidate
for fresh trials. The `mix_lab.py --profile timing-margin --seed SEED` profile runs 20 scored
clients through X-Wing Sphinx and hybrid PKI with 100 ms mean per hop,
one real-or-drop slot per second and 0.5 loops per second per client. Each
client sends live requests. The baseline is 5% with all 20 plausible.

Score the resulting capture with
`python3 tools/mix_holdout.py RUN --out REPORT --require-margin`. For a
trial to pass, the held-out delay scorer and the sender-frequency prior
trained on the earlier half must both score at most 8% overall and in every
one of five equal-duration held-out blocks. The gate also checks for all
20 clients in the held-out requests and on the wire in every block, at
least 50 matched arrivals per block, at least 75% held-out match coverage,
a positive control of at least 80% across at least 60 events, and at least 90% live-fetch
success within five points of the control. The 8% cutoff leaves a two-point
margin against the 10% target. It is an empirical acceptance threshold.

The first full trial on 25 November passed every check. On 395 matched
held-out requests, the delay scorer reached 3.3% overall and 4.4% in its
highest block. The sender-frequency prior reached 4.8% overall and 6.6%
in its highest block. Random guessing remains 5%. The low-latency control
scored 97.9% on 97 events. All 793 mix requests met the live-fetch criterion.
The measured p90 was 4.08 seconds and client uplink averaged 559 kbit/s.
The trial used 20 lab clients on one host and network.

A second seed on the same day and host doubled the request rate from one
request every 30 seconds per client on average to one every 15 seconds.
It passed every check. The delay scorer reached 3.2% overall and 5.4% in
its highest block across 713 matched held-out requests. The sender-frequency
prior reached 4.6% overall and 6.2% in its highest block. The low-latency
control reached 96.6% on 179 events. Of 1,616 mix requests, 1,567 (97.0%)
met the live-fetch criterion, compared with 371/371 on the control.
The measured p90 was 4.18 seconds and client uplink averaged 564 kbit/s.

Keep production qualification open until this frozen protocol passes on
independent days and networks with distinct workload seeds. Include busy
and low-occupancy periods, repeat with a wider set of timing observers, and
measure bandwidth, latency and request delivery. An operator would have to
enforce the qualifying network parameters and reject or defer use when the
plausible sender pool cannot be established. The current client accepts
operator-supplied directories and cannot establish the live sender pool.

### Operator independence

The enrolled two-hop route uses two providers and one operator. The project’s
provider table assigns both providers to the same legal sphere. The local mesh directory
had zero verified, unexpired descriptors at the time of inspection. There is no
observed pool of unrelated operators or shared-exit users in this deployment
from which to estimate a production anonymity set.

### Physical-laptop transfer pilot

The exploratory pilot uses separate 500-tree forests for `relay30` and the
undefended control. Each is fitted on the 240 fixed windows from that arm in
the archived cloud run. On a physical laptop and a different network, each
pilot arm attempts those 20 domains and 10 domains absent from training once.
The saved plan fixes site order, arm order and a 0.5 acceptance threshold on
the model score before collection. Both arms preserve all attempts and use the
same 12-second windows. The relay30 arm runs first, so order effects are still
possible. This is an exploratory transfer measurement on one held-out device
and network.

The first control arm stopped after 14 loads when the host monitor detected a
concurrent build or inference process. The complete replacement arm used the
same site order. The defended arm completed 23 of 30 browser loads against
30 of 30 in the replacement control. Both arms stopped capture cleanly with
zero recorder drops and zero unexpected outgoing metadata. The defended arm
had no unexpected protection samples in the 30 fixed windows. Its observer
recorded 44 stale path-probe samples outside those windows, including two
before the first window. A fixed-window pass provides limited coverage of
connection behavior during longer browser attempts and between windows.

The aggregate-only analyzer is [`tools/wf_environment_holdout.py`](../tools/wf_environment_holdout.py).
It checks matched site sets and capture validity and reports known-site
accuracy alongside unseen-site acceptance at the fixed threshold. A successful
undefended transfer must reach the existing 80% positive-control accuracy gate
to support interpretation of the defended classifier's performance.

| Pilot arm | Known-site top-1 | Known sites accepted and correct at 0.5 | Unseen sites accepted at 0.5 |
| --- | ---: | ---: | ---: |
| Undefended | 10/20 (50%) | 7/20 | 2/10 |
| `relay30` | 1/20 (5%) | 0/20 | 0/10 |

The undefended transfer missed the 80% gate. The low defended score therefore
does not establish resistance to a classifier trained in the test environment
or trained on more diverse data. The load success gap also warrants a matched
availability investigation before wider testing. The aggregate record includes
the original archive integrity check, the two timing holdouts and both pilot
arms. [Evidence](evidence/PRIVACY_FOLLOWUP_20261125.json)

### Next collection gates

- Repeat the full counterbalanced schedule across at least three days, two
  networks and two physical devices, with a fresh undefended control in each
  environment. Hold out whole environments and keep failed loads in the
  denominator. Measure shared-CPU and power conditions alongside page success
  and protection validity.
- Qualify a larger open-world set with a decision rule fixed on development
  data. Report false acceptance, known-site recall, and uncertainty from the
  held-out devices and networks.
- For the default VPN, collect synchronized metadata from the owned entry and
  exit paths with explicit clock-error bounds, known request assignments and
  a low-latency positive control. Hold out complete sessions, days and paths.
- Measure shared-exit activity and route concentration with independently
  operated nodes. Count operational control domains as well as provider names
  and report the observed anonymity set for the measured interval.


# GPA lab plan — from simulation to live sites

The lab exists to answer one question before users depend on the lane:
**can an adversary with two observation points link a cell across an honest
hop?** Everything else (delivery, delay, replay) is engineering; this is the
security claim.

## Tier 1 — simulation (built, passing)

`tests/lab.rs` in this crate. What each check pins:

| Check | Property | Status |
|---|---|---|
| `lab_delivery_replay_tagging_linkability_and_delays` | 24 clients over 6 mixes, v=3: delivery, replay caught, tagged cell dies silently, **no 64-byte window shared between any two links**, Erlang(3, μ) delays, accounting closes | passing |
| `lab_payloads_arrive_intact` | end-to-end AEAD opens byte-exactly through real MixNodes | passing |
| `lab_queue_pressure_protects_data_over_cover` | Little's-law queue: data survives, cover sacrificed | passing |

The linkability check is the one that found R3 (payload region static
across links) and R4 (dead cover region static across links). Both are now
fixed and regression-tested at two levels (sphinx-local `r4_*` test + the
lab assertion).

Known residue, accepted: the 4-byte fixed prefix
(`version || n_hops || flags || reserved`) is identical on every link by
necessity (every mix parses it). It cannot span a 64-byte window and is
equivalent to a protocol magic number.

## Tier 2 — local soak (daemon, once built)

- 10 local mix nodes, 72 h, scripted load: 50 cells/s aggregate, 20% cover.
- Flood drills (each 10 min, 10× rate): replay flood, corrupt-cell flood,
  cover flood. Pass = only cover degrades; accounting stays closed;
  `ReplayCache::overflows` may rise but delivery ratio for honest traffic
  stays ≥ 99.9%.
- Delay telemetry: per-hop empirical CDF vs Erlang(μ); alert if KS
  statistic > 0.05 (would indicate timing leakage in scheduling).

## Tier 3 — live-site pilot (G2)

Cohort: opt-in flag, ≤ 100 clients, ≥ 4 geographically diverse mixes
operated by at least 2 independent operators.

**Observer probes (the core of the tier):** two independent collectors,
each tapping one mix's ingress link (with operator consent, in the pilot
contract), positioned as hop 1 and hop 3 of probe paths. Probes send
flagged-but-otherwise-normal cells through known paths. The collectors
exchange only 64-byte window sketches (bloom filters) of observed cells.

- Null hypothesis: window matches between the two taps occur only by chance.
  With ~2^12 windows per side out of 2^512 window space, expected shared
  count under H0 is ~0; ANY verified match is a finding.
- This is exactly the check that caught R3/R4 in simulation — the pilot
  runs it against the real stack (serialization, framing, transport) where
  simulation cannot reach.

**Timing probes:** same taps record ingress timestamps; the pilot computes
the mutual information between hop-1 ingress times and hop-3 ingress times
for probe traffic, compared against a shuffled control. Alert if MI probe >
MI control + 3σ (delay discipline leakage).

**Acceptance thresholds (gate G2 exit):**
- Delivery ratio ≥ 99.9% over a 7-day window.
- Zero verified linkability-probe matches.
- Delay p99 ≤ 2.8 s at μ = 1 s (Erlang(v=3) theory + margin).
- Replay/tagging drills produce no observable timing signature (drill
  cells' sojourn distribution ≡ healthy cells' distribution, KS < 0.05).

## What must be built for tiers 2–3

1. The mix daemon (listener, ready-heap scheduler, metrics export).
2. The probe client (scripted paths + window-sketch collector protocol).
3. Operator pilot contracts (the taps are consented, logged, and
   ephemeral — they must not outlive the pilot).

Items 1–2 are the next build tasks after this pack; item 3 is an
operational task for the rollout phase.

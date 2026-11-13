# Cutover plan: Katzenpost (X-Wing) → PQ-Sphinx option E

Decision (option 1 of the mix-lane rollout): **build option E now, keep
Katzenpost until it is proven.** The `avpn mix` lane ships Katzenpost-based
channels (X-Wing hybrid KEM headers, ≈7164 B per the project's budget table)
as the production default. This crate (`avpn-mix-lane`) is the option E
implementation — 1396 B headers at v = 3, +112 B per extra hop — gated behind
configuration until it passes the gates below. Nobody runs an unreviewed
Sphinx construction by default on day one; the §2.3 XOR re-blinding carries
an explicit review-pending flag until G3.

## Why option E is worth the gate work

| | Katzenpost lane (current) | Option E (this crate) |
|---|---|---|
| Header, v = 3 | ≈7164 B (X-Wing per hop) | **1396 B** |
| Marginal hop | large (X-Wing ct per hop) | **+112 B** (X25519 elem + MAC + rt) |
| v = 5 paths | impractical | 1620 B — cheap |
| PQ scope | PQ hybrid per hop | PQ at the trust boundary (entry ML-KEM-768); inner hops classical |
| Payload capacity (S=4096, v=3) | squeezed | 2684 B (66%) |

Trade-off stated plainly: option E's inner-hop path crypto is classical
X25519; an adversary who breaks X25519 blinding AND observes multiple hops
could link inner path segments. Payload *content* remains PQ end-to-end
(`payload_key = HKDF(K_1||…||K_v)` mixes every hop secret, K_1 is PQ). This
mirrors the existing AVPN pattern — PQ at the boundary where long-term
identity linking matters most — and is the documented reason E is 5× smaller
on the wire.

## Gates

**G0 — byte-identity in CI (PASSED, keep automated).**
`cargo test` green on both crates (reference 57/57, this crate 40/40); the
regeneration check (dump_cells output == committed cells.txt) catches any
accidental protocol drift. The reference crate is the oracle, cross-verified
against Python (kyber-py, cryptography, blake3, hashlib).

**G1 — simulation lab (PASSED).**
`tests/lab.rs`: full §1.2 pipeline — delivery, replay rejection, tagger
resistance, cross-link linkability (the check that caught R3 and R4),
Erlang delay sanity, accounting closure.

**G1.5 — local soak (next, ~1 week of wall time).**
Run the daemon (once built) over a 10-node local test network for 72 h:
zero unexplained accounting drift (`accepted == forwarded + delivered +
not_mine + replays`), zero replay-cache overflows, delay percentiles within
theory (Erlang(v, μ)), no mailbox drops at target load. Kill with cover
floods, replay floods, and corrupt-cell floods at 10× rate; the only allowed
degradation is cover loss.

**G2 — live-site GPA pilot (flag-gated cohort).**
See `GPA_LAB_PLAN.md`. Small opt-in cohort, real sites, independent observer
probes. Exit criteria: delivery ≥ 99.9%, no linkability-probe hits beyond
chance (p < 0.05 over the probe corpus), delay p99 ≤ budget.

**G3 — external review.**
(a) The §2.3 KEM-ciphertext XOR re-blinding — the one non-standard
construction in the header — reviewed by an external cryptographer, with the
Tamarin effort (`tamarin/REBLINDING_PLAN.md`) as supporting evidence.
(b) A Cure53-class audit of this crate and the daemon.
No security claim rests on §2.3 until this gate clears; everything else is
standard-primitive composition (and R1–R4 are exactly the classic Sphinx
disciplines).

**G4 — default flip.**
`mix_header = "option_e"` becomes the default; Katzenpost lane stays
available for one minor release as fallback, then is removed.

## Rollback

Config-level, no data migration (cells are ephemeral; mailboxes are
RAM-only). Flipping `mix_header` back to `"katzenpost"` is a restart-time
operation per mix. Surbs and in-flight cells die with the lane switch —
acceptable for an async lane, and the reason the flip happens between
releases, not mid-epoch.

## Config sketch

```toml
[mix]
header           = "katzenpost"   # "katzenpost" | "option_e"
delay_mean_ms    = 1000           # §1.3: 250..2000
epoch_ms         = 60000
queue_policy     = "littles_law"  # cover sacrificed first (§1.4)
```

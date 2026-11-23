# CPVPN/Mesh — Path selection design

**Proposed, not landed.** This document extends the community mesh
([MESH_DESIGN.md](MESH_DESIGN.md)) with the client-side path-selection
algorithm: how a client composes entry/middle/exit chains from gossiped
descriptors, what weights a descriptor carries, how guards and rotation
work, and how routing diversity is measured. It also records the proposed
traffic-class profiles for streaming and bulk/P2P workloads. Nothing here
is implemented yet; decisions marked **owner decision** are required
before any of it is built. Existing landed behavior is labelled *landed*
and must not be regressed by this design.

## 1. The problem

The cloud installer can provision or record servers on many providers
(13 provider keys today: `oci`, `aws`, `azure`, `gcp`, `own`, plus
`racknerd`, `ionos`, `ovh`, `netcup`, `hetzner`, `1984`, `infomaniak`,
`exoscale`; the OpenTofu registry search indexes 4,825 more, of which only
reviewed recipes may ever provision). The mesh turns those servers into a
pool of published nodes with roles (entry/relay/exit). What is missing is
the **selection layer**: a local, deterministic, auditable algorithm that
picks chains from the pool the way Tor's client picks circuits — without
a central directory, and without any classifier promoting nodes.

Two prior decisions constrain this design (*landed*):

- The chain builder already enforces **distinct operator, provider and
  country per hop**, and refuses an entry and exit on one provider unless
  `--allow-same-provider` is given.
- The entry is a **sticky guard** ("entry fixed as the guard", rotation
  of later hops within a signed window, 4.2 s lab failover with no leak;
  `evidence/FAILOVER.json`). Mesh relays do not yet fail over between
  members' exits.

## 2. Descriptor weights

Selection needs each signed descriptor to carry machine-checkable facts.
Proposed additions to the descriptor schema (signed by the operator key
at `cypherpunk mesh publish`, so they are attestations, not self-reported
marketing):

| Field | Type | Used for |
|---|---|---|
| `roles` | set of `entry`/`relay`/`exit` | constraint filter (already conceptually present) |
| `exit_policy` | ports/protocols admitted, egress ceiling | exit eligibility per destination (Tor-style exit policy) |
| `capacity_class` | measured `s` (small) … `xl`, re-measured periodically by the mesh's own protection-validity probes | selection weight |
| `uptime_class` | measured 30-day availability | selection weight |
| `legal` | country, provider key, operator pseudonym | diversity constraints |
| `toS_class` | free-tier / paid / own-hardware egress allowance | exit eligibility and cost honesty |

Weights are published facts with evidence behind them, exactly like the
rate classes; **no LLM or keyword classifier may compute or adjust a
weight** (the registry-search rule generalizes here). A node whose
capacity cannot be measured recently is selectable only at the floor
weight, never promoted on claimed numbers.

## 3. The selection algorithm

Tor's bandwidth-weighted choice over a global consensus, adapted to a
gossiped descriptor set with no authorities:

```text
select_chain(dest, profile):
  1. pool    = descriptors valid now (signature, session cert, not expired)
  2. entry   = the pinned guard (sticky; see §4)
  3. exits   = pool where roles ⊇ {exit} and exit_policy admits dest
               and legal.provider ≠ entry.provider
               and legal.operator ≠ entry.operator
               and legal.country  ≠ entry.country
  4. middles = pool where roles ⊇ {relay}
               and node ∉ {entry, chosen exit}
               (sharing a provider with entry or exit is allowed, as today)
  5. exit    = weighted_pick(exits,   w = capacity_class × uptime_class)
  6. middle  = weighted_pick(middles, w = capacity_class × uptime_class)
  7. if fewer than one candidate remains at any position: report the
     constraint that failed, do not silently drop it
```

Properties kept deliberately:

- **Weighted, not best**: always the highest-capacity node would
  concentrate traffic and make the top node a global observer's dream;
  weights only tilt probabilities (Tor's argument, and the reason I2P-style
  "pick my personally fastest peers" profiling is rejected: it fragments
  the anonymity set — every client ranks differently).
- **Diversity as hard constraints, not weights**: provider/operator/country
  separation is a filter pass. Neither Tor (families, /16) nor I2P has the
  legal-entity dimension; it stays this project's own rule.
- **Deterministic and auditable**: given the same descriptor set and seed,
  the same chain is chosen — so a test can replay a selection and the
  owner can audit why a chain was refused.

## 4. Guards, rotation, parallel chains

- **Keep the sticky guard** (landed decision). Guards defend against
  predecessor/position attacks; I2P's guardless 10-minute rotation is
  explicitly *not* adopted for the entry.
- **Rotate the non-guard hops within the existing signed windows**;
  hardware-bound session certificates (per-session ML-DSA-65 keys, short
  expiry) already make rotation cheap: no new PIN/touch ceremony per hop
  change.
- **Parallel live chains (borrowed from I2P's tunnel pairs):** maintain
  one live chain plus one hot standby built through a *different* entry-
  eligible node. This is the generalization of the landed standby-exit
  work to the mesh, and it closes the open "mesh relays do not fail over
  between members' exits" gap. Churn between two live chains also
  complicates long-run intersection attacks at no per-flow cost.
- **Unidirectional inbound/outbound tunnels (I2P's core trick) are not
  adopted**: the carrier is a bidirectional low-latency WireGuard/QUIC
  stream with bidirectional constant-rate cover; splitting directions
  doubles cost, adds RTT, and buys most of its value only for internal
  (hidden-service-like) traffic, which the mesh does not have.

## 5. Path counting and the anonymity-set metric

Routing diversity is measurable; publish it as a tool output
(`cypherpunk mesh diversity`), not as a marketing number. With per-role
eligible sets E (entry), M (relay), X (exit) over the *currently
published* pool:

```text
provider-level chains(h=3) = Σ over (e,m,x) ∈ E×M×X,
                                e.provider ≠ x.provider          → count 1
node-level chains(h=3)     = Σ over the same tuples → n_e · n_m · n_x
```

At today's provider keys (13), that is 13 × 13 × 12 = **2,028** provider-
level orderings (middle may share a provider with either end, as the CLI
allows today); node-level multiplies by nodes per provider. If every
indexed registry provider (4,825) one day had a reviewed recipe, provider-
level orderings would reach ~1.1 × 10¹¹ — which is why chains are sampled
(§3), never enumerated.

Two honest separations, per the project's evidence rules:

- **Path count is a routing metric.** The mesh's security goal is
  full-membership indistinguishability (`1/N`, MESH_DESIGN §1): with
  constant-rate cover and fan-in, any active member is an equally likely
  origin. A million provider combinations do not improve `1/N`; only
  active member count and per-hop defense do. Path count measures
  resilience (correlation, takedown, provider churn), not anonymity.
- **Runnable vs indexed**: only reviewed recipes and recorded own-hosts
  are selectable; the 4,825-entry index is a search space, not a pool.

## 6. Traffic-class profiles

The rate classes (`metered`/`standard`/`fast`/`line`, landed, 0–3.7%
wire-rate change measured) and the rotating strong-posture defense
database are the machinery profiles plug into.

### 6.1 Streaming profile

Commercial "streaming" VPNs are one hop, no cover traffic, full line
rate, with exit IPs curated to not be datacenter-blocked. Matching their
*speed* is feasible; matching all four properties is not, and the
difference must stay visible to the user.

| Property | Commercial 1-hop | Proposed streaming profile | Notes |
|---|---|---|---|
| Hops | 1 | 2 (guard + exit), middle dropped | halves added RTT vs 3-hop |
| Entry-link defense | none | Maybenot burst-adaptive padding | not constant-rate — **owner decision**, see below |
| Inter-hop / exit-side | none | per-hop reshaping retained on the middle→exit link | exit-side WF identified video at 93 % through a commercial VPN (Chalmers 2025, cited in MESH_DESIGN §7); dropping all exit-side defense re-opens exactly that result |
| Rate class | — | `line` | the landed line-rate class already exists |
| Exit IP class | curated | measured: descriptor `toS_class` + exit policy | a datacenter-blocked exit is an eligibility fact, not a bug |

The honest tension, stated for the owner: the mesh today has **one
posture, strong** (the balanced profile was removed deliberately). A
burst-adaptive entry link is a second, weaker posture. Options:

1. **Strong-only streaming**: keep constant-rate cover at `line` class.
   Speed matches commercial VPNs whenever the client's own access link
   is the bottleneck — the cover stream is already at line rate, so a
   burst rides the same envelope. Cost: the uplink runs hot continuously
   (the already-documented energy/battery item), and strict constant
   rate cannot exceed the link it is shaped to.
2. **Opt-in adaptive streaming profile**: Maybenot-only entry link,
   labelled in the GUI and plan as reduced protection, never default,
   never mixed into the same anonymity claims. This restores commercial
   speed parity on links slower than the cover rate, at the price of a
   distinguishable traffic class on the client↔entry segment.

**Recommendation:** ship (1) first and measure; treat (2) as a separate
owner decision with its own validation gate, because it reverses a
recorded design decision (one posture).

### 6.2 Bulk/P2P (magnet) profile

BitTorrent over the tunnel is a legitimate bulk workload (distributions,
archives, datasets) and the protocol's design — many peers, chunked,
multipath — is actually friendlier to cover traffic than video streaming.
What it needs from the VPN is plumbing, not integration:

- **Interface binding** as a hard requirement: the torrent client must be
  bound to the tunnel interface (guard, kill switch), because DHT/PEX
  announce the source address and a single leak de-anonymizes the client.
  Document and test the common clients' bind feature; the kill-switch and
  fail-closed behavior is already landed.
- **DHT/PEX and tracker traffic through the exit** with the exit policy
  deciding admission; peer connections are ordinary tunneled flows.
- **Exit port admission is opt-in and scarce**: a stable listening port
  on a shared exit is an abuse magnet and contradicts most providers'
  ToS; an exit may offer it, the plan must say so, and it must never be
  required for the profile to work (connect-only mode).
- **Anonymity honesty**: a swarm is many long-lived observers seeing
  high-volume traffic — the hardest workload for intersection attacks.
  The profile should carry an explicit long-session warning, and the
  traffic-analysis roadmap item (open-world, cross-link correlation)
  must cover swarm-shaped flows before any P2P privacy claim is made.

**Boundary (owner decision):** support the *protocol workload*, not a
*catalog*. Bundling a piratebay-style magnet search into the client would
aim the product at copyright infringement, torpedo the opt-in exit
guidance (exits are contributed with provider ToS and abuse caveats),
contradict the funding/governance record's clean hands, and hand every
exit-hating network operator the excuse they need. Users can open any
magnet in any bound client; the VPN's job is to make the pipe safe, not
to curate the cargo.

## 7. Decisions required from the owner

1. Adopt the descriptor weight fields (§2) and the selection algorithm
   (§3), or amend.
2. Adaptive streaming posture (§6.1 option 2): allow a second, labelled
   posture — or keep strong-only.
3. Exit port admission for P2P (§6.2): opt-in per exit, or refused
   project-wide.
4. Diversity metric publication (§5): ship `cypherpunk mesh diversity` as a
   tool output bound to real descriptor sets.

## 8. Gates before any of this is claimed

- Selection algorithm: property tests for the constraint filter (no
  same-provider/operator/country ends, exit policy honored), replay
  determinism, and mutation checks (a broken filter must fail tests).
- Guard/rotation/parallel chains: extend the landed failover evidence to
  the two-live-chain mesh case with external packet witnesses.
- Streaming: measure the strong-only line-rate envelope against a
  commercial 1-hop baseline on identical links before any speed claim;
  publish the delta, not a best case.
- P2P: leak tests for interface binding (client off-tunnel attempts must
  fail closed) before the profile is documented.

# AVPN/Mesh — Design

**A community-owned, post-quantum, per-hop-defended WireGuard mesh VPN.**
Evolution of ADVANCED_VPN 0.6.0. Status: core scaffolding landed (see
*Implementation status* at the end).

## 1. Summary

AVPN/Mesh turns ADVANCED_VPN from a single-operator VPN into a **community
mesh**: every member contributes at least one server (an always-free cloud VM
is enough), and in return can build multi-hop chains across nodes contributed
by other members, browsable and selectable from the CLI. It keeps everything
ADVANCED_VPN already does (post-quantum authentication, HTTP/3 carrier
camouflage, fail-closed no-retained-data, hardware-sealed keys), keeps the
WireGuard/GotaTun carrier, and adds:

1. **Traffic-analysis defense on every hop** — independent Maybenot machines
   re-shape timing with fresh randomness at each relay, backed by
   bidirectional constant-rate cover. One security posture: **strong**. The
   balanced profile is removed.
2. **A mesh social layer** adapted from Meshtastic: signed gossiped node
   descriptors, a public relay pool plus invitation-only private groups,
   key-pinned pseudonymous identity, and a contribution economy with no
   accounts, payments, or company.

## 2. Membership: your hardware device is your account

There is **no account number, no user record, no ledger anywhere**. A member
*is* a key held by a hardware device:

- **Preferred: Nitrokey** — open source, and the same FIDO2 hmac-secret
  credential class ADVANCED_VPN already seals client keys with.
- **Accepted: any capable hardware token** that can generate and hold the
  required keys (FIDO2 hmac-secret for the Ed25519 membership credential; the
  operator ML-DSA-65 key sealed under it, exactly as `avpn init` does today).

The device private key never leaves the token. Everything the mesh knows about
a member is derived from public material: the **member ID** is `!xxxxxxxx`,
the truncated SHA-256 of the device membership public key (Meshtastic's node-
number convention). Lose the device and you are a new member — keys are cheap
to regenerate and the mesh keeps nothing to recover, same as enrollment today.

Software fallback key custody (`systemd-creds`/`none`) is possible for nodes
but ranks below hardware-backed members in the directory.

## 3. Gap analysis vs Mullvad and IVPN (2025–2026)

| Gap in commercial VPNs | AVPN/Mesh answer |
|---|---|
| All relays provider-operated | Every member contributes ≥1 server; chains span members |
| Multihop under one legal entity | Chain builder enforces distinct operator, provider **and** country per hop |
| DAITA only on client→entry (Mullvad); nothing (IVPN) | Maybenot on every link, independent randomness per hop, bidirectional constant-rate cover; strong-only |
| PQ key exchange only, classical auth | ML-DSA-65-only auth, retained and extended to mesh descriptors |
| Observers can still tell it's a VPN | HTTP/3 cloak on UDP 443 retained, extended toward inter-hop links |
| No free tier | Contribution-based: an always-free VM (e.g. OCI ~10 TiB/mo egress) is the membership fee |
| Central server directory | Gossiped signed descriptors; no central directory |

## 4. Threat model

- **A1 local observer** (ISP/firewall): wants to identify VPN use and
  fingerprint destinations → cloak + strong shaping on the first link.
- **A2 exit-side observer** (exit's ISP/DC/destination AS): the vantage
  first-link-only defenses ignore → per-hop re-shaping + end-to-end duration
  quantization.
- **A3 correlating observer** (two or more links, up to global passive):
  DeepCorr/DeepCoFFEA class → independent re-shaping per hop + inter-relay
  chaff. Honestly bounded: a global passive adversary with unlimited
  retraining remains catastrophic for any low-latency system; per-hop defense
  raises cost, it does not yield mixnet-grade unlinkability.
- **A4 active attacker**: timing watermarks (RAINBOW/SWIRL) destroyed only by
  re-shaping at an intermediate hop — a per-hop defense exists precisely
  because of this class.
- **A5 malicious mesh nodes** (new): stranger-run entries/relays/exits that
  log, probe, correlate; Sybil operators. Mitigated by the diversity rule,
  the contribution cost, and opt-in exits.
- **A6 cloud providers** and **A7 coercion of any single node or member**:
  RAM-only operation, hop-splitting across providers and operators.

## 5. The mesh layer (Meshtastic-derived)

From Meshtastic's serverless volunteer mesh we take the protocol discipline,
not the payload austerity:

- **Signed node descriptors** (the NodeInfo pattern): node ID `!xxxxxxxx` of
  the node key, WG/cloak endpoints, roles, provider, country, capacity,
  probe-measured health, operator, TTL 7 days. ML-DSA-65 signed; verified in
  the control plane before entering any directory (`src/mesh/descriptor.rs`,
  `tools/mesh.py`).
- **Gossip**: managed flooding, hop limit 3, duplicate suppression,
  auto-scaling announce interval as the directory grows. Bootstrap via any
  enrolled peer or volunteer beacons that store-and-forward descriptors for
  offline peers and enforce anti-amplification (rate limits, ban lists) — the
  lesson of Meshtastic's public MQTT moderation.
- **Key pinning (TOFU)**: peers pin first-seen node keys; key changes need
  explicit re-verification.
- **Public pool + private groups + private nodes**: the pool is open and
  low-trust (safety comes from multihop, not trust); private groups are
  invitation-only meshes sharing a group key; a `--private` node is never
  published and is usable only by its operator.
- **Roles as social contracts**: relay is the default duty of every node;
  exit is a separate explicit opt-in with provider-ToS and abuse guidance
  (Meshtastic deprecated self-declared router roles for good reason).

## 6. The contribution economy

> **Membership = one contributed relay-capable server**, anchored to your
> hardware device. An always-free cloud VM suffices.

`avpn mesh offer --guided` ranks always-free providers by free egress, checks
your sign-ins, provisions through the existing `avpn cloud` machinery,
hardens (`retention.py`), and publishes the descriptor — or keeps it private:

| Rank | Provider | Free egress | Role fit |
|---|---|---|---|
| 1 | Oracle Cloud Always Free | ~10 TiB/mo, no expiry | entry, relay, exit* |
| 2 | AWS free plan | ~100 GiB/mo, 6 months | entry, relay |
| 3 | GCP e2-micro free tier | ~1 GiB/mo | beacon only — **not relay-capable, not counted** |
| 4 | Your own host | your plan | any |

*exit after an explicit risk acknowledgement; free-tier ToS apply.

**Quota without a ledger.** Relaying for the mesh earns blind-signed credits;
building a chain through others' nodes spends them. Public-pool credits are
blind signatures: issuance unlinkable to redemption, daily epochs. The
control-plane verifier landed as Chaum blind RSA-FDH (`tools/mesh_tokens.py`:
blinded issuance, unlinked redemption, a digest-only double-spend ledger);
the target primitive remains VOPRF (Privacy-Pass family), and the Rust data
plane (`src/mesh/tokens.rs`) keeps rejecting public spends **fail-closed**
until a reviewed VOPRF verifier is vendored. Private groups use HMAC credits
(members already trust each other). A member who only ever uses their own
private nodes needs no credits at all.

## 7. Traffic-analysis defense: strong, on every hop

Why per-hop is necessary (documented attacks):

1. **Exit-link WF**: the exit→destination segment shows the naked shape;
   classifiers trained at exits work (93% video identification through a
   commercial VPN without exit-side defense — Chalmers 2025).
2. **End-to-end correlation**: DeepCoFFEA keeps 84–95% TPR even when the
   first link is defended with WTF-PAD/FRONT — padding one side of a
   correlation barely dents it.
3. **Active watermarking**: marks injected at the destination side survive
   untouched hops and are readable client-side; only intermediate-hop
   re-shaping destroys them.

The stack (`src/daita.rs`), every hop, both endpoints, independently seeded:
netflow collapse, re-armed FRONT, Tamaraw with the fixed stop machine, and
**bidirectional constant-rate cover** (self-sustaining on its own decoy clock,
unbudgeted at machine level — resource limits belong to the node's controller
and fail closed at the carrier byte budget, never by weakening machines).
Blocking stays enabled: padding-only defenses cap out at ≥93% against
RF-class attacks.

### Our measurements (tools/mesh_wf_sim.py)

Exit-side vantage, 10 synthetic site profiles, 80 traces/site, timing +
direction features, RandomForest, closed world (chance = 10%):

| Defense | WF accuracy | Cost |
|---|---|---|
| None | 73.9% | — |
| Client-only constant-rate shaping (DAITA-style placement) | 71.8% | jitter erodes the clock |
| Per-hop re-shape with idle-grace cover | 68.2% | short gaps + volume leak |
| Per-hop full constant cover, 4 s quantum | 23.2% | ~5× packets |
| Bidirectional constant-rate, 4 s quantum | 22.5% | ~10× |
| Bidirectional constant-rate, 8 s quantum | 16.4% | ~14× |
| **Bidirectional constant-rate, 16 s quantum** | **8.9% ≈ chance** | ~25×; ~0.96 Mbit/s per link |

The same comparison at the acceptance scale — 100 sites, 80 traces/site,
closed world (chance = 1%), raw numbers in
[docs/evidence/MESH_WF_SIM.json](evidence/MESH_WF_SIM.json):

| Defense | WF accuracy | Cost |
|---|---|---|
| None | 30.3% | — |
| Client-only constant-rate shaping (DAITA-style placement) | 22.0% | ~2.5× packets |
| Per-hop re-shape with idle-grace cover | 16.9% | ~3× |
| Per-hop full constant cover, 4 s quantum | 2.9% | ~7× |
| Bidirectional constant-rate, 4 s quantum | 2.2% | ~14× |
| Bidirectional constant-rate, 8 s quantum | 1.6% | ~20× |
| **Bidirectional constant-rate, 16 s quantum** | **1.4% ≈ chance** | ~36× |

Mechanisms the numbers demonstrate: **placement dominates** (the same shaping
scores 22.0% client-side-only vs 2.9% per-hop at 100 sites); **direction must
die** (only bidirectional streams remove it); **duration is the last leak**
(accuracy converges to chance as the duration quantum coarsens). Synthetic
traces and a classical classifier — this shows mechanism and ordering, not a
real-world bound; it matches published Tamaraw/constant-rate results. The
remaining acceptance test is real traces against DF/Tik-Tok/RF at every
vantage (§8).

### Affording cover on free tiers

The tunable is the node's **daily cover budget** (default 2 GiB/day, fits OCI
Always Free with relay headroom), set by the operator in the descriptor and
enforced by the controller — never a user-facing security dial. Idle links
run randomized cover-activity windows so real sessions hide among scheduled
ones; cover intensity is front-loaded (the trace front is the most
informative region). The CLI shows the monthly egress math and refuses
configurations that would exhaust a free tier.

## 8. WF test program (acceptance gates)

Extending tools/daita_lab.py and tools/mesh_wf_sim.py: 100+ sites plus
open-world background; DF/Tik-Tok/RF attackers trained on defended traces;
measurements at every vantage (client-side, each inter-hop link, exit-side,
cross-link); DeepCorr/DeepCoFFEA-style flow confirmation and a
watermark-injection test. Gates: closed-world ≤ chance + 10 pp at every
single vantage; cross-link TPR ≤ 1% @ 1e-3 FPR; watermark detection ≤ 5%;
default cover budget ≤ 2 GiB/day per contributed node. Results publish to
docs/evidence/ as before.

## 9. Trust in a stranger-run mesh

| Malicious node | Sees | Cannot see |
|---|---|---|
| Entry | your IP; cloaked shaped ciphertext | destinations, payload, the rest of the chain |
| Relay | its two neighbours | either end |
| Exit | destinations (TLS-protected payload) | your IP or identity |

The chain builder's **diversity rule** (distinct operator, provider, country
per hop; never below two operators) means one malicious operator or one
compelled provider sees at most one vantage. Sybil is bounded by the
contribution cost: every node must be a working contributed server. Exits are
opt-in, declare port policies, and can be group-scoped; the docs state
plainly that running a public exit carries real legal exposure no technology
removes. The docs also state the mesh's own gossip metadata (node IDs,
announce timing) is visible to members — Meshtastic's candor rule.

## 10. What we still cannot defend

Global passive adversaries at scale; volume/duration below the quantum;
endpoint compromise; browser fingerprinting; a cloud provider's metadata on
its own VM; exit operators' legal exposure; gossip metadata. Stated in
`avpn help threat-model`, not buried.

## 11. Implementation status

| Component | Where | Status |
|---|---|---|
| Strong-only machine set + bidirectional cover, per-hop independent seeds | `src/daita.rs`, `src/bin/advanced-vpn-wireguard.rs` | landed; `balanced` bundles refused |
| Member/node identity (hardware-anchored) | `src/mesh/identity.rs` | landed |
| Descriptor schema + validation | `src/mesh/descriptor.rs`, `tools/mesh.py` | landed |
| Directory + diversity chain selection | `src/mesh/directory.rs`, `tools/mesh.py` | landed |
| Contribution credits | `src/mesh/tokens.rs`, `tools/mesh_tokens.py`, `tools/mesh.py` | interim verifier landed: Chaum blind RSA-FDH credits in the Python control plane (unlinkable issue/spend, double-spend ledger, fail-closed); `tokens.rs` stays fail-closed until the VOPRF verifier is vendored |
| `avpn mesh` CLI | `src/bin/avpn/mesh.rs`, `tools/mesh.py` | landed (nodes/chain/offer/quota/identity/publish) |
| `avpn-mesh` launcher | `tools/install.py` | landed (user wrapper + system launcher, hash-locked venv) |
| WF simulation | `tools/mesh_wf_sim.py` | landed |
| Gossip transport + beacons | `tools/mesh.py`, `tools/mesh_beacon.py` | landed: store-and-forward gossip with TTL hop counter, dedup, per-member rate limits, auto-ban, anti-amplification (fixed-shape small responses; POSTs never trigger data-plane traffic) |
| Descriptor signing via hardware unseal | `tools/keyguard.py`, `tools/mesh.py` | landed: `avpn mesh publish` signs through the sealed envelope (one PIN + touch per publish), self-checks the signed descriptor, and gossips it; unsigned publishing stays refused |
| Ephemeral defense database (DAITA-v2-style) | `tools/defense_db.py`, `src/daita.rs` (`DefenseDb`), carrier `defense_db` | landed: rotating randomized strong-posture parameterizations, fail-closed validation mirrored in Rust and Python; no profile in force refuses the run |
| Inter-relay chaff links | carrier `cover: "always-on"` | landed: 5 s keepalive on server roles starts the self-sustaining cover machine within seconds of tunnel setup, so idle relay↔relay links carry the same constant-rate stream as busy ones |
| 100-site WF simulation run | `docs/evidence/MESH_WF_SIM.json` | landed (1.4–2.2% vs 1% chance for the shipped posture); real-trace DF/Tik-Tok/RF gates remain Phase 1 lab work (§8) |

Non-goals: no token sale/cryptocurrency, no company, no GUI in v1, no mobile
clients in v1, no exit-node requirement for membership, no weakening of the
one-mode rule.

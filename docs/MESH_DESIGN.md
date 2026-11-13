# AVPN/Mesh — Design

**A community-owned, post-quantum, per-hop-defended WireGuard mesh VPN.**
Evolution of ADVANCED_VPN 0.7.0. Status: core scaffolding and multi-member data-plane fan-in landed (see
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
2. **An FCMP++-inspired full-mesh anonymity set** — rather than single-tenant
   isolation or Tor's unpadded circuit subsets, multi-member relay fan-in
   (`members[]` peer tables) combined with always-on constant-rate cover streams
   across every link and unlinkable blind/zero-knowledge membership proofs makes
   any outbound request at an exit equally likely to have originated from **any
   active participant in the entire mesh** (`1 / N` full-membership indistinguishability).
3. **A mesh social layer** adapted from Meshtastic: signed gossiped node
   descriptors, a public relay pool plus invitation-only private groups,
   key-pinned pseudonymous identity, and a contribution economy with no
   accounts, payments, or company.
4. **Multi-browser TLS/QUIC fingerprint parity & continuous red-teaming** —
   matching the user's actual browser (`chrome`, `firefox`, `safari`, `brave`)
   on the outer HTTP/3 and TLS 1.3 cloak so DPI cannot detect browser-vs-tunnel
   JA4 mismatches, paired with continuous adversarial testing via
   [RedteamAgent](https://github.com/NeoTheCapt/RedteamAgent),
   [Redamon](https://github.com/samugit83/redamon), and
   [PyRIT](https://github.com/azure/PyRIT).

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

### What the network learns about your key

Enough for its functions, and nothing it has to be trusted to forget. Like a browser that
answers a site's attestation request with "none", nothing in this system asks about the
device itself:

- **Learned:** the credential's public key (it checks signatures and derives your member
  ID), and that each signature was made with PIN and touch (the user-verified and
  user-present flags).
- **Never requested:** attestation. No protocol message has a field for it, and the
  credential is created with attestation "none".
- **Never carried:** what `operator.pub` and every membership proof contain is the bare
  COSE public key, built from the key itself. It has no field for an AAGUID (which names
  the make and model), a credential ID or a certificate, so nothing is filled in and then
  zeroed (`keyguard.public_key_of`;
  `test_the_published_key_has_no_room_for_device_identity`). Operator files from before
  v0.10, which carried the full credential record, still verify; only their key is read.
- **On the USB cable, not avoidable yet:** when a credential is created, the authenticator
  still sends its own attestation (batch certificate, AAGUID) to the local program, and the
  FIDO library reads the key's capabilities (`getInfo`) on connect. Asking the key not to
  produce attestation needs CTAP 2.2's attestation-format preference, which the pinned
  python-fido2 (2.2.1) cannot send. None of it is stored or sent anywhere: the vault keeps
  only the credential ID (the key needs it back to sign) and the public key. When the
  library supports the preference, the request will ask for none.
- **Still visible, and why:** the signature counter. It is inside the data the key signs,
  so it cannot be left out without breaking the signature. On a key that keeps one counter
  for all sites, its value grows with every use anywhere, which tells an observer roughly
  how often the key is used and can help link the same key across services. Keys that
  keep a counter per credential, or report zero, reveal nothing this way.
- **The cost of asking nothing:** without attestation, "hardware-backed" is the member's
  own claim, which software can make too. Proving it would mean showing at least the
  key's model (vendors' batch certificates cover large batches, so not the individual
  key). If the mesh ever needs that proof, it should be checked once, through the
  oblivious control plane, with only "yes" kept and published, never the model.

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
  raises cost, it does not yield mixnet-grade unlinkability. For async traffic,
  the mix lane (`avpn mix`) does: measured 10.7% vs 88.2% sender
  identification (chance 10%, post-quantum Sphinx, `MIX_LANE.json`).
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

Where it runs: the client↔entry link carries the WireGuard + DAITA carrier
(`src/daita.rs`); every link between two servers carries a **paced,
encrypted link** (`src/link.rs`, v0.8.0) with the same invariant — fixed-size
AES-256-GCM cells under a per-link key the operator seals to both servers, a
fixed number of cells per tick of the chain's clock, real or empty, and replies
only on credit earned from authenticated cells (no reflection). Before v0.8.0
the server↔server links were unshaped; measured on the link into the exit,
idle 0.5 packets/s jumped to 34–3,419 packets/s during a download; now it holds
the class's rate within 0.1% (`docs/evidence/RATE_CLASSES.json`, `inner_link`).

The carrier's stack, both endpoints, independently seeded:
a **bidirectional constant-rate packet stream** built from two Maybenot
machines (`stream_grid` + self-sustaining `cover`) running under GotaTun's
strict-blocking scheduler (`strict: true`, `Replace: true`). On every clock
tick, each slot either releases one queued real packet or emits a 1380-byte
decoy packet, so idle and busy intervals have the same wire packet rate. Four
rate classes share this exact invariant and differ only in tick interval and
staggered slot count (`metered` = 20 ms × 1 slot / 50 pps, `standard` = 2 ms ×
1 slot / 500 pps, `fast` = 2 ms × 8 staggered slots / 4,000 pps, `line` = 2 ms ×
32 staggered slots / 16,000 pps). Resource limits belong to the node's
controller and fail closed at the carrier byte budget, never by weakening
machines.

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

The operator chooses a rate class (`--rate metered|standard|fast|line`, default
`metered`) and an optional fail-closed daily byte cap (`--daily-limit-mib`). At
`metered` (50 pps per direction = ~0.55 Mbit/s wire rate, ~5.7 GiB/day per
direction, ~342 GiB/month bidirectional), a continuous 24/7 stream fits well
inside Oracle Cloud Always Free (~10 TiB/month egress) with ample relay
headroom. On tighter monthly caps (such as the AWS 100 GiB/month free tier),
operators pair `metered` with `--daily-limit-mib` or connect on demand. On
unmetered VPS or fiber links, `standard` (~4.5 Mbit/s), `fast` (~33 Mbit/s),
and `line` (~131 Mbit/s) raise application throughput by increasing the
constant wire rate rather than weakening the constant-rate invariant.

## 8. WF test program (acceptance gates)

Extending tools/daita_lab.py and tools/mesh_wf_sim.py: 30-site namespace lab
(`tools/daita_lab.py --sites 30 --loads 10`, chance = 3.3%) and 100-site
exit-vantage simulation (`tools/mesh_wf_sim.py --sites 100`, chance = 1.0%);
measurements at the camouflaged carrier and inner link; fixed-window and
oracle-cut evaluations. In the 30-site namespace lab at the fixed 6 s window,
`metered` scores **3.3%** and `fast` scores **1.7%** (at or below 1/30 random
chance) on the carrier versus 27.0–74.7% on the unshaped inner link
([docs/evidence/DAITA_LAB.json](evidence/DAITA_LAB.json),
[docs/evidence/RATE_CLASSES.json](evidence/RATE_CLASSES.json)). Remaining
Phase 2 lab extensions: 100+ real browser traces with open-world background,
DF/Tik-Tok/RF deep classifiers, DeepCorr/DeepCoFFEA cross-link flow
confirmation, and active watermark injection.

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

Global passive adversaries at scale (a constant-rate stream keeps packet
order, so it is still a circuit; only per-packet mixing defeats end-to-end
correlation); endpoint compromise; browser fingerprinting; a cloud provider's
metadata on its own VM; exit operators' legal exposure; gossip metadata
between members (beacon queries themselves can go through an oblivious relay,
see §11). Stated in
`avpn help threat-model`, not buried.

## 11. Implementation status

| Component | Where | Status |
|---|---|---|
| Constant-rate bidirectional stream (`stream_grid` + `cover`) + 4 rate classes (`metered`/`standard`/`fast`/`line`) with staggered multi-slot timers | `src/daita.rs`, `vendor/gotatun/src/device/daita/`, `src/bin/advanced-vpn-wireguard.rs` | landed; `balanced` bundles refused; `<1%` idle-vs-busy wire rate delta |
| Multi-member data-plane fan-in (`members[]` peer tables across cloak, WG, inner QUIC, and DNS) | `src/config.rs`, `src/tls.rs`, `src/run.rs`, `src/cloak.rs`, `src/bin/advanced-vpn-cloak.rs`, `src/bin/advanced-vpn-wireguard.rs`, `tools/managed_profile.py` | landed (`mesh_bundles` issues N independent client bundles sharing one relay/exit peer table) |
| Censorship ladder: QUIC/HTTP/3 cloak + automatic TCP/TLS 1.3 fallback + realistic HTML5 decoy origin | `src/cloak.rs`, `src/bin/advanced-vpn-cloak.rs`, `tools/avpnctl.py`, `tools/cloud.py` | landed (UDP 443 primary, automatic TCP 443 fallback in 2 s when UDP is blocked, 10 s QUIC recovery probe, `200 OK` HTML5 decoy page) |
| Signed local DNS blocklist (`NXDOMAIN` before upstream DoT) | `src/bin/advanced-vpn-dns.rs`, `tools/managed_profile.py`, `tools/avpnctl.py` | landed (`avpn init --dns-blocklist FILE`) |
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
| Per-hop shaping (server↔server links) | `src/link.rs`, `src/run.rs`, `tools/managed_profile.py` (`link.kem.json`) | landed in v0.8.0: paced, encrypted constant-rate links between every pair of consecutive servers, per-link PSK sealed to each device's hybrid KEM key; measured 0.0–0.1% idle-vs-busy change on the link into the exit (`RATE_CLASSES.json`, `inner_link`). (v0.7.0 listed "inter-relay chaff" here: the carrier only ever ran client↔entry, so that row was wrong.) |
| I2P front | `tools/i2p.py`, `src/cloak.rs` (front mode), `tools/avpnctl.py` (front table, `advanced-vpn-i2p` user) | landed in v0.9.0: the client reaches the entry only through I2P; the entry never exchanged a packet with the client in a private I2P network, and only the I2P router left the client (`I2P_FRONT.json`). |
| Mix lane | `tools/mix.py`, `avpn mix`, Katzenpost v0.0.110 (separate, unmodified) | landed in v0.9.0: a mixnet client inside the protected namespace; against a global passive adversary with live websites, 10.7% sender identification vs 88.2% on a low-latency path, chance 10%, with X-Wing (post-quantum) Sphinx (`MIX_LANE.json`). Mesh nodes running mixnet nodes is future work. |
| Self-healing chains: standby exits, failover, rotation | `src/run.rs` (`NextHops`), `tools/managed_profile.py`, `avpn init --standby-exit` | landed for single-operator chains: failover 4.2 s in the lab with no leak, rotation within a signed window, entry fixed as the guard (`FAILOVER.json`); mesh relays do not fail over between members' exits yet |
| Own node as entry + legal spheres | `src/mesh/directory.rs`, `tools/mesh.py`, `tools/providers.py` | landed: the member's own node is its entry; the exit must answer to another legal sphere than the entry (US clouds = one sphere); Rust and Python run one shared fixture (`tools/testdata/chain_selection.json`) |
| Oblivious control plane | `tools/ohttp.py`, `tools/ohttp_relay.py`, beacon `/ohttp` | landed: beacon queries through a relay of another operator, sealed with PQ HPKE (ML-KEM-768 + X25519); RFC 9458 design, not wire-compatible (`OHTTP_LAB.json`) |
| 100-site WF simulation + 30-site namespace WF lab | `docs/evidence/MESH_WF_SIM.json`, `docs/evidence/DAITA_LAB.json`, `docs/evidence/RATE_CLASSES.json` | landed (1.4–2.2% vs 1% chance in 100-site exit-vantage sim; 3.3% vs 3.3% chance at fixed 6 s window in 30-site namespace lab) |

Non-goals: no token sale/cryptocurrency, no company, no GUI in v1, no mobile
clients in v1, no exit-node requirement for membership, no weakening of the
one-mode rule.

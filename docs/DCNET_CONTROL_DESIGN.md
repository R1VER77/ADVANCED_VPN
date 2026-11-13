> **Status (November 2026):** reference design. Adopted as a library only (src/dcnet.rs, tools/dcnet_reference.py, formal/dcnet/), not reachable from any command until the mesh has members. Its claim is computational, never information-theoretic.

# DCNET_CONTROL_DESIGN.md — DC-net control channel for AVPN/Mesh

Status: design proposal. Position taken **after v0.9.0** (I2P front,
Katzenpost mix lane, `avpn mix`, oblivious control plane, VERIFICATION_PLAN.md).
This doc is the step-5 item from `MIX_LANE_DESIGN.md` §4, revised in light of
what actually shipped.

## 0. Position after v0.9.0 — read this first

v0.9.0 changed the calculus. The mix lane (`avpn mix`, unmodified Katzenpost
v0.0.110) already provides computationally anonymous transport for async
traffic, and the oblivious control plane already handles enrollment and
directory queries. So the first question is not *how* to build a DC-net, but
*whether one earns its place*:

| Option for anonymous control events | Trust assumption | Cost | Claim class |
|---|---|---|---|
| **Ride the mix lane** (default, available today) | Katzenpost mix providers non-colluding | zero new code | computational unlinkability |
| **DC-net cell** (this doc) | the other cell members (no infrastructure operator) | new protocol, O(n) round traffic | computational (PRG pads), upgradeable toward IT |
| Oblivious control plane (status quo) | directory servers | already shipped | existing claims |

The DC-net's only honest differentiator is **infrastructure-freedom**: mix
providers can be sybil'd, subpoenaed, or go dark; a DC-net cell's anonymity
depends only on the other members in the cell, who are the same peers whose
servers carry the traffic anyway. Its unique niche is therefore the events
where the *identity of the initiator* is the most damaging thing that could
leak, even if every mix provider is compromised:

- **ENROLL_INTENT** — "someone is joining" before hardware-anchored identity
  is established.
- **CHAIN_SETUP_COMMIT** — the commitment that binds a chain descriptor to a
  session without revealing which member built it.
- **KEY_ROTATION_NOTICE** — announcement that a member's node keys changed
  (the TOFU re-verification event; knowing *who* rotated *when* is itself
  correlation material).
- **MIX_LANE_FALLBACK** — "a member stopped using the mix lane," the event
  most correlated with coercion.

Recommendation: **ship the mix-lane routing of these events first** (a config
flag, days of work), and treat the DC-net cell as the v2 hardening step for
the two events where infrastructure-freedom matters (CHAIN_SETUP_COMMIT,
MIX_LANE_FALLBACK). Everything below is the v2 design.

Non-goals, stated up front: no attempt to carry bulk or interactive traffic;
no accountable-tracing mechanism (see §5 — the jam policy is accept-DoS);
no information-theoretic claim (see §2 — the pads are PRG-derived).

## 1. Architecture

### 1.1 Cells

- Membership is derived deterministically from the existing directory: cell
  assignment = `H(member_id || epoch) mod n_cells`, so no one chooses their
  cellmates and re-assignment happens every epoch (e.g., 24 h) to bound
  long-term pair exposure.
- Target cell size **20–60 concurrently online members** (Herbivore-derived).
  Cells below 12 online members are dissolved for the epoch (an anonymity
  set smaller than a dozen is not worth the bandwidth).
- Mesh-mode only. In single-operator mode there is no peer group; the
  construct is meaningless (an anonymity set of 1 is a tautology) and the
  config must refuse to enable it.

### 1.2 Rounds

- Round cadence: **one round every 5 s** per cell. Control events are rare;
  5 s is imperceptible for the events in scope.
- Round structure: 3 phases, total ≈ 2.5 s + slop:
  1. **Sync** (≈1 s): round number and epoch agreed via the existing gossip
     layer; members who miss sync are treated as silent for the round.
  2. **Transmit** (≈1 s): every online member broadcasts exactly one
     fixed-size transmission (see §3) over their existing constant-rate
     server links.
  3. **Aggregate + verify** (≈0.5 s): any member (or observer) can compute
     the group XOR; decoding follows §4.
- Round numbers are strictly monotonic per cell and **never repeat**, even
  across epochs; pads are derived with the round number in the context
  (round-binding, tested in the harness §6-F).

### 1.3 What rides the DC-net

Only the four event types in §0, each ≤ 64 B encoded, one reserved slot per
round. Everything else (descriptors, credits, liveness) stays on existing
channels — the DC-net is a scalpel, not a general bus.

## 2. Pads and the honest security claim

- At enrollment, each ordered pair establishes `K_ij` via the already-shipped
  hybrid (ML-KEM-768 + X25519), signatures ML-DSA-65. `K_ij` lives in the
  hardware-sealed key store (`keyguard`), same as member keys.
- Per-round pairwise pad: `pad_ij(r) = PRG(HKDF(K_ij, "dc-pad" || cell_id), "dc-round-" || r)`.
- Member i's transmission in round r:
  `c_i(r) = m_i ⊕ (⊕_{j≠i} pad_ij(r))` — member i XORs only the pads of
  pairs involving i, so each pad appears exactly twice in the group sum and
  cancels **by construction** (verified by the harness, §6-F.1).
- **Claim discipline:** because pads come from a PRG seeded by ML-KEM-derived
  keys, the unlinkability guarantee is **computational**, full stop. The doc
  must never say "information-theoretic." The upgrade path (not v2): burn
  pre-provisioned true-random pad material held on the Nitrokey; at 64 B ×
  (n−1) pairs × 17 280 rounds/month ≈ 21 MB per member-month for a 24-member
  cell — logistically plausible, but re-keying on churn burns it faster, so
  this stays an explicitly opt-in hardened mode.

## 3. Wire format

```
dc_frame := magic(2) || cell_id(4) || round(8) || flags(1) || body(64)
           || member_mac(32)          // 111 bytes total
```

- `flags`: version/flags byte, **constant 0 in v2 and identical across all
  members in a round.** It must NEVER encode sender state (a "this frame
  carries an event" bit would identify the sender outright — the bodies
  themselves look uniformly random whether or not they carry an event, and
  that is the only thing keeping the sender hidden).
- `body`: every member's body is a full pad XOR (`⊕ over partners j of
  pad_ij(r)`), with the sender additionally XORing the event encoding
  `{ event_type(1) || nonce(8) || payload(46) || crc8(1) || zero(8) }`.
  A silent member's body is NOT zero — it is indistinguishable random-looking
  bytes; only the *group sum* of a null round is all-zero.
- `member_mac`: keyed by a *per-round broadcast key* derived from
  `HKDF(K_ij-family)`? — No: the MAC key cannot identify the member or the
  sum would be linkable. Instead: `member_mac = HMAC(anon_key_r, frame)`,
  where `anon_key_r = HKDF(⊕-of-nothing...)` — concretely, each member uses
  a **pre-committed per-epoch anonymous MAC key** registered blinded with
  the directory (blind-RSA credits machinery, already shipped). The MAC
  exists only to authenticate *membership in the cell* (jam filtering input,
  §5), not to identify the member: the directory can verify the MAC against
  the blinded registration without learning which member sent which frame.
- Total frame: 111 B. Inside the existing constant-rate envelope this is
  noise — the DC-net traffic is indistinguishable from ordinary cell framing
  on the wire.

Per-member per-round transmit volume: 111 B × 1 frame + the group sum they
compute locally from gossip-synced frames: O(n) frames observed ≈ 24 × 111 B
≈ 2.7 KB/round ≈ **0.5 KB/s** steady-state at 5 s rounds. Cheap by design.

## 4. Decoding and collision handling

- Group XOR of all n frames: null rounds decode to all-zero; a sender's
  event survives cancellation.
- **Collision** (two senders in one round): XOR of two different event
  encodings — the CRC-8 check fails and the round decodes as Garbled.
  Policy: both events are lost; each sender re-transmits in a later round
  chosen by exponential backoff keyed to their (private) nonce. Expected
  collision rate at ≤1 event/cell/hour across 24 members: negligible
  (<10⁻⁴/round); at enrollment storms (many ENROLL_INTENTs), backoff
  resolves within seconds.
- **Identical-collision edge (documented, accepted):** two senders
  submitting *byte-identical* events in the same round cancel to a null
  round — indistinguishable from no event. Benign (duplicate events carry
  no information beyond the first), and the per-event nonce makes it
  vanishingly rare by construction.
- **Jam** (member xors garbage every round): group sum is non-decodable
  garbage (harness §6-F.4). Policy in v2: abort the round, do nothing else.
  See §5.

## 5. Jamming policy (decided before the protocol, as promised)

- **v2 accepts DoS.** A jamming member can suppress DC-net rounds
  indefinitely. The events in scope all have non-DC-net fallbacks (mix lane,
  oblivious control plane), so jamming degrades the *stronger* guarantee,
  not availability of the function itself.
- **Accountable tracing is out of scope and must stay out.** Any mechanism
  that can identify a disrupter is a mechanism that can identify a sender.
  If jamming becomes a sustained practical problem, the answer is cell
  re-assignment (epoch churn) — the jammer must re-enroll and re-establish
  pairwise keys each epoch, at hardware-anchored cost — not traitor tracing.
- This trade-off is a documented consequence, not an oversight.

## 6. Verification

Hooks into `VERIFICATION_PLAN.md` (extend its priority list):

8. **DC-net round state machine** — Tamarin model of the XOR-cancellation +
   round-binding properties: pad cancellation, replay-of-stale-round fails,
   sender-position independence. The three properties are exactly harness
   §6-F.1/F.3/F.2 in symbolic form. **Model authored: `dcnet.spthy`** (4
   lemmas: pad_secrecy, sender_anonymity, cancellation, frame_origin) —
   authored, not yet executed; run `tamarin-prover dcnet.spthy --prove`.
9. **Pad derivation** — Kani harness over `pad_ij(r) = PRG(HKDF(...))`:
   round-context separation, no pad reuse across epochs.

Statistical/empirical harness (`mix_lane_test_harness.py`, section F,
currently 5/5 passing):

- F.1 XOR-cancellation recovers the message; idle round decodes null.
- F.2 decodes for every sender position (24/24).
- F.3 stale round transmission fails to decode (round-binding).
- F.4 jam corrupts the round and is detectable (abort policy).

**Rust reference implementation: `src/dcnet.rs`** — round core, frame
codec, pad derivation, group aggregation, with an inline test module whose
golden vectors are generated by the byte-exact Python mirror
(`tools/dcnet_reference.py`, writes `vectors.json`; 8/8 self-checks
passing). Cross-language vector equality is proven on the Python side and
asserted by the Rust tests against the embedded hex vectors.

Live tests to add when the Rust lands in the binary: round-participation
uniformity under idle vs event-carrying epochs (KS, same machinery as
mix-lane test A), and epoch churn coverage (every member sees every
cellmate over K epochs with high probability — coupon-collector bound,
state the K).

## 7. Implementation order

1. Config flag: route CHAIN_SETUP_COMMIT and MIX_LANE_FALLBACK over the
   existing mix lane (days; immediately useful).
2. ~~Rust module `src/dcnet.rs`~~ **authored** — drop in `src/dcnet.rs`,
   wire cell assignment from directory and gossip round-sync at the
   integration layer (`avpn mesh`).
3. ~~Harness section F ported to Rust integration tests; Tamarin model~~
   **authored** — inline `#[cfg(test)]` module in `src/dcnet.rs` (14 tests,
   golden-vector based) + `dcnet.spthy`. Remaining: run `cargo test` and
   `tamarin-prover --prove` in CI (extend `.github/workflows/verify.yml`).
4. Opt-in true-random pad mode (Nitrokey-held material), documented as the
   only path to an information-theoretic statement, with the re-key burn
   rate computed from real churn.

## 8. Resulting Limits-section wording (proposed)

> The DC-net control channel provides sender unlinkability for a fixed set
> of control events within a cell of concurrently online members, under the
> assumption that at least one pairwise pad per event is uncompromised. The
> guarantee is computational (PRG-derived pads); an optional hardware-held
> true-random pad mode upgrades it toward information-theoretic at a
> documented key-burn cost. The channel is intentionally narrow: it does
> not carry bulk traffic, it is disabled in single-operator mode, and it
> accepts denial-of-service rather than adopting any accountability
> mechanism that could identify a sender.

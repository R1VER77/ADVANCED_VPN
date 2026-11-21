# cypherpunk_vpn roadmap

Updated 19 November 2026. This is the public project roadmap. Items below are planned
unless explicitly marked complete; implementation, a passing laboratory test and a
production security claim are separate milestones. The existing detailed design and
validation documents remain the technical references.

The agreed [implementation plan for tasks 1–7](IMPLEMENTATION_PLAN_20261117.md) records
the sequence, interfaces, code sketches, selected defaults and acceptance gates. It was
saved at the owner's request before implementation; planned work is not completion.

The owner's [18 November extension](HARDWARE_EMULATION_AND_CLOUD_INSTALLER_PLAN_20261118.md)
specifies hardware simulation first, whole-registry OpenTofu search with separately
reviewed VPN recipes, strict hardware eligibility, and immediate signed publication
of the validated checkpoint. It preserves the remaining main-plan acceptance gates.

## 1. Traffic-analysis resistance: first technical priority

- [x] Complete the interleaved relay-clock look-ahead measurement, comparing page-load
  success, latency and fingerprinting resistance before choosing defaults.
  The [17 November analysis](WF_REAL_RERUN3.md) found residual classification signal
  and more missed relay slots at 5 ms; defaults remain unchanged.
- [ ] Repeat with a fresh undefended positive control, counterbalanced variant order,
  varied recorded site-order seeds and clear snapshot/failed-load reporting. The
  six-round, 720-attempt plan was attempted on 17 November; capture loss and battery
  conditions invalidated that run. Its failed data remains preserved; a newly frozen
  run is required.
  [Fresh-control analysis tooling](WF_REPLICATION.md) now retains complete failed-load
  windows and fits secondary resource references on training rounds only. Recorder,
  protection-validity checks and the counterbalanced runner are implemented. The frozen
  run completed on 20 November ([result](WF_REPLICATION.md)): defended accuracy is near
  chance with no corrected signal, but the local gate failed on upper bounds (up to 12.1%),
  load success (−6 to −7 points) and one unprotected sample window per arm; defaults stay.
  Cross-environment qualification remains open.
- [ ] Validate the busy-CPU fix on held-out days, networks and devices, with confidence
  intervals, negative results and load failures reported alongside positive results.
- [ ] Expand beyond the current small closed-world experiment to larger monitored and
  open-world sets and cross-link correlation attacks.
- [x] Keep experimental controls opt-in. This remains a release constraint until their
  acceptance gates pass; the latest measurements did not authorize promotion.

See the [README measurements](../README.md), [verification plan](VERIFICATION_PLAN.md)
and [security scope](../SECURITY.md). More hops under one operator do not establish
anonymity from that operator.

## 2. CCC-informed principles and governance

This work draws on the CCC's [Hacker Ethics](https://www.ccc.de/en/hackerethik),
[statutes](https://www.ccc.de/en/satzung) and
[incompatibility declaration](https://www.ccc.de/en/club/unvereinbarkeitserklaerung-des-ccc).
It does not claim CCC approval, affiliation or certification. The CCC association's
organizational and nonprofit provisions are not automatically this project's structure.

- [x] Publish a concise [principles statement](PRINCIPLES.md): privacy, decentralization, free software,
  public technical knowledge, user autonomy and attention to social consequences.
- [x] Publish [community conduct rules](../CODE_OF_CONDUCT.md) explicitly rejecting racism, fascism,
  harassment and the trivialization of historical or current violence, with a private
  reporting route, named responsibility and a fair response/appeal process. Apply these
  rules to project participation and partnerships without surveilling VPN users. The
  single-maintainer project has no independent appeal panel; conflicted appeals await
  an agreed uninvolved reviewer rather than inventing independence.
- [x] Publish a [voluntary funding and partnership record](FUNDING.md), reflecting the
  owner's current report and intention to disclose future funding, with private donor
  information protected. No new paid services or audit budget is authorized. Unknown
  or undisclosed relationships are not evidence of independence.
- [x] Record important [design and governance decisions](DECISIONS.md), their reasons and [review paths](GOVERNANCE.md);
  evaluate contributions by their merits and conduct rather than credentials or status.
- [x] Preserve the project's free-software aims under its [current license terms](../LICENSE);
  the previous Apache declaration is historical provenance. Community conduct rules must not become
  additional license restrictions, traffic inspection or identity collection.
- [ ] Document hardware, server, accessibility and connectivity costs; test the setup
  with people who do not already administer servers. Report cover-traffic bandwidth,
  energy/battery costs and trade-offs without silently weakening protection.
  Documented on 21 November: [hardware costs](HARDWARE_COSTS.md), and every server's monthly cap and
  usage ([fee guard](FEE_GUARD.md)). Open: the sessions with people who do not administer servers.
- [x] Keep security limitations prominent, distinguish implemented/tested/planned claims,
  and publish reproducible evidence and incidents. An [independent review package](INDEPENDENT_REVIEW.md)
  is prepared and supports unpaid review; it is not a completed audit.
- [ ] Obtain and publish scoped independent review and closure evidence before broad
  anonymity or production-readiness claims. Funding is not a prerequisite for review.

Acceptance: linked public policies and reporting instructions; a visible decision and
funding record; a documented accessibility evaluation; reproducible measurements; and
review that the policies add no surveillance or proprietary license restrictions.
These governance items are not complete merely because this roadmap lists them.

## 3. Installation and guided setup

**The setup flow (owner, 20 November, [D007](DECISIONS.md), [design](GEMMA_SETUP_FLOW.md)):**
one ordered, Gemma-led conversation. (1) Provisioning through pinned OpenTofu modules,
with the hardware-key work inside it; (2) when it completes, the GUI appears; (3) each later
launch checks for a viable profile: none leads back to provisioning, otherwise choose one
or add another. The open items below are the parts of that flow, in that order: hardware
keys, then OpenTofu provisioning, then the profile store and GUI, with Gemma leading
throughout.

- [x] Deliver shared read-only preflight, current-evidence setup progress and confirmed,
  narrowly scoped hardware repairs. A command succeeding is not proof a repair worked.
- [x] Physically test the four connected Nitrokey, YubiKey, Trezor and Ledger units
  using isolated test vaults, without resets or wallet material. On 17 November all
  four passed capability checks, fresh-assertion vault round trips,
  missing-access detection, confirmed udev repair and baseline restoration
  ([evidence](evidence/SETUP_HARDWARE_20261117.json)). YubiKey disabled-USB-FIDO2 recovery
  also passed, preserving the same credential and USB/NFC settings.
- [ ] Complete physical multiple-device, locked/unavailable-app, additional model/firmware
  and full enrolled-installation scenarios. Synthetic ambiguity checks do not close these.
- [ ] Add actual Nitrokey USB/IP, Trezor and Ledger app-emulator integration and generic
  virtual-token/fault tests against production crypto. Publish evidence by test level;
  block strict setup for noncompliant interfaces without changing existing credentials.
  On 19 November the unmodified FIDO2 firmware of CanoKey, TKey (Tillitis QEMU) and
  Solo 2 passed the same production-crypto operations as Solo 1
  ([support matrix](SUPPORT_MATRIX.md)); the TKey run found a firmware hmac-secret
  protocol-2 defect, handled by negotiating protocol 1 for that key. The owner skipped
  the Nitrokey 3, Trezor and Ledger emulators as optional, the physical units being the
  baseline; they remain open here.
- [ ] Keep the long-term VPN keys on the hardware key (owner request, 19 November). Today
  the key only unseals a vault, so malware on the computer can copy the unlocked keys
  whatever the PIN entry. **Phase 1 done** ([hardware-bound sessions](HARDWARE_BOUND_SESSIONS.md)):
  every hop now refuses a hardware-protected client's leaves unless its FIDO2 key, touched
  and PIN-unlocked, signed that session (at most 12 h), so copied keys stop working when the
  session ends; verified on four emulated firmwares and in Tamarin. **Phase 2 done** (20
  November): the VPN's processes hold only per-session keys, certified by a short-lived,
  undumpable signer that alone unseals the identities; a stolen session key works only in
  its window. Remaining: per-session carrier (WireGuard, cloak) keys, a Qubes-style signing
  VM transport, and the physical units. Kernel WireGuard takes its static key as bytes and needs it at
  every handshake (about every two minutes), so this needs a userspace data plane that asks
  the key for each X25519 operation without a touch: OpenPGP-card ECDH on Nitrokey 3,
  YubiKey, CanoKey and Ledger, SLIP-0017 on Trezor, or a TKey app; not FIDO2. It protects
  the durable identity, not a session in progress: present malware still sees that
  session's keys and plaintext. The post-quantum PSK and ML-KEM keys stay on the computer
  until a key offers ML-KEM without returning the shared secret over USB.
- [x] Rank every supported key (owner decision, 19 November): open firmware is
  cypherpunk-preferred, a PIN entered on the key beats one typed on the computer, and the
  P-256 CTAP PIN/UV channel is flagged on every key rather than blocking
  ([ranking](DEVICE_COMPATIBILITY_VALIDATION.md)). No firmware is modified.
- [x] Package a pinned runtime and offline core dependencies. Validate system/user
  install, in-place replacement, guarded removal, corruption refusal and preserved state
  in clean Debian 12/13 and Ubuntu 22.04/24.04 VMs. Installation never enables services.
  [Evidence](evidence/OFFLINE_PACKAGE_20261117.json) includes Python 3.13.18/OpenSSL 3.5.9,
  604 tests on both Python 3.10 and 3.13, and explicit limits.
- [ ] Finish static musl preflight, native `.deb`/`.rpm` and signed apt distribution,
  cross-release/protocol migrations, interrupted-upgrade recovery and current-release
  reboot/protection testing. Same-bundle replacement is not a rolling live upgrade.
  Native candidate lifecycle trials passed on [four Debian/Ubuntu releases](evidence/NATIVE_PACKAGE_MATRIX_20261118.json)
  and [Fedora/Rocky](evidence/NATIVE_RPM_MATRIX_20261118.json). Production signing,
  provenance, publication and full protection/recovery qualification remain open.
- [ ] Broaden cloud provisioning through pinned OpenTofu modules and retain bring-your-own
  SSH hosts. Provider actions need resource previews, cost information and clean teardown.
  This is step 1 of the flow, and the hardware-key items above run inside it.
- [ ] A profile store: the client holds more than one enrolled chain with an active
  selection, and a viability check (verified, current, protection intact, servers healthy)
  that decides what each launch shows.
- [ ] The GUI ([`apps/cypherpunk-vpn`](../apps/cypherpunk-vpn)) appears when provisioning
  completes, and on later launches offers the viable profiles or adding one. It stays driven
  by the same typed controller checks, with honest progress, actionable failure states
  (including a chain that stops answering) and explicit review of privileged or billable
  changes.
- [ ] Gemma-centric setup (D007): a local Gemma model leads the whole flow conversationally,
  trained for the conversation and tool calls over the narrowed provider catalog, its facts
  from the versioned catalog and provider documentation (training is not a substitute for
  current documentation). It calls only the engine's typed tools; credentials and PINs stay
  outside its context; approval stays with the person; the flow works without it.
- [ ] Add local search across the full OpenTofu registry. Only reviewed, pinned,
  VPN-capable recipes may provision; enforce encrypted saved plans/state, exact-plan
  review, operation ownership and recovery. Listing is not live-provider qualification.

## 4. Assurance, decentralization and anonymity sets

- [x] Prepare a scoped [review package](INDEPENDENT_REVIEW.md) that supports unpaid
  independent review without making development depend on funding.
- [ ] Extend formal models, fuzz parsers, review secret handling and obtain actual
  independent review covering shaping and enrollment/control boundaries. Self-review
  and CI are not independent review.
  On 19 November Tamarin models for [verification plan](VERIFICATION_PLAN.md) items 1–6
  joined CI: 15 models, 52 lemmas verified and 24 mutants falsified, each within the
  abstraction [its fidelity table](../formal/README.md) states. ProVerif then proved
  OHTTP and credit unlinkability (mutation-checked); the credit work found and closed an
  issuer tagging attack (`unblind` now verifies). Hardware-bound sessions added a sixteenth
  Tamarin model: 57 lemmas and 26 mutants in all (`docs/evidence/TAMARIN.json`). On 20
  November Kani proved the link's replay window and reply credit on the code itself, and
  every parser of outside bytes is fuzzed in CI (five Rust targets, coverage-guided, 40
  million runs clean before landing; Python by mutation, which found three exception
  types escaping the enrollment and session-leaf parsers, now refused as `ValueError`).
  Secret-handling review and independent review remain.
  On 21 November a secret-handling review ([tools/test_secret_review.py](../tools/test_secret_review.py)) and
  per-session carrier keys ([tools/test_session_carrier.py](../tools/test_session_carrier.py)) landed; independent review remains.
- [x] Let the operator add a hardware post-quantum signature (19 November): an optional
  third signature half from an ML-DSA-44 FIDO2 credential on a separate key, required by
  every verifier once the operator's public file names it. Only Solo 2's Hacker build
  offers that credential today, so it is tested in emulation only.
- [x] Review the owner-supplied Maurer and Ahlswede–Csiszár papers against the DC-net
  construction and pad tools. The [review](INFORMATION_THEORETIC_REVIEW_20261117.md)
  supports conditional construction-level sender anonymity and records the current
  generator's proof gaps; it does not qualify an operational VPN claim.
- [ ] Qualify a strict information-theoretic pad profile: conditional source entropy,
  independent extractor seed, seed reuse and joint error budgets, secret custody,
  non-reuse and actual honest-edge connectivity. Resolve event authorization before
  DC-net integration; the public event hash is not authentication.
- [ ] Validate pad exposure containment and forward-secrecy boundaries against the
  [assessment and engineering guide](PAD_EXPOSURE_VALIDATION.md): independent-pad
  assumptions, adaptive exposure, durable consumption, complete-book compromise,
  erasure limits and integration. Treat post-compromise recovery as separate new
  work; existing symbolic proofs do not qualify that stronger claim.
- [x] Remove the central public DNS dependency through a self-run resolver at the exit,
  preserving the documented post-quantum transport policy and explaining resolver limits.
  `avpn init --dns-recursive` (20 November): the exit's Unbound validates DNSSEC and
  minimises query names; checked live (20 of 20 names, a DNSSEC failure refused) with the
  exit's forwarder in front, which only ever speaks plain DNS to loopback. Its queries to
  authoritative servers are plain DNS, a named exception (PQ_INVENTORY exception 5), so it
  is opt-in; the hybrid post-quantum DoT forwarder stays the default.
- [ ] Measure operator/provider independence, correlation exposure and actual anonymity
  sets. Evaluate integration with an existing compatible anonymity network.
- [ ] Review mesh membership and credit verification; keep unreviewed mechanisms
  fail-closed and clearly label classical versus post-quantum security assumptions.

See [mesh](MESH_DESIGN.md), [mix lane](MIX_LANE_DESIGN.md),
[DC-net control](DCNET_CONTROL_DESIGN.md), [membership](ZK_MEMBERSHIP_DESIGN.md)
and the [post-quantum inventory](PQ_INVENTORY.md).

## 5. Name migration and reach

- [x] Use `cypherpunk_vpn` as the project name in the README.
- [x] [Plan](NAME_MIGRATION.md) the repository, binary, package, service, state and signed-chain migration;
  preserve recovery and avoid breaking existing installations through a cosmetic rename.
- [x] Implement and validate the compatibility migration before changing canonical
  services, state paths or signed protocol domains.
  On 21 November the compatibility shim landed ([tools/name_migration.py](../tools/name_migration.py),
  13 tests): old names keep working while the canonical ones change.
- [ ] Expand to aarch64 Linux, then additional desktop/mobile platforms, with
  platform-specific protection tests before marking each supported.
- [x] Publish a [device/platform matrix](SUPPORT_MATRIX.md) distinguishing protocol compatibility,
  physically tested models/firmware and planned targets.

## 6. CYPHERPUNKS research qualification

The [18 November review](RESEARCH_REVIEW_20261118.md) reconciles the on-disk GLM5.3
artifacts and the [research specification](CYPHERPUNKS_PROTOCOL_SPECIFICATION.md).
The owner's full-stack hybrid-PQ and SafeCurves requirements remain target policy.

- [x] Harden and locally validate the Task 3 packaging proposal: real RPM scriptlet/EVR
  semantics, required signed index coverage, no-follow paths, primary/subkey pins,
  signed key classification and freshness. Real apt positive/negative controls and
  six-distribution native package lifecycle trials passed. This closes the scoped
  proposal checks, not production signing/publication or complete platform protection.
- [ ] Specify and prove voucher issuance, redemption, quantum unlinkability,
  nullifier binding and spent-state recovery. A classical VOPRF plus KEM/hash inputs
  is not by itself a proof of those properties. Keep public admission fail-closed.
  Implemented on 21 November ([tools/voucher.py](../tools/voucher.py), [tools/voprf.py](../tools/voprf.py), RFC 9497 vectors);
  the proofs remain.
- [ ] Implement/authenticate a consistent PIR directory with secure randomness and
  explicit independent-operator assumptions. Distinguish XOR reference timings from
  deployed DPF results and from network reservations.
  Implemented on 21 November ([tools/pir_directory.py](../tools/pir_directory.py): two-server XOR and DPF, 13 tests);
  deployed DPF timings remain.
- [ ] Account for all handshake flights and parameter generations. Retain the
  established hybrid/ML-DSA baseline while evaluating MAYO; category-1 MAYO-1 does
  not supply category-3 authentication. Preserve PMTU/fallback and downgrade protection.
- [ ] Allocate disjoint, durably consumed material to DC-net masks and session PSKs;
  qualify physical entropy/custody and cross-plane linkage before operational IT claims.
- [ ] Resolve DC-net scheduling versus the bootstrap target, logical broadcast versus
  physical fanout/bandwidth, and jamming abort versus event authorization.
- [ ] Validate complete DLEQ batches, authenticated event effects and jamming/fallback
  dependencies. Preserve no-tracing policy without claiming that all disruption
  accountability identifies honest senders; include the whitepaper draft corrections
  in the research review before publication.
  On 21 November [tools/dcnet_validation.py](../tools/dcnet_validation.py) (20 tests) validated complete DLEQ
  batches over the real ristretto255 VOPRF, authenticated event effects (a substitution
  attack shown, then closed) and jamming/fallback dependencies (detection, never
  attribution). Open: the whitepaper draft corrections in the research review.
- [ ] Complete the interface/curve inventory and versioned migration. Preserve current
  device keys, document compatibility dependencies and test the PQ property of each
  interface; do not silently reset hardware to satisfy a design mandate.
  The inventory landed on 21 November ([tools/test_curve_inventory.py](../tools/test_curve_inventory.py), which scans this
  tree); the versioned migration remains.
- [ ] Publish scientific claims/whitepaper figures only after the corresponding formal,
  live empirical and independent-review gates. Synthetic chance-level classification
  and primitive timings remain labelled research results.

These items extend assurance stage 7 of the main plan. They do not close or replace
its current installation, live traffic, native GUI, provider, hardware and usability gates.

## Release gates

Use signed, reviewable changes; a changelog and incident history; appropriate local and
CI checks; hardware and VM validation for affected paths; and explicit live-deployment
review. Do not ship a positive privacy claim based only on simulated tests. Documentation
and accessible setup can progress while CPU-sensitive experiments run; compilation and
load tests wait until those measurements finish.

## Commercial-gap and streaming items (21 November)

Landed, each with its tests (`python -m unittest tools.test_<name>`):

- [x] Streaming eligibility as dated measurement, never a promise: `avpn stream-check`
  ([tools/stream_check.py](../tools/stream_check.py), with the transport profile), the generated
  [eligibility table](STREAMING_ELIGIBILITY.md) and `avpn cloud rotate` for a fresh exit address
  ([streaming parity](STREAMING_GEO_PARITY_20261120.md) §4).
- [x] `exit_policy` and `streaming` in the signed node descriptor, validated alike by the
  Python control plane and every Rust node (one shared fixture, `tests/fixtures/descriptor_fields.json`;
  [path selection](PATH_SELECTION_DESIGN.md) §2). Rust nodes refused both as unknown fields before.
- [x] Auto-connect on untrusted networks ([tools/autoconnect.py](../tools/autoconnect.py)), multi-hop presets with the
  3-hop ceiling ([tools/multihop_presets.py](../tools/multihop_presets.py)), and the GUI's read side for both plus the
  eligibility table ([tools/controller_extension.py](../tools/controller_extension.py); SSIDs never cross).
- [x] The IPv6 leak suite ([tools/ipv6_leak_suite.py](../tools/ipv6_leak_suite.py)).
- [ ] IPv6 inside the user's tunnel ([design](IPV6_TUNNELING_DESIGN.md), D009). IPv6 between servers
  shipped separately: TCP links and the egress lock ([fee guard](FEE_GUARD.md)).
- [ ] Router deployment on GL-MT6000/GL-MT3000 ([design](ROUTER_DEPLOYMENT.md), D010); signed
  deployment-side auto-update (D011); [Tor over the tunnel](TOR_RECIPE.md) (D012).
- [x] The GUI's write side: the create/join setup branches over three branch-bound actions
  (operator keys, the exit request, signing the route with a stated allowance; accepting a
  cost above the allowance is not offered), exact argv, previews that re-verify, an
  append-only journal ([tools/controller_create_join.py](../tools/controller_create_join.py)).
- [ ] The first live eligibility row from a real exit (D016), and a real `avpn cloud rotate`.

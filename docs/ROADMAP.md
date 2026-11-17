# cypherpunk_vpn roadmap

Updated 17 November 2026. This is the public project roadmap. Items below are planned
unless explicitly marked complete; implementation, a passing laboratory test and a
production security claim are separate milestones. The existing detailed design and
validation documents remain the technical references.

## 1. Traffic-analysis resistance: first technical priority

- [ ] Complete the interleaved relay-clock look-ahead measurement, comparing page-load
  success, latency and fingerprinting resistance before choosing defaults.
- [ ] Validate the busy-CPU fix on held-out days, networks and devices, with confidence
  intervals, negative results and load failures reported alongside positive results.
- [ ] Expand beyond the current small closed-world experiment to larger monitored and
  open-world sets and cross-link correlation attacks.
- [ ] Keep experimental controls opt-in until their acceptance gates pass.

See the [README measurements](../README.md), [verification plan](VERIFICATION_PLAN.md)
and [security scope](../SECURITY.md). More hops under one operator do not establish
anonymity from that operator.

## 2. CCC-informed principles and governance

This work draws on the CCC's [Hacker Ethics](https://www.ccc.de/en/hackerethik),
[statutes](https://www.ccc.de/en/satzung) and
[incompatibility declaration](https://www.ccc.de/en/club/unvereinbarkeitserklaerung-des-ccc).
It does not claim CCC approval, affiliation or certification. The CCC association's
organizational and nonprofit provisions are not automatically this project's structure.

- [ ] Publish a concise principles statement: privacy, decentralization, free software,
  public technical knowledge, user autonomy and attention to social consequences.
- [ ] Publish community conduct rules explicitly rejecting racism, fascism,
  harassment and the trivialization of historical or current violence, with a private
  reporting route, named responsibility and a fair response/appeal process. Apply these
  rules to project participation and partnerships without surveilling VPN users.
- [ ] Publish funding, sponsorship, material conflicts and partnership decisions, while
  protecting donor and contributor information that need not be public. Do not present
  unknown or undisclosed funding as evidence of independence.
- [ ] Record important design and governance decisions, their reasons and review paths;
  evaluate contributions by their merits and conduct rather than credentials or status.
- [ ] Preserve Apache-2.0 software freedoms. Community conduct rules must not become
  additional license restrictions, traffic inspection or identity collection.
- [ ] Document hardware, server, accessibility and connectivity costs; test the setup
  with people who do not already administer servers. Report cover-traffic bandwidth,
  energy/battery costs and trade-offs without silently weakening protection.
- [ ] Keep security limitations prominent, distinguish implemented/tested/planned claims,
  publish reproducible evidence and incidents, and seek independent review before
  making broad anonymity or production-readiness claims.

Acceptance: linked public policies and reporting instructions; a visible decision and
funding record; a documented accessibility evaluation; reproducible measurements; and
review that the policies add no surveillance or proprietary license restrictions.
These governance items are not complete merely because this roadmap lists them.

## 3. Installation and guided setup

- [x] Deliver shared read-only preflight, current-evidence setup progress and confirmed,
  narrowly scoped hardware repairs. A command succeeding is not proof a repair worked.
- [ ] Test Nitrokey, YubiKey, Trezor and Ledger: detection, capability limitations,
  multiple devices, unavailable/locked apps, missing device access, repair and rollback.
  Use isolated test vaults; never reset credentials or use wallet recovery material.
  On 17 November all four connected units passed fresh-assertion vault round trips,
  missing-access detection, confirmed udev repair and baseline restoration
  ([evidence](evidence/SETUP_HARDWARE_20261117.json)). YubiKey disabled-USB-FIDO2 recovery
  also passed, preserving the same credential and USB/NFC settings. Locked-app, additional
  firmware/model and complete installation scenarios still need coverage.
- [ ] Package a pinned runtime and offline dependencies; validate install, upgrade,
  removal and recovery in clean supported-distribution VMs. Do not silently enable VPN
  services during installation.
- [ ] Add a GUI driven by the same typed controller checks, with honest progress,
  actionable failure states and explicit review of privileged or billable changes.
- [ ] Evaluate an optional local Gemma assistant against the deterministic setup engine.
  Use versioned official provider documentation and tested adapters for changing flows;
  model training is not a substitute for current documentation. Keep credentials and
  PINs outside model context, bound its tools, and reserve approval for the user.
- [ ] Broaden cloud provisioning through pinned OpenTofu modules and retain bring-your-own
  SSH hosts. Provider actions need resource previews, cost information and clean teardown.

## 4. Assurance, decentralization and anonymity sets

- [ ] Extend formal models, fuzz parsers, review secret handling and commission an
  independent audit covering the shaping fix and enrollment/control boundaries.
- [ ] Remove the central public DNS dependency through a self-run resolver at the exit,
  preserving the documented post-quantum transport policy and explaining resolver limits.
- [ ] Measure operator/provider independence, correlation exposure and actual anonymity
  sets. Evaluate integration with an existing compatible anonymity network.
- [ ] Review mesh membership and credit verification; keep unreviewed mechanisms
  fail-closed and clearly label classical versus post-quantum security assumptions.

See [mesh](MESH_DESIGN.md), [mix lane](MIX_LANE_DESIGN.md),
[DC-net control](DCNET_CONTROL_DESIGN.md), [membership](ZK_MEMBERSHIP_DESIGN.md)
and the [post-quantum inventory](PQ_INVENTORY.md).

## 5. Name migration and reach

- [x] Use `cypherpunk_vpn` as the project name in the README.
- [ ] Plan the repository, binary, package, service, state and signed-chain migration;
  preserve recovery and avoid breaking existing installations through a cosmetic rename.
- [ ] Expand to aarch64 Linux, then additional desktop/mobile platforms, with
  platform-specific protection tests before marking each supported.
- [ ] Publish a device/platform matrix distinguishing protocol compatibility,
  physically tested models/firmware and planned targets.

## Release gates

Use signed, reviewable changes; a changelog and incident history; appropriate local and
CI checks; hardware and VM validation for affected paths; and explicit live-deployment
review. Do not ship a positive privacy claim based only on simulated tests. Documentation
and accessible setup can progress while CPU-sensitive experiments run; compilation and
load tests wait until those measurements finish.

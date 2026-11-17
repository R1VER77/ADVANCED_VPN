# cypherpunk_vpn roadmap

Updated 17 November 2026. This is the public project roadmap. Items below are planned
unless explicitly marked complete; implementation, a passing laboratory test and a
production security claim are separate milestones. The existing detailed design and
validation documents remain the technical references.

The agreed [implementation plan for tasks 1–7](IMPLEMENTATION_PLAN_20261117.md) records
the sequence, interfaces, code sketches, selected defaults and acceptance gates. It was
saved at the owner's request before implementation; planned work is not completion.

## 1. Traffic-analysis resistance: first technical priority

- [x] Complete the interleaved relay-clock look-ahead measurement, comparing page-load
  success, latency and fingerprinting resistance before choosing defaults.
  The [17 November analysis](WF_REAL_RERUN3.md) found residual classification signal
  and more missed relay slots at 5 ms; defaults remain unchanged.
- [ ] Repeat with a fresh undefended positive control, counterbalanced variant order,
  varied recorded site-order seeds and clear snapshot/failed-load reporting. The
  six-round, 720-attempt plan is prepared but has not been started.
  [Fresh-control analysis tooling](WF_REPLICATION.md) now retains complete failed-load
  windows and fits secondary resource references on training rounds only. Recorder,
  protection and counterbalanced-runner evidence still need implementation.
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
- [x] Preserve Apache-2.0 software freedoms. Community conduct rules must not become
  additional license restrictions, traffic inspection or identity collection.
- [ ] Document hardware, server, accessibility and connectivity costs; test the setup
  with people who do not already administer servers. Report cover-traffic bandwidth,
  energy/battery costs and trade-offs without silently weakening protection.
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
- [x] Package a pinned runtime and offline core dependencies. Validate system/user
  install, in-place replacement, guarded removal, corruption refusal and preserved state
  in clean Debian 12/13 and Ubuntu 22.04/24.04 VMs. Installation never enables services.
  [Evidence](evidence/OFFLINE_PACKAGE_20261117.json) includes Python 3.13.18/OpenSSL 3.5.9,
  604 tests on both Python 3.10 and 3.13, and explicit limits.
- [ ] Finish static musl preflight, native `.deb`/`.rpm` and signed apt distribution,
  cross-release/protocol migrations, interrupted-upgrade recovery and current-release
  reboot/protection testing. Same-bundle replacement is not a rolling live upgrade.
- [ ] Add a GUI driven by the same typed controller checks, with honest progress,
  actionable failure states and explicit review of privileged or billable changes.
- [ ] Evaluate an optional local Gemma assistant against the deterministic setup engine.
  Use versioned official provider documentation and tested adapters for changing flows;
  model training is not a substitute for current documentation. Keep credentials and
  PINs outside model context, bound its tools, and reserve approval for the user.
- [ ] Broaden cloud provisioning through pinned OpenTofu modules and retain bring-your-own
  SSH hosts. Provider actions need resource previews, cost information and clean teardown.

## 4. Assurance, decentralization and anonymity sets

- [x] Prepare a scoped [review package](INDEPENDENT_REVIEW.md) that supports unpaid
  independent review without making development depend on funding.
- [ ] Extend formal models, fuzz parsers, review secret handling and obtain actual
  independent review covering shaping and enrollment/control boundaries. Self-review
  and CI are not independent review.
- [x] Review the owner-supplied Maurer and Ahlswede–Csiszár papers against the DC-net
  construction and pad tools. The [review](INFORMATION_THEORETIC_REVIEW_20261117.md)
  supports conditional construction-level sender anonymity and records the current
  generator's proof gaps; it does not qualify an operational VPN claim.
- [ ] Qualify a strict information-theoretic pad profile: conditional source entropy,
  independent extractor seed, seed reuse and joint error budgets, secret custody,
  non-reuse and actual honest-edge connectivity. Resolve event authorization before
  DC-net integration; the public event hash is not authentication.
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
- [x] [Plan](NAME_MIGRATION.md) the repository, binary, package, service, state and signed-chain migration;
  preserve recovery and avoid breaking existing installations through a cosmetic rename.
- [ ] Implement and validate the compatibility migration before changing canonical
  services, state paths or signed protocol domains.
- [ ] Expand to aarch64 Linux, then additional desktop/mobile platforms, with
  platform-specific protection tests before marking each supported.
- [x] Publish a [device/platform matrix](SUPPORT_MATRIX.md) distinguishing protocol compatibility,
  physically tested models/firmware and planned targets.

## Release gates

Use signed, reviewable changes; a changelog and incident history; appropriate local and
CI checks; hardware and VM validation for affected paths; and explicit live-deployment
review. Do not ship a positive privacy claim based only on simulated tests. Documentation
and accessible setup can progress while CPU-sensitive experiments run; compilation and
load tests wait until those measurements finish.

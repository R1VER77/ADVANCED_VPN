# Hardware emulation and searchable cloud installation

Owner decisions, 18 November 2026: publish the validated checkpoint and this plan,
then implement hardware simulation first, followed by an installer search spanning
the whole OpenTofu registry. Strict hardware policy blocks a required interface that
violates the full-stack PQ/SafeCurves target. Simulation does not establish physical
device support. This extends, rather than replaces,
[the main implementation plan](IMPLEMENTATION_PLAN_20261117.md).

## 1. Starting state and publication

GitHub `main` was checked at hardware-signed `5d69623697524796b105dd5f24f0644339a05652`.
Its latest verification, [run 44273400186](https://github.com/R1VER77/ADVANCED_VPN/actions/runs/44273400186),
failed. Local fixes address desktop Rust formatting and a status-mtime fixture;
the new revision must pass its own CI. No open pull requests were present.

The reviewed, locally validated checkpoint includes:

- A glibc-baseline gate and baseline-built GNU core; native package lifecycle and
  caller-bound bus checks on Debian 12/13, Ubuntu 22.04/24.04, Fedora 45 and Rocky 10.3.
- RPM downgrade ordering, exact scriptlet inspection and SELinux label restoration
  before application-slot activation. Fedora/Rocky remained enforcing.
- A hardened apt repository verifier, authenticated apt download and wrong-key/
  tampered-package controls using destroyed disposable software test keys.
- Actual native WebKit rendering of the GUI's unavailable-controller state and narrow
  layout. The host-built debug GUI is not a portable packaged release.
- A review of the GLM5.3 research folder and GitHub proposals, preserving their inputs,
  correcting unsupported claims and adding research qualification gates.

The [progress tracker](IMPLEMENTATION_PROGRESS_20261117.md) and
[support matrix](SUPPORT_MATRIX.md) identify exact evidence and limits. Candidate
package tests are not final release provenance, full enrolled-tunnel qualification,
physical power-loss tests or independent review.

Publication procedure:

1. Save this plan, link it from the roadmap and README, and retain every failed trial.
2. Inspect the full pending diff, validate affected code, check documentation/evidence
   consistency and exclude private logs, credentials, test secret keys and build caches.
3. Create one hardware-signed checkpoint containing the validated fixes, public
   evidence, research corrections and this plan. This immediate publication follows
   the owner's later instruction to push now, superseding the earlier instruction
   to withhold this checkpoint until every roadmap gate passed.
4. Verify the actual commit signature, refresh remote `main`, preserve concurrent
   signed changes, and push without force. At inspection `main` was unprotected;
   recheck before publication and honor any protections added subsequently.
5. Verify GitHub's published SHA/signature and follow the new verification run. Fix
   material failures with signed corrections. Never manufacture a green result by
   removing a security check or substituting an older successful run.
6. Continue independent implementation while a native authentication prompt waits.
   Signing/SSH PINs and passphrases stay in the local terminal; no unsigned fallback
   or replacement of the configured hardware signing/deployment keys.

## 2. Hardware laboratory and strict eligibility

### What virtual testing establishes

Exercise the shipping setup, key-generation, sealing, enrollment and verification
code against actual software authenticators. Do not mock successful signatures,
derived secrets, encryption or enrollment verification in end-to-end cases. Transport
adapters and synthetic faults are permitted and must be identified in evidence.

[Qubes Split GPG](https://doc.qubes-os.org/en/latest/user/security-in-qubes/split-gpg-2.html)
isolates key operations behind an RPC boundary; it does not emulate a token's firmware,
USB controller or physical security. Use its separation principle for test-process
isolation, without adding a new production GPG-to-FIDO substitution.

| Backend | Intended evidence | Boundary |
|---|---|---|
| Nitrokey 3 upstream USB/IP runner | Run the actual NK3 application stack, attach its virtual CTAPHID interface inside a disposable Linux guest, control presence and persistent test storage. | No secure-element, physical entropy, actual USB/NFC electrical or production-unit assurance. |
| Trezor firmware emulator and its FIDO transport | Run production client/protocol code against the upstream firmware snapshot; use upstream debug controls for simulated device approval. | Record emulated model/build; emulator transport and display do not qualify a physical model. |
| Ledger Security Key with Speculos | Run the actual app with its supported CTAP/U2F transport and upstream test harness. Start with Nano S Plus app builds; add other app targets only with separate results. | App tests do not emulate every OS, firmware-update, secure-element or wallet behavior. |
| Generic CanoKey virtual card | Independently test CTAPHID, Ed25519/hmac-secret and, separately, OpenPGP boundaries through real guest USB plumbing. | A CanoKey pass is not a YubiKey, Nitrokey, Trezor or Ledger firmware pass. |
| Capability/fault fixtures | Deterministic unsupported features, vendor-tool responses, malformed frames and multiple-device ambiguity. | Synthetic outcomes, especially YubiKey-specific configuration cases, remain labelled synthetic. |

The relevant upstream entrypoints were verified:

- [Nitrokey USB/IP runner](https://github.com/Nitrokey/nitrokey-3-firmware/tree/e16626ff48b31a412585116a13107a90e601e68d/runners/usbip)
  includes NK3 apps, CTAPHID and controlled presence. Use signal/reject controls rather
  than treating its default accept-all presence as a meaningful consent test.
- [Trezor firmware tests](https://github.com/trezor/trezor-firmware/blob/main/tests/README.md)
  and `test_emu_fido2` provide the vendor FIDO test path.
- [Ledger Security Key tests](https://github.com/LedgerHQ/app-security-key/blob/8918841873b8690df6a8586a2388c25fd12d477e/tests/README.md)
  describe Speculos FIDO transport and its upstream test patches. Pin the app,
  compatible SDK, emulator, container digests and dependency locks together.
- [QEMU CanoKey documentation](https://www.qemu.org/docs/master/system/devices/canokey.html)
  documents guest USB, test storage and its one-card-per-QEMU limitation. The installed
  QEMU 10.0.13 does not currently expose CanoKey, so build an isolated compatible
  CanoKey-enabled QEMU; do not replace the host's packaged QEMU.

Freeze full source/submodule commits, binary hashes, licenses and build dependencies
in a laboratory manifest before executing each backend. Prefer the matching upstream
CI build configuration; unresolved version/transport compatibility is an explicit
blocked backend, not an invitation to fake a successful response. YubiKey-specific
firmware emulation is not assumed available; retain the existing physical 5.2.7 result
and use capability/configuration fixtures for additional software paths.

### Isolation and interfaces

- Add a laboratory runner with backend, scenario, OS image and fresh output directory
  inputs. It owns emulator processes, virtual state, guest disks and cleanup receipts.
  Production GUI/CLI requests cannot select a test backend or arbitrary device socket.
- Refactor device discovery behind a private injectable test seam where emulator
  transports require it. Keep Fido2Client, Fido2Server, assertion verification, hybrid
  KEM, ML-DSA and envelope encryption unchanged. Actual virtual USB uses the normal
  production discovery path without injection.
- Load USB/IP modules and change access rules only inside disposable guests. No real
  USB passthrough, host udev edits, production vaults, wallet material or firmware
  flashing. Emulator storage contains disposable software secrets and is mode 0600.
- Keep one CanoKey per QEMU process. Test multiple-device ambiguity through independent
  emulator endpoints/fixtures, labelled by transport; never claim the single-card
  QEMU backend validated a multi-card USB topology.
- Emit a bounded public evidence record containing backend/source hashes, application
  revision, OS, scenario, result, actual COSE/PIN-UV algorithms and limitations.
  Physical, firmware-emulated, protocol-emulated and synthetic evidence are separate
  dimensions; none automatically promotes another.

### Scenarios and acceptance

Run credential creation; required presence/verification; one- and two-salt hmac-secret;
same credential/salt stability and independent credential/salt separation; real
seal/unseal and tamper refusal; fresh assertions and operator dual-signature
verification; and actual client/relay/exit key generation, sealing and public requests.
Record which keys are generated in application software and sealed by the token;
do not claim existing tokens generate ML-KEM or ML-DSA internally.

Negative cases include absent hmac-secret/CTAP2, unsupported algorithms, U2F-only,
wrong credential/RP/origin/challenge, missing presence/verification, invalid signatures,
nonzero counter rollback/replay and legitimate zero-counter behavior, wrong salt/key,
PIN rejection/blocking, cancellation, timeout, removal, reconnect, backend death and
ambiguous devices. Verify failure leaves no half-created enrollment, unrelated device
change, orphan prompt, secret-bearing diagnostic or automatic weaker fallback.

Test actual guest access denial and restoration, including after reconnect; vendor
descriptor/configuration fixtures only establish matching/decision logic. Do not make
hidraw nodes world-writable or grant wallet interfaces to repair FIDO access.

Mutation controls remove signature verification, permit an unsupported algorithm,
accept absent user verification and ignore a failed repair recheck; the corresponding
tests must fail. Pin upstream FIDO test dependencies separately from the application's
dependency lock when their versions conflict.

### Strict policy decision

The owner selected **block under strict policy**. Report credential-signature
algorithm separately from PIN/UV key agreement. Current CTAP PIN/UV protocols 1/2 use
P-256; an Ed25519 credential does not change that. See [the inventory](PQ_INVENTORY.md).

New setup and connection/enrollment under the strict policy cannot complete when
the required path uses P-256, lacks the required PQ property, or cannot establish its
actual algorithms. Existing standard FIDO devices can pass functional compatibility
tests and still be ineligible for strict setup. No compatibility opt-in or software
test-token fallback is introduced by this work.

When creating a new signing credential on a capable device, request Ed25519/EdDSA
explicitly and verify the returned COSE key; do not offer ES256 as a fallback or
relabel an existing ES256 credential. Absence of an advertised algorithm list is
unknown evidence, not proof of Ed25519 support or non-support. Any credential-creation
probe requires the ordinary reviewed creation operation. OpenPGP, SSH and FIDO
applications have distinct capabilities: an OpenPGP Curve25519 option or Ed25519 SSH
credential cannot switch CTAP's PIN/hmac-secret exchange to X25519. The connected
Nitrokey's read-only GetInfo on 18 November reported hmac-secret and PIN/UV protocols
2/1 but no explicit algorithm list; no credential or PIN was changed for that check.

Preserve all existing credentials and signed profiles. Do not rewrite authenticated
policy fields or silently grandfather an old profile into strict qualification;
incompatible profiles require the versioned operator migration. An upgrade does not
tear down an existing tunnel or clear its guard automatically. Present its measured
network protection separately from its unmet crypto-policy requirement, and block
new incompatible strict operations. A future compliant hardware protocol needs its
own implementation and independent qualification; an idealized simulator cannot
close that production gate.

## 3. Whole-registry search and guided OpenTofu installation

### Registry search

The owner selected search across the **whole OpenTofu provider registry**, including
entries without reviewed VPN recipes. Registry inclusion does not establish that a
provider offers VM compute, permits VPN exits, or supports this VPN.

Build a compact local index from the complete provider tree of a pinned
[OpenTofu registry snapshot](https://github.com/opentofu/registry), retaining canonical
namespace/name identifiers and upstream blacklisted versions. Fetching the tree does
not require downloading every provider's historical binary/version metadata. Refuse
truncated inventories. Keep the upstream commit and generated-index hash in evidence.
Ship the index through the authenticated application release; updates are separately
reviewed bundles, never arbitrary plugin installation during search.

Add a keyboard-accessible provider search to **Create my network**. Search names,
aliases and canonical provider IDs locally, with no query telemetry or per-keystroke
network calls. Rank reviewed VPN candidates first, but search all entries. Show filters
for all entries, reviewed recipes, unreviewed candidates and unavailable/non-compute
providers; expose an always-visible bring-your-own SSH path.

Each result distinguishes listing, recipe availability, documented capabilities,
software/VM test evidence and authorized live evidence. Unreviewed/non-compute entries
remain viewable with a reason and official documentation link, but cannot launch
provisioning. No LLM or keyword classifier may promote one to runnable status.

### Eligibility and rollout

A reviewed recipe must supply a compatible Linux VM/image/architecture, root/sudo,
TUN, nftables, required namespace/seccomp/systemd support, role-specific reachable
ports and underlay MTU, adequate measured resources, public address/routing and
explicit egress/terms information. Evaluate entry, middle and exit separately.
Unknown allowance or acceptable-use terms remain unknown, not a free/unlimited claim.
Container-only/serverless offerings without the required host control are not usable
through that recipe. Run the shipping host preflight on the actual resulting VM.

Recipe order: generic SSH; existing AWS/OCI parity; GCP/Azure; then Hetzner,
DigitalOcean, Vultr, Akamai/Linode, Scaleway, OVHcloud and UpCloud. Other cataloged
hosts remain searchable and can use compatible pre-existing SSH servers until their
own recipe qualifies. Start automated Linux recipes on a validated x86_64 image;
ARM selection remains blocked until native ARM qualification passes.

Existing AWS constraints remain in force: selected Region only, eligibility/paid-plan
and spend checks, no assumed free instances/addresses/egress and no cross-Region
deployment. Provider implementation must load the applicable current AWS guidance.
No new paid infrastructure is authorized for this engineering work.

### Interfaces and execution boundary

Extend the shared controller/CLI contract, not a separate GUI-only setup engine:

- Add bounded, read-only `SearchProviders(query, cursor, filter)` and its explicit
  Tauri capability. Maximum 50 results, 256 UTF-8 query bytes; opaque cursor bound to
  the index digest. Return public metadata only and keep existing response bounds.
- Extend setup snapshots with the selected provider/recipe, applicability/blocking
  reasons and authoritative authentication, preview, provisioning, bootstrap and
  verification steps. Count checked steps, not invented time percentages.
- Add typed cloud discover/preview/apply/reconcile/destroy actions through existing
  caller-bound plans and operation status/cancellation. Requests name reviewed IDs
  and typed inputs, never raw HCL, plugin URLs, arbitrary commands or root file paths.
- Keep compatibility with existing CLI entrypoints and cloud inventory. Existing
  resources are discovered/imported only through an explicit ownership review; do
  not adopt or destroy unrelated resources automatically.

Use pinned **OpenTofu 1.13.9**, verified against its official signed release checksums
and provenance; the [release](https://github.com/opentofu/opentofu/releases/tag/v1.13.9)
was current when inspected. The Linux amd64 ZIP SHA-256 advertised by the release is
`bc44eb6b06446ba83bd4072114891987f590f66cca712737a7f1147c50c539ce`.
Pin every recipe/module/provider and use a read-only installation mirror/lockfile.
Registry search never executes provider binaries. Provider versions in the reviewed
blacklist are refused, even when otherwise pinned.

Run OpenTofu as a dedicated unprivileged, operation-scoped worker. The root controller
owns authorization and narrowly scoped host changes; the WebView/model receives only
sanitized summaries. Use native provider login flows/credential adapters; never ask
the WebView or assistant to handle provider passwords, tokens or hardware PINs.
Isolate credentials to the approved provider/project/operation and clear inherited
OpenTofu CLI overrides, logging, plugin paths and unrelated cloud credentials.

The operation sequence is fixed:

```text
discover → verify prerequisites/authentication → preview saved plan
→ trusted review/authorization → apply those exact saved bytes
→ reconcile → bootstrap → verify VPN/guard → offer owned-resource teardown
```

The review binds caller, provider/project/region, recipe/modules/plugins, public
inputs, encrypted plan bytes, state lineage/serial, generation and expiry. Changes
invalidate authorization. A replan requires another review. Show resources, reachable
ports, expected/unknown costs, resource ownership and cleanup before creation.
The saved-plan flow follows [OpenTofu's two-step interface](https://opentofu.org/docs/cli/commands/plan/):

```text
tofu init -input=false -lockfile=readonly
tofu plan -input=false -out=plan.bin
# Parse private plan output into a bounded public review, then authorize its digest.
tofu apply -input=false plan.bin
```

The runner invokes fixed argv arrays, not an interpolated shell. Plan JSON stays
private and never passes wholesale to the GUI/model. Reject unexpected resource
types, destructive changes to unowned resources, plaintext private-key outputs and
unauthorized provisioners. Bootstrap transports public configuration and verified
package references; node private keys are generated on their destination. Verify SSH
host identity before bootstrap rather than silently trusting its first answer.

### Encrypted state and recovery

Enforce [OpenTofu state/plan encryption](https://opentofu.org/docs/language/state/encryption/)
with its external key-provider protocol and an operation-scoped local hardware-backed
key agent. Implement the documented header/input/output exchange exactly. Bind the
key lease to the provisioning workspace/job, use purpose-separated keys, and reject
requests for unrelated jobs. Keys travel only over private local IPC to the helper
and OpenTofu; they never enter HCL, argv, logs, GUI or model context. A pinned provider
plugin remains trusted executable code; at-rest encryption does not protect plaintext
from a malicious authorized plugin.

Keep state, plans, backups and journals encrypted, with 0700 directories and 0600
files; temporary decrypted summaries remain in bounded memory/private RAM storage.
No plaintext fallback or environment override may disable encryption. Keep a durable
generation/lineage check: encryption alone does not prevent replay of old state/plans.
Exercise key-loss/recovery before live deployment. Preserve an encrypted backup and
clearly report that lost hardware/recovery material can make state unrecoverable.

Persist operation intent before resource creation. Cancellation/timeout/GUI death
must reconcile actual cloud state and report uncertain/remaining resources; it must
not pretend that cancellation destroyed them. Teardown gets its own exact reviewed
destroy plan and may affect only resources with verified operation ownership. Failed
or ambiguous discovery produces manual recovery guidance rather than broad deletion.

## 4. Validation and delivery gates

1. **Publication:** authentic local/remote commit signatures, matching remote SHA and
   green checks for the new revision. Commit/push authentication cannot use virtual
   signing keys. Do not publish lab secrets or claim candidate hashes are a final
   release attestation.
2. **Hardware software:** positive and adversarial cases exercise production crypto;
   mutant checks fail; backend crashes/removal/cancellation retain safe state. Run
   vendor suites in isolated dependency environments, then application integration.
3. **Linux:** run a minimal USB/IP setup/permission round trip on every push where
   the runner supports it, with explicit environment skips. Run the full guest matrix
   on the existing local KVM resources before a release: Debian 12/13, Ubuntu
   22.04/24.04, Fedora 45 and Rocky 10.3. Never equate an unavailable kernel/emulator
   job with a pass. Include enforcing SELinux and actual native authentication-agent
   interaction, not only the existing authorization fixture.
4. **Policy:** Ed25519 plus P-256 PIN exchange still blocks strict setup; unknown or
   unsupported algorithms block; simulated future capabilities cannot establish
   production PQ hardware support. Existing keys/profiles/guards survive refusal.
5. **Provider search:** complete snapshot inventory, deterministic aliases/ranking,
   pagination, keyboard/screen-reader/narrow layout, offline search, stale cursor,
   malicious metadata and absence of plugin execution/secret fields. Every entry's
   runnable status must agree between CLI, GUI and controller.
6. **OpenTofu:** use `mock_provider` and plan-only test runs for credential-free CI;
   `tofu test` is not inherently harmless and can create real infrastructure. Require
   no live credentials/network in mock tests. Test encrypted save/reopen, wrong key,
   tampering, replay, stale/changing plans, unauthorized job/key access, partial
   creation, lost responses, cancellation, restart, ownership-safe destroy and secret
   canaries in all public outputs. Use a local disposable VM/SSH target for real
   bootstrap/protection checks. Live provider evidence requires separately authorized
   resources and is not inferred from mocks.
7. **Physical/user:** retain the four units' earlier physical setup results, then
   qualify remaining real-device recovery cases, native prompts and five owner-arranged
   non-admin usability sessions. NFC, electrical behavior, real firmware/security
   boundaries and physical 4 GB assistant performance remain real-device gates.

Freeze independent lab state per run, preserve rejected evidence and stop only owned
processes. Preflight storage and build prerequisites. No emulation, package builds,
fuzzing, training or hardware administration may overlap traffic-analysis collection.
The failed `replication-20261117d` stays rejected. No collection is currently active.

## 5. Resume the main VPN roadmap

Execute in this order after the signed checkpoint. The new work is integrated into
the main roadmap rather than allowed to substitute for missing protection evidence.

| Workstream | What remains |
|---|---|
| 1 CI/provenance | Green checks for the checkpoint; reproducible release artifacts, authenticated provenance and production repository-key/publication qualification. |
| 4 Hardware/recovery, first | The virtual laboratory and strict eligibility above; complete VM interruption/full-storage/damaged-runtime/profile/restart/power-cut fault matrix with external packet witnesses; remaining physical device cases. VM power cuts are labelled VM tests. |
| 5–6 GUI/provisioning, next | Whole-registry search, reviewed recipe rollout, encrypted OpenTofu jobs, full create/join branches, verified enrollment/connect/resume and native prompts; five real participant sessions. |
| 2 Traffic analysis, quiet windows | Re-smoke the dedicated recorder CPU/64 MiB buffers, freeze a new 720-attempt run, analyze all attempts/grouped holdouts and permutations, correct leakage and freshly replicate across three days, two networks and two physical clients. |
| 3 Distribution | Production signing/provenance, RPM repository metadata, cross-release migrations and final packages rebuilt from one source revision. Candidate lifecycle passes do not close these gates. |
| 6 Optional local assistant | Reviewed documentation updater and bounded action proposals; task-tuned FunctionGemma evaluation/training after the deterministic wizard works; held-out/adversarial tests and actual 4 GB device measurements. No authenticated website automation or shell authority for the model. |
| 7 Assurance/platforms | Signed DNS policy and owned-recursive alternative without silent fallback; formal models/broken variants, parser fuzzing, secret lifetime review, fail-closed mesh/spent-state reconciliation, naming/path migrations, then native ARM Linux → Android → macOS → Windows → iOS/iPadOS, each with its own protection tests. |
| Research/review | Preserve the GLM5.3/PAD-exposure research gates, reconcile claims with evidence and qualify any proposed incorporation separately. Obtain an actual independent review/retest; no funding is assumed necessary, but internal/model review is not independent review. |

Update progress, support claims and evidence at each completed gate. Source
implementation, simulated tests, physical qualification and independent review remain
separate. Do not mark the seven-stage roadmap complete while external evidence,
compliant hardware or a native platform gate is still missing.

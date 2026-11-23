# Main implementation progress

Owner direction originally requested tasks 1–7 before one final implementation commit.
On 18 November the owner explicitly requested immediate GitHub publication of the
validated checkpoint and a saved hardware-emulation/cloud-installer plan, then continued
implementation. Publish that checkpoint now; preserve all existing signed history.
Pad-exposure qualification research follows the main implementation sequence; runtime
incorporation depends on its evidence gates. The controlling specification is
[the saved plan](IMPLEMENTATION_PLAN_20261117.md). The initial implementation is
published in signed commit `bad0a21`. Preserve it and the subsequent signed R&D
policy commits through `5d69623`; this checkpoint records the subsequent validated
review corrections and the newly saved extension. Publication is verified against
the resulting signed commit and GitHub checks, not inferred from this document.

The [new extension](HARDWARE_EMULATION_AND_CLOUD_INSTALLER_PLAN_20261118.md) records
the chosen order (hardware simulation first), whole-registry search with reviewed
VPN provisioning recipes, and refusal under strict hardware policy. Those new
capabilities are planned; saving/publishing their plan is not implementation.

The checkpoint is now published as hardware-signed `15e79759b0d182d7e6eec1ea83f093ac7f1c36f6`;
both local verification and GitHub report a valid signature, and remote `main` matched.
[Verification run 44421603036](https://github.com/R1VER77/CYPHERPUNK_VPN/actions/runs/44421603036)
passed all four jobs (Linux desktop, protocol proof, formal models and Python 3.10).
The owner's subsequent refinement defers
repeat baseline/emulator work for **all four commissioned physical units**. The next
hardware work determines VPN usability for the additional devices named in the
research, using [the candidate inventory](DEVICE_COMPATIBILITY_VALIDATION.md).
No Nitrokey emulator build was launched.

Signed licensing commit `d26c355` appeared in the shared owner workspace during this
work. Preserve it and the published documentation commit `66c26f3`. New component
metadata follows AGPL-3.0-or-later and the authoritative repository LICENSE. The
licensing commit included the in-progress workspace-member declarations; its new
workspace dependencies were included by `bad0a21`. All remaining gates below
retain their actual evidence status.

Completion means the acceptance gate passed. Source implementation, simulation,
physical validation and independent review remain distinct.

Current installation scope: candidate B passed the full scoped native-package
lifecycle on Debian 12/13 and Ubuntu 22.04/24.04. Fedora/Rocky RPM trials exposed
inherited SELinux file labels at authorized controller startup. The correction
restores host file contexts on the prepared slot before activation; fresh Fedora/Rocky
trials now pass with enforcing mode retained. Cloud creation
still has two dedicated provider paths plus generic SSH; thousands of integrations
and a trained local model are not implemented. See the [support matrix](SUPPORT_MATRIX.md).

| Task | Current implementation and evidence | Remaining gates |
|---|---|---|
| 1 CI/provenance | Baseline `43996ad` passed three jobs; verification/release share static bootstrap builds; new locked native desktop CI job; build dependency advisory GHSA-fc5q-39xc-vjpf addressed via vendored picomatch extglob guard | Final CI and provenance qualification |
| 2 Traffic analysis | Metadata recorder, observation validity, counterbalanced runner and grouped analysis; three-arm smoke passed | Fresh controlled collection, analysis/correction and cross-environment replication |
| 3 Installation | Portable candidate B passed native lifecycle/live bus trials on Debian 12/13 and Ubuntu 22.04/24.04; real apt controls passed. Corrected RPM candidate E passed the complete scoped lifecycle/live bus trial on Fedora 45/Rocky 10.3 with SELinux enforcing | Hardware repository key, RPM repository metadata, provenance/publication and full release/protection qualification |
| 4 Recovery/hardware | Static guard missing-runtime and missing-guard reboot trial passed; externally witnessed IPv4/IPv6 output/forwarding checks; additional Solo PC firmware key/signing/enrollment operations passed | Full installation fault matrix; remaining additional-device operations and targeted physical differences, without repeating the commissioned four-unit baseline |
| 5 GUI | Prototype preserved/imported; production/demo separation, Vue/Tauri builds, native broker, caller-bound plans, native approval details, public request export; real system-bus boundary checks passed with disposable authorization fixture | Native authentication agent/WebKit interaction, complete owner/provider flow and five participants |
| 6 Provisioning/assistant | Existing provider tooling/design retained | Deterministic expanded adapters, encrypted plans/state, documentation updates, training and physical evaluation |
| 7 Assurance/platforms | Existing formal baseline; initial `cypherpunk` command aliases added | Selected DNS, added formal/fuzz/secret work, mesh reconciliation, migration, native platform qualification and independent review |

## Collection state

**No traffic collection is active.** The 720-attempt run in the private frozen
`replication-20261117d` snapshot stopped with status `failed`. Manifest SHA-256:
`26a7527ca2b42b29f51f793a80c03fe3f042e1807b7198e2439300b954804865`.
The first three arms completed 120 attempts. The fourth (`r2-relay30`) logged 40
attempts but reported 3,435 capture drops. Heartbeat gaps were below 0.517 seconds;
telemetry also recorded battery operation. Preserve this rejected run. Do not reuse,
overwrite or analyze it as a valid complete replication.

The preceding two-site libpcap smoke passed all three arms with zero capture drops,
no unexpected outgoing metadata and bracketed status observations. Five loads
succeeded; one 5 ms timeout remains in the data. The interface-boundary smoke excluded
3,400 unrelated loopback packets and retained its selected-interface frame. These
checks qualify the collector behavior, not traffic-analysis resistance.

The next source revision gives recording CPU 4 and 64 MiB rings per direction while
client/server retain CPUs 0–1/2–3. Power conditions are sampled before/during/after
arms and analysis rejects battery/build interference. Re-smoke, finish heavy builds
and VMs, recover sufficient free storage, then freeze a new `replication-20261117e`.
Read its actual RUN.json before further heavy work. No builds, training or hardware
administration may overlap collection. No new paid resources are authorized.

## Native installation and recovery

- Native preflight and Python share one policy and 21 parity fixtures. Native
  preflight, boot guard and controller built for musl; ELF checks reject interpreter,
  dynamic dependency and writable/executable segment counterexamples. Native unit
  tests and Clippy pass. Actual host/distribution parity remains to be qualified.
- Application slots have content/mode/link manifests, fsync, exclusive locking,
  durable journal and one atomic current pointer. Old slots remain available.
  Rollback changes application code only, never security counters, keys or profiles.
- Legacy adoption uses Linux atomic directory/link exchanges with a recovery journal
  and retained original inodes. It requires explicit stopped-installation approval.
- A verified repair can replace damaged selected code. It records that damaged slot
  as unusable and never selects it on rollback. A failed repair leaves no selected
  application; independent protection remains outside that transaction.
- Stable system artifacts have ownership receipts and durable replacement intent,
  permitting recovery across a cut between artifact/receipt replacement. Modified
  policy and foreign artifacts are refused. AppArmor installation preserves unrelated
  administrator rules around an exactly recognized managed block.
- Removal is serialized and refuses persistent deny intent, guard dependencies,
  active/enabled services, firewall tables, owned interfaces/namespaces and running
  code. It includes broker, D-Bus, Polkit and independent guard artifacts. User removal
  cleans retained legacy application files while preserving separate private state.
- Debian/RPM packaging uses a pinned offline runtime, fixed aliases under `/usr/bin`
  and lifecycle scripts without activation. Unmanaged installs and foreign commands
  require explicit handling. The Debian candidate is unsigned and unqualified;
  RPM build tooling and real distribution tests remain pending. A successful archive
  build does not qualify package installation or a signed repository.

The latest static-guard VM trial, `native-bootguard-20261117c`, passed with binary,
policy, harness and base-image input hashes. Its positive control observed 82 marker
frames. With no application runtime, the network was ready, the independent guard
was active and no marker escaped. With that guard binary removed, all five configured
manager units were inactive and no marker escaped. This is local IPv4 VM evidence,
not physical power loss or qualification of all network managers/initramfs.

The forwarding harness now witnesses packets on the external namespace, with permanent
neighbors so ND/ARP refresh cannot mask a leak. It requires positive controls before
and after protection and a broken variant without the forward chain to leak in both
families. Production whole-device forwarding is explicitly denied; hotspot service is
not implemented. Earlier failed harness trials remain preserved.

Native package trial `native-package-debian13-20261117a` passed install, replacement,
damaged-code repair and reboot without activation, and refused armed removal. The
harness then incorrectly treated the expected kernel EPERM on its negative probe as
a test failure. Its result remains failed. Subsequent failed trials exposed a bootstrap
timeout and an unmounted post-reboot test payload; preserve them. The corrected 18
November trial passed its scoped lifecycle and real bus checks, as recorded below.
A private-state marker is a retention fixture,
not a complete qualification of real enrolled monotonic counters.

## Desktop/controller boundary

- Public transport has six bounded methods on the fixed system bus. Sender name,
  bus ID and UID come from the driver. The root worker accepts inherited pipes only.
  Its paths are fixed to the broker's physical application slot; environment and raw
  diagnostics do not pass to the WebView. Hardware probing drops to the caller UID.
- Plans bind caller, input digest, checked device/profile inputs, generation and
  monotonic expiry; they are consumed once and rechecked under the CLI mutation lock.
  The trusted native Polkit prompt obtains its summary, effects and digest from the
  stored plan. It rejects markup/control/expansion injection. Cancellation stays owned
  and does not need another administrator prompt. Authentication waits release the
  worker mutex. Refusal preserves the live caller connection and owned operation.
- Native/device PIN prompts remain outside the WebView. Cancellation targets only
  the operation's prompt, never resets a device or clears protection. These paths
  still require native integration and physical testing.
- Status requires a fresh private inode, controller/child start identities, explicit
  guard/scope and 3/3/15-second evidence. Contradictory or stopped-controller status
  remains unknown. A stopped supervisor's kernel rules are not yet independently
  verified by the desktop status path.
- Production/demo web builds pass; native checking and Clippy pass. Production has
  explicit ACL/CSP and no automatic mock fallback. Map assets are offline; existing
  profiles lack signed coordinates, so production does not invent locations.
- Join setup exports only validated projected public request fields and offers
  recovery when vault creation succeeded before device-key creation. Unknown future
  fields cannot enter that public export. Native file export and a full owner/provider
  branch remain outstanding; the current public request can be selected/copied.
- Production and dev npm audit report zero findings. Build-only dependency advisory
  GHSA-fc5q-39xc-vjpf was mitigated via a locally vendored picomatch 4.0.7 fork in
  `vendor/picomatch/` with an extglob-repetition guard (`lib/extglob-guard.js`,
  `CYPHERPUNK_GUARD.md`), verified via `scripts/check-glob-guard.mjs` against both the
  live override and a disposable guard-removed mutant that times out. `npm audit --audit-level=high`
  reports 0 vulnerabilities. The imported README and controller contract describe the actual source.

## Validation record and next work

The updated regression suite passed all **705 tests, 24 skipped**. Rust workspace
crates (`cypherpunk-preflight`, `cypherpunk-bootguard`, `cypherpunk-controller`) passed
all unit tests and strict Clippy without warnings. Native desktop production and demo
builds succeed cleanly. These are mock/software fixture tests unless explicitly
identified as kernel/VM evidence. The final broad regression and Python 3.10 checks
include the latest changes.

Continue the native package lifecycle and distro matrix, then real broker authorization
and native GUI flows. Complete provider/owner onboarding and the remaining stages in
the controlling plan. Physical device sessions, five real people, cross-network/client
traffic qualification, hardware OpenPGP provisioning and independent review require
actual evidence. Do not mark them complete from source, simulation or model review.

## 18 November research/proposal integration

Reviewed all four GLM5.3 validation archives, the PDF, raw models/benchmarks, Task 3
patch and current signed GitHub proposal. [Review](RESEARCH_REVIEW_20261118.md) and
[scope counterchecks](evidence/RESEARCH_COUNTERCHECKS_20261118.json) record concrete
limitations and incorporation decisions. The roadmap now includes the R&D proof and
measurement gates without changing the owner's full-stack hybrid-PQ/SafeCurves goals.

The Task 3 patch is integrated locally with corrections: the proposed RPM `$2`
version guard was replaced by installed-database/native EVR checking; repository
verification now requires signed index coverage, safe anchored paths, immutable
signature snapshots, freshness, signed key classification and primary/subkey binding.
All 19 focused repository tests passed on the development interpreter and Python 3.10.
Nine packaging tests ran with one native-RPM
compatibility skip on this host. Real RPM transaction/distro gates remain open.
The package VM payload must be remounted after reboot; trial C's missing test client
was a harness fault, and its failed evidence is preserved. New guest trials follow.

The 18 November regression passed: **705 tests, 24 skips**. The local glob guard and
full npm audit also passed (zero findings). GitHub run `44273400186` on `5d69623`
failed desktop Rust formatting and a test fixture whose captured clock preceded its
file mtime; those source corrections are now local. The timestamp fixture sets explicit
inode times and retains the production refusal of future-dated status. Final CI on the
new signed revision is still required.

The new Debian 13 package/real-bus trial passed all its scoped phases: install, retained
slot replacement, damaged-code repair, reboot without activation, twelve native RPM
EVR comparisons, denied access and caller-bound live D-Bus operations, armed-removal
refusal with zero externally observed probe markers, explicit recovered removal, and
post-removal reboot with a working positive control. See
[evidence](evidence/NATIVE_PACKAGE_DEBIAN13_20261118.json). It uses a synthetic private
retention marker and a temporary Polkit authorization rule, so it does not qualify real
enrollment, a native authentication agent, physical power loss or an RPM distribution.

The same candidate A was correctly refused by Debian 12: its GNU core requires glibc
2.38 while its package metadata declared 2.35. Preserve the failed trial. The package
builder now checks staged ELF requirements against the shared release baseline before
emitting an archive; a negative regression refuses a deliberately newer-ABI fixture.
A fresh GNU core build from the signed `5d69623` source passed in an Ubuntu 22.04
build image, with no network or host credentials mounted during compilation. All five
GNU binaries require glibc 2.34; the selected release floor remains 2.35. The
[build record](evidence/NATIVE_CORE_BASELINE_20261118.json) identifies inputs and hashes.
The rebuilt core also passed the actual isolated
[protocol/rejection lab](evidence/NATIVE_CORE_PROTOCOL_20261118.json), including
replay/tamper/revocation refusal, relay-loss fail-closed behavior and reconnection.
This is a local namespace result, without WAN or hardware qualification.
Candidate A's Debian 13 pass does not qualify it for older distributions. Rebuilt
candidate B (`d0973be5…`) is running fresh trials on all four declared Debian/Ubuntu
distributions; Debian 12 has passed. Consult the per-trial RESULT.json files.

The real apt client passed authenticated update/download and both wrong-key and
tampered-archive negative controls in networkless containers. The retained
[record](evidence/APT_CLIENT_20261118.json) is download-only evidence with an ephemeral
software test key. Its private material was destroyed. This neither provisions the
production hardware key nor fixes candidate A's ABI failure.

The review also covers both whitepaper content drafts, including actual DLEQ batch
binding, accountability versus sender tracing, event substitution, jamming isolation,
fallback policy and pad custody. Original drafts remain unchanged. See the review's
additional-drafts section and the hashed input inventory.

The unsigned RPM archive now builds as an ordinary user in an isolated Ubuntu
container. Inspection verifies exact generated scriptlets, root metadata and only
declared payload/alias paths. The first inspected archive unexpectedly added global
build-ID links; `_build_id_links none` removes them in the corrected candidate. Real
RPM empty-package transactions also passed eight cases, including three downgrade
refusals (version, release and epoch). These are archive and guard evidence, separate
from the still-open Fedora/Rocky VPN installation matrix.

CI now includes native package ABI checking and real apt positive/negative download
controls with a disposable software key. Local YAML/shell parsing passed. The new
workflow has not run on GitHub yet; the signed-publication gate remains pending.

Native desktop rendering now has an actual repeatable WebKit test, separate from
the earlier build checks. It passed the embedded production frontend's absent-controller
unknown state and 420-pixel layout on an isolated X display with software compositing.
The [record](evidence/NATIVE_GUI_20261118.json) and screenshots identify its exact debug
binary. No mocked controller, privileged action, PIN field or device operation was
used. Readiness now checks the DOM and compositor paint rather than capturing an early
white window. This does not qualify a packaged app, native authentication agent or
owner/provider/participant flow. The host-built GUI requires glibc 2.39 and therefore
cannot be promoted as an older-distribution GUI artifact; build that release on its
declared baseline and test native dependencies separately. CI includes the smoke.

Candidate B passed full native package trials on Debian 12 and 13. Ubuntu 22.04
passed install/replace/repair/reboot but its first live-bus trial failed because the
temporary JavaScript authorization rule is unsupported by its legacy Polkit. That
failed record remains. The corrected harness checks the actual Polkit version and
uses a disposable `.pkla` fixture for pre-0.106, retaining denial before the fixture
and never installing that grant in production. Fresh Ubuntu 22.04/24.04 trials are
ran subsequently. The [final four-distribution matrix](evidence/NATIVE_PACKAGE_MATRIX_20261118.json)
now passes, including Ubuntu 22.04's legacy Polkit fixture and Ubuntu 24.04's
networkless dpkg lifecycle phases. Its earlier apt timeout, local-file handling and
missing-PATH harness failures remain preserved. Both Python 3.10 and the development
interpreter passed the full **705-test suite with 24 skips**. The exact ABI-correct
candidate B also passed the real apt authentication/download negative controls.

RPM qualification is in progress against publisher-signature/hash-verified Fedora 45
and Rocky Linux 10.3 images. Their QGA administration restrictions require an explicit,
VM-only management fixture; product SELinux policy and enforcing mode stay unchanged.
Fedora correctly refused the unsigned candidate. A separately labelled, software-test-
signed candidate and metadata-only older fixture now have verified signatures in an
isolated keyring. Their private test key was destroyed; production hardware signing
and release provenance remain unqualified. Current trial outcomes come from their
RESULT.json files, not from successful signing or archive inspection alone.

The policy inventory now names the local CTAP PIN/UV P-256 key agreement used by
the pinned FIDO library. An Ed25519 credential does not change this boundary. The
full-stack hybrid-PQ/SafeCurves mandate remains a target requiring compatible hardware
protocols and migration; no available device was reset or modified for that policy.

The initial signed RPM trials passed installation, replacement, damaged-code repair
and reboot without activation on both Fedora and Rocky, then failed authorized
controller use. Fedora's audit log reported `init_t self:process setpgid`; executable
labels had been inherited as `lib_t` from the payload. Restoring the host's configured
application labels gave `bin_t` and a successful bus diagnostic under enforcing mode.
The [diagnostic record](evidence/NATIVE_RPM_SELINUX_DIAGNOSTIC_20261118.json) preserves
the failed lifecycle result and explicitly identifies the separate diagnostic.
The fix labels only each new, unselected system slot and syncs it before publishing;
a regression proves label failure leaves the old current slot selected. All ten
runtime-integrity/transaction tests passed on Python 3.10 and the development interpreter;
nine package tests passed with one host-native-RPM skip. RPM depends explicitly on
`policycoreutils`. Fresh candidate D is software-test-signed with a new disposable
key, whose private material was destroyed. Fresh Fedora H and Rocky D trials follow.

Those intermediate trials failed safely before slot activation: resolving the
`restorecon` symlink changed argv[0] to `setfiles`, selecting its different command
syntax. The [rejected results](evidence/NATIVE_RPM_LABEL_DISPATCH_REJECTED_20261118.json)
are retained. The corrected invocation preserves its fixed dispatch name and still
executes only the ownership-checked resolved binary. Fresh candidate E, separately
test-signed with another destroyed software key, passed both full scoped lifecycle
trials: Fedora I and Rocky E. The [aggregate record](evidence/NATIVE_RPM_MATRIX_20261118.json)
includes signature, downgrade, retained replacement, repair, reboot, authorized bus,
protected removal and state-preserving recovered removal phases. Both guests were
stopped and owned temporary disks removed; logs/captures/results remain. Neither
trial qualifies a dedicated SELinux domain, real enrollment, physical power loss,
native authentication agent, RPM repository publication or release provenance.

## Additional downloads and device compatibility

The supplied research directory now has 36 files: the original 26 are unchanged,
and 10 additions are reconciled in [the gap review](RESEARCH_GAPS_20261118.md).
All six newly downloaded `.bin` JSON reports exactly match existing repository
records; they are retained evidence, not fresh WAN, traffic or membership runs.
The new spreadsheet supplies useful source/metadata corrections. The accompanying
progress report marks all 148 emulator scenarios skipped and does not deliver its
referenced runner/mutation/fuzz files. Do not count those descriptions as execution.

The new [firmware laboratory](HARDWARE_FIRMWARE_LAB.md) closes one actual execution
gap: Solo 1's pinned experimental PC authenticator passed real VPN fresh-assertion
sealing, operator dual signatures and corrupted-half refusals, two-salt hmac-secret,
all three roles' key generation/unseal, signed client enrollment and an explicit
Ed25519 assertion. [Result](evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json).
USB transport, PIN input and presence are virtual; no physical or tunnel pass is
claimed, and PIN/UV P-256 keeps strict hardware eligibility blocked.

The owner clarified that firmware execution should establish software compatibility
without waiting for a physical device or duplicating the full suite. Continue the
additional candidates. A later physical check targets shipped firmware/configuration,
native access/prompts and unplug/restart differences. The four commissioned units
remain untouched. An open glib 0.18.5 dependency alert, GHSA-wrw7-89jp-8q8g, remains
a separate desktop assurance task; the successful checkpoint CI does not close it.

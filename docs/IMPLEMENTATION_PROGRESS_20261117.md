# Main implementation progress

Owner direction: complete main-plan tasks 1–7 before one final implementation commit.
Preserve existing signed history; do not create interim implementation commits.
Pad-exposure qualification research follows the main implementation sequence; runtime
incorporation depends on its evidence gates. The controlling specification is
[the saved plan](IMPLEMENTATION_PLAN_20261117.md). No implementation commit has been made.

Signed licensing commit `d26c355` appeared in the shared owner workspace during this
work. Preserve it and the published documentation commit `66c26f3`. New component
metadata follows AGPL-3.0-or-later and the authoritative repository LICENSE. The
licensing commit included the in-progress workspace-member declarations; its new
workspace dependencies are completed by the implementation still pending here.

Completion means the acceptance gate passed. Source implementation, simulation,
physical validation and independent review remain distinct.

| Task | Current implementation and evidence | Remaining gates |
|---|---|---|
| 1 CI/provenance | Baseline `43996ad` passed three jobs; verification/release share static bootstrap builds; new locked native desktop CI job; build dependency advisory GHSA-fc5q-39xc-vjpf addressed via vendored picomatch extglob guard | Final CI and provenance qualification |
| 2 Traffic analysis | Metadata recorder, observation validity, counterbalanced runner and grouped analysis; three-arm smoke passed | Fresh controlled collection, analysis/correction and cross-environment replication |
| 3 Installation | Shared native/Python preflight, static helpers, verified slots, atomic legacy adoption, guarded removal; native Debian candidate built and RPM recipe/builder added | Complete native package VM matrix, RPM qualification, downgrade policy and signed repository |
| 4 Recovery/hardware | Static guard missing-runtime and missing-guard reboot trial passed; externally witnessed IPv4/IPv6 output/forwarding checks | Full installation fault matrix and remaining physical four-device cases |
| 5 GUI | Prototype preserved/imported; production/demo separation, Vue/Tauri builds, native broker, caller-bound plans, native approval details, public request export | Native IPC/Polkit/WebKit integration, complete owner/provider flow and five participants |
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
a test failure. Its result remains failed. The corrected trial uses candidate B in a
fresh `native-package-debian13-20261117b` directory; consult RESULT.json for its actual
state before claiming completion. A private-state marker is a retention fixture,
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

The updated regression suite passed all **682 tests, 23 skipped**. Rust workspace
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

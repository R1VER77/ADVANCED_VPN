# Completing tasks 1–7 for cypherpunk_vpn

Agreed implementation plan, 17 November 2026. Saved before implementation at the
owner's request. This records intended work and acceptance gates, not completion.
The public [roadmap](ROADMAP.md) tracks which gates have actually passed.

## 1. Summary and fixed decisions

The starting point is commit `c4b4719`. Its GitHub verification workflow is fully
green, including formal models, protocol laboratories, Python compatibility and
offline-package tests ([run 44070958070](https://github.com/R1VER77/ADVANCED_VPN/actions/runs/44070958070)).

Already completed: deterministic setup checks, confirmed hardware repairs, physical
tests of the four available devices, offline runtime packaging, guarded removal, and
clean installation tests on Debian 12/13 and Ubuntu 22.04/24.04.

Selected defaults:

- **DNS:** encrypted hybrid-PQ upstream remains the default; owned recursive DNS is an
  explicit alternative.
- **Mobile assistant:** qualify on **4 GB devices**; treat 2 GB support as a separate
  stretch target.
- **Gemma:** text guidance and proposed, reviewed actions.
- **Development:** existing resources and free tools; no new paid infrastructure.
- **Publication:** validate, hardware-sign, automatically push and integrate signed
  commits.
- **Authority:** the controller verifies security state. The GUI and model present
  findings and proposals.

The first deliverable is a complete Linux release candidate. Other platforms follow
with their own protection tests. Snippets below specify new contracts and critical
behavior; they do not mean those changes are already implemented.

## 2. Implementation workstreams

### Task 1 — Maintain a trustworthy CI and release baseline

**Current status:** the existing workflow has passed. This task becomes an ongoing
release requirement.

1. Record the successful workflow against the source commit.
2. Add required checks as the native installer, controller bridge, GUI and platform
   adapters arrive.
3. Preserve the existing release gate: the tag's own verification must pass, and failed
   verification runs on that commit must block publication.
4. Keep dependency locks and interpreter pins shared between verification and release
   builds.
5. Build packages from one source revision and produce checksums, dependency
   inventories and build attestations.
6. Verify attestations before publishing release assets.
7. Preserve signed history and verify the remote branch after each push.

The existing release-gate interface remains:

```yaml
- name: Require successful verification
  run: |
    python3 tools/release_gate.py \
      "$GITHUB_REPOSITORY" \
      "$GITHUB_SHA" \
      "$GITHUB_REF_NAME"
```

| Component | Required checks |
|---|---|
| Native preflight | Static build, fixture parity, unsupported-host cases |
| Packages | Offline install, upgrade, removal and rollback |
| Controller bridge | Authorization, stale plans, malformed requests |
| GUI | Type checking, component tests, native WebKit rendering |
| Assistant | Secret boundaries, tool restrictions, held-out evaluation |
| Platforms | Native builds and platform-specific protection tests |

**Completion gate:** a release identifies its source, required checks, artifact hashes
and provenance. Skipped hardware or platform tests remain visible in its support
matrix.

### Task 2 — Resolve the traffic-analysis findings

The last experiment retained classification signal. Choosing a faster setting alone
will not close this task.

#### A. Complete the controlled replication

Implement the prepared six-round, **720-attempt** schedule:

- 20 monitored sites.
- Two loads per site, per variant, per round.
- Three variants: undefended, relay 30 ms and relay 5 ms.
- Every ordering of the three variants appears once.
- Each round uses a different recorded site-order seed.
- All variants within a round use the same site-order seed.

```python
ROUNDS = [
    (1475067252, ("relay30", "relay5", "undefended")),
    (929854378,  ("relay30", "undefended", "relay5")),
    (1997314573, ("relay5", "undefended", "relay30")),
    (3200583649, ("relay5", "relay30", "undefended")),
    (1259733358, ("undefended", "relay30", "relay5")),
    (1713829992, ("undefended", "relay5", "relay30")),
]

def scheduled_arms():
    for round_id, (seed, variants) in enumerate(ROUNDS, 1):
        for variant in variants:
            yield {
                "round": round_id,
                "variant": variant,
                "seed": seed,
                "workers": 1,
            }
```

Defended arms preserve the measured `fast` configuration, 4,000-packet clock setting,
bidirectional clock operation and CPU placement. The undefended arm explicitly clears
clock overrides.

Before collection:

- Freeze and hash binaries, browser settings, tools and the analysis specification.
- Check storage against the projected capture size with a 2 GiB reserve.
- Refuse to overwrite an existing run directory.
- Check CPU and power conditions.
- Avoid concurrent compilation, training and hardware administration.
- Record interruptions and background activity.

Captures continue storing packet timing, direction and length rather than packet
contents. Each completed arm can be compressed losslessly after collection stops.

#### B. Correct the analysis limitations

Extend `tools/wf_real.py` and `tools/wf_ab.py` to:

- Support the undefended control alongside both defended variants.
- Record protection observations throughout each load.
- Add a separate metadata-only escape audit for the isolated test namespace.
- Preserve every attempted load in availability and latency reports.
- Use complete fixed-window captures as the primary classifier dataset.
- Keep resource-filtered results as a secondary sensitivity analysis.
- Compute filter references from training folds, excluding held-out observations.
- Retain whole-round holdouts.
- Run at least 1,000 grouped label permutations.
- Correct prespecified defended-view comparisons for multiple testing.
- Report confidence intervals, individual-site results and missed-slot counters.

A missing or incomplete capture is a collection failure, rather than an omitted
successful-looking sample.

#### C. Investigate and correct remaining leakage

If replication confirms leakage, correlate classification results with missed
transmission slots, queue starvation/depth, late kernel submissions, reconnection and
handshake boundaries, CPU pressure/clock phase, and upstream/downstream differences.

The implementation direction is an independent, bounded transmission scheduler with
sufficient prefilled departures and no catch-up bursts. Candidate scheduling changes
preserve nonce uniqueness, key rotation and bounded buffering.

Tuning and final validation datasets are separate. A candidate selected on tuning data
must pass fresh collection.

#### Acceptance gates

These are proposed engineering thresholds, not general anonymity guarantees:

- The undefended control demonstrates that the attack pipeline works.
- For the 20-site experiment, each defended view's upper confidence bound is no more
  than **five percentage points above chance**.
- Corrected tests reveal no unresolved classification signal.
- Page-load success meets a preregistered non-inferiority margin of five percentage
  points against the matched control.
- No cleartext application escape occurs.
- Results replicate across at least three days, two networks and two physical client
  devices before promoting experimental defaults.

Then expand to 100 monitored sites, an open-world population and cross-link correlation
tests. Larger collections need their own frozen protocol and storage check. An
unsuccessful gate produces a published finding and another implementation iteration.
A non-significant p-value alone does not establish privacy.

### Task 3 — Finish native installation and distribution

#### A. Static preflight

Implement a small Rust preflight binary compiled for musl. Reproduce the existing host
checks: supported OS, architecture, required ABI, TUN, nftables, seccomp, systemd,
trusted executables, available storage and conflicting VPN interfaces.

Share declarative policy tables and fixtures; run both implementations against the
same cases and compare normalized findings/severity. Keep fixture-root overrides out
of production builds. Report unavailable optional hardware/provider checks explicitly.
The native program works before Python is available; the bundled interpreter remains
the runtime for existing orchestration.

#### B. Versioned application slots

Replace the directory-replacement window with verified, versioned slots and an atomic
`current` pointer. The transaction is:

`prepare → verify → fsync → activate → check → commit`

Retain the previous slot until running processes and rollback no longer need it.
After manifest verification and a durable transaction record, activation follows:

```python
def activate_verified_slot(root, slot):
    releases = (root / "releases").resolve(strict=True)
    slot = slot.resolve(strict=True)
    if slot.parent != releases:
        raise ValueError("slot outside the release directory")
    pending = root / ".current-next"
    pending.symlink_to(slot.relative_to(root))
    os.replace(pending, root / "current")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
```

Also use an exclusive upgrade lock, safe temporary-file creation and a recoverable
journal. Stable launchers resolve the selected slot before starting Python, so running
processes retain one coherent code/runtime version.

#### C. Native packages

- `cypherpunk-vpn`: controller, transport, runtime and compatibility commands.
- `cypherpunk-vpn-gui`: optional desktop application.

Package-managed commands belong under `/usr/bin`; preserve unrelated `/usr/local/bin`
files. Maintainer scripts operate offline, create required service identities, install
units without activation, preserve keys/private state, retain the guard during upgrades,
refuse unsafe removal and detect unmanaged tar installs for explicit verified adoption.

Start `.deb` qualification on the existing four distributions. Then qualify RPM packages
on Fedora 45 and Rocky Linux 10.3 using publisher-verified images:
[Fedora announcement](https://fedoramagazine.org/announcing-fedora-linux-45/),
[Rocky announcement](https://rockylinux.org/news/rocky-linux-10-3-ga-release).

#### D. Signed repositories

Publish signed apt metadata and package checksums using a dedicated hardware-backed
OpenPGP key. Inventory existing hardware slots before provisioning; never overwrite a
populated slot. Publish the fingerprint and rotation/revocation procedure. Preserve
build attestations. OpenPGP signatures remain a documented classical supply-chain
assumption.

**Completion gate:** package-manager installation, replacement, removal and recovery
pass on declared distributions without activation or loss of existing state.

### Task 4 — Complete recovery and hardware validation

#### A. Installation and protection fault tests

Inject failures after staging/manifest verification, before/after slot activation,
during service restart/configuration migration, after power loss, with missing runtime
files/full storage/damaged manifests, with incompatible signed profiles, and while the
guard is enabled and the tunnel is unavailable.

The boot guard must operate independently of the replaceable Python runtime. Missing
or invalid application slots leave the machine blocked. Rollback restores compatible
code/configuration pointers, never hardware counters, consumed pads, revocations or
other monotonic security state.

```python
FAULTS = (
    "after_stage_fsync",
    "before_activation",
    "after_activation",
    "during_restart",
    "power_loss",
    "incompatible_profile",
)

for fault in FAULTS:
    trial = run_disposable_vm_fault(fault)
    assert trial.cleartext_application_packets == 0
    assert trial.private_state_preserved
    assert trial.uncertain_ui_verdict != "protected"
```

Results come from guest state and out-of-band packet observation.

#### B. Remaining physical-device cases

For Nitrokey, YubiKey, Trezor and Ledger, complete locked/unavailable applications,
multiple authenticators, wrong-device selection, removal during enrollment/assertion,
cancellation/known PIN rejection, missing/repaired access after reconnect, supported and
unsupported algorithms, and full enrollment/connection/reboot/recovery.

Use isolated vaults. Preserve unrelated applications, OTP slots and credentials. No
automated PIN guessing, reset or firmware update. Replace vendor-command parsing with
pinned vendor-library adapters where practical, preserving canonical repair plans and
fresh post-repair verification.

**Completion gate:** supported entries name the tested unit, firmware when known,
operations and limitations.

### Task 5 — Build the real GUI and setup progress flow

#### A. Establish the controller boundary

Bring the existing prototype into the repository as a maintained application,
preserving its original snapshot. Use Vue/TypeScript for presentation, Tauri Rust for
the unprivileged desktop adapter, a narrow system D-Bus controller interface, Polkit
authorization and the existing setup engine for authoritative checks.

The privileged service derives caller identity from the D-Bus connection. Polkit
supports subjects tied to unique bus names:
[Polkit documentation](https://www.freedesktop.org/software/polkit/docs/latest/PolkitSystemBusName.html).

| Method | Behavior |
|---|---|
| `GetSnapshot` | Sanitized current status and freshness |
| `GetSetup` | Recheck and return setup graph |
| `PreviewAction` | Canonical action plan |
| `ApplyAction` | Authorize, revalidate and execute that exact plan |
| `CancelOperation` | Safe cancellation retaining protection |

Plans bind caller, target, input digest, state generation and expiry; consume once and
recheck before execution. Bundle import passes an opened descriptor or bounded bytes
rather than asking root to follow an arbitrary user path.

#### B. Implement both onboarding branches

**Create my network:** system → hardware → provider authentication → resource preview
→ provisioning → node requests → operator signing → enrollment → guard → verified
connection.

**Join an existing network:** system → hardware → trusted operator identity → bundle
verification → enrollment → guard → verified connection.

The existing seven client checks remain authoritative; owner provisioning adds
prerequisites.

```typescript
type StepState =
  | "pending" | "running"
  | "waiting_for_user" | "waiting_for_hardware"
  | "blocked" | "failed" | "complete" | "skipped";

interface SetupSnapshot {
  schema: 1;
  complete: number;
  total: number;
  current: string | null;
  finished: boolean;
  steps: SetupStep[];
}

interface ActionPlan {
  id: string;
  inputDigest: string;
  generation: number;
  expiresAt: number;
  summary: string;
  effects: string[];
}
```

Only controller checks complete/invalidate steps. Progress counts checked steps,
rather than inventing a time percentage.

#### C. Correct the prototype contract

- `unlock` answers a trusted hardware prompt.
- Guard removal remains explicit `reset --allow-cleartext`.
- Rate-class changes initiate a newly signed route workflow.
- Connection scope is explicit: applications or whole device.
- Stale, missing or contradictory status displays **unknown**.
- Production builds have no automatic mock-controller fallback.
- PIN simulation/demo controls stay in a separate demonstration build.

#### D. Finish appearance and accessibility

Retain the IVPN-style split layout, project logo, Wayqo palette and offline map. Add
collapsible checklist, one current prompt, actionable errors, verified resume, keyboard
navigation, screen-reader labels and reduced motion. Configure explicit Tauri
capabilities for application commands and plugins, supplementing backend validation:
[Tauri security guidance](https://v2.tauri.app/security/capabilities/).

**Completion gate:** native packaged-app tests and owner-arranged sessions with at
least five people who do not administer servers. They must distinguish protected,
blocked and unknown and recover from scripted failures without technical assistance.

### Task 6 — Expand provisioning and train the optional assistant

#### A. Deterministic provider adapters first

Implement `discover → preview → apply → reconcile → verify → destroy`.

Rollout: (1) bring-your-own SSH; (2) AWS/OCI parity; (3) GCP/Azure; (4) Hetzner,
DigitalOcean, Vultr, Akamai/Linode, Scaleway, OVH and UpCloud.

Expose architecture, image, connectivity, resource ownership, allowance information,
cost uncertainty and teardown. Run as ordinary user; use native provider credentials;
pin OpenTofu/plugins; apply the exact reviewed saved plan; reconcile partial creation;
destroy only operation-owned resources. Bootstrap carries public data; private node
keys are generated on their destination. Keep raw output/credentials outside GUI/model
context. AWS discovery respects selected Region, eligibility and spend controls and
never assumes credits, addresses or compute are free.

#### B. Encrypt state and saved plans

Use supported encryption with a hardware-backed local key helper implementing the
external-key protocol and communicating with an operation-scoped key agent:
[OpenTofu encryption documentation](https://opentofu.org/docs/language/state/encryption/).

```hcl
terraform {
  encryption {
    key_provider "external" "device" {
      command = ["/usr/libexec/cypherpunk-state-key"]
    }
    method "aes_gcm" "device" {
      keys = key_provider.external.device
    }
    state {
      method   = method.aes_gcm.device
      enforced = true
    }
    plan {
      method   = method.aes_gcm.device
      enforced = true
    }
  }
}
```

Keys do not appear in configuration, arguments, logs or model context. Bind helper
requests to the active provisioning job.

#### C. Local assistant architecture

Start with **task-tuned FunctionGemma 270M** for bounded next-action selection and help
routing, with reviewed templates for critical instructions. Evaluate **Gemma 4 E2B**
separately for fuller conversation. Effective and total parameter counts differ;
4 GB suitability must be measured:
[FunctionGemma](https://ai.google.dev/gemma/docs/functiongemma),
[Gemma 4](https://ai.google.dev/gemma/docs/core/model_card_4).
Use [LiteRT-LM](https://developers.google.com/edge/litert-lm/overview) for mobile inference.

Model operations: explain current finding, search approved help, propose allowlisted
action. Execution remains behind independent controller/provider review and
authorization. The inference process has no provider credentials, hardware access,
shell execution, authenticated-browser inspection or runtime network access.

#### D. Documentation updates

A separate updater retrieves public official documentation through an allowlist and
records URL/applicable version, fetch time/digest, HTTP revision metadata and review
status. New documentation is untrusted content; it cannot add tools or change an
adapter. Interface mismatch produces guidance or a blocked adapter until a tested
update arrives. Offline operation uses signed documentation bundles. Model and
documentation updates remain separate releases.

#### E. Training and evaluation

Build reviewed successful/failing trajectories, ambiguous hardware, unsupported
algorithms, interruptions, stale documentation and malicious instructions. Split by
scenario family; hold out provider/document revisions and hardware combinations.
Template variants cannot straddle training/final evaluation.

```python
adapter = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    task_type="CAUSAL_LM",
)

training = SFTConfig(
    output_dir="setup-assistant",
    max_length=512,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=16,
    num_train_epochs=2,
    learning_rate=1e-4,
    report_to="none",
)
```

Use pinned local model/data revisions with telemetry and automatic uploads disabled.
Existing CPU resources support the small-model path; larger-model training depends on
suitable available hardware.

Initial gates: ≥95% correct supported held-out next actions; ≥99% correct abstention
on deliberately unsupported cases; no unauthorized executions in adversarial
integration tests; default assistant ≤1 GiB peak memory; no sustained-test OOM on a
physical 4 GB device. Measure latency, throughput, thermal and battery behavior. Unload
on help close/setup finish. Observed safety success does not replace tool enforcement.

**Completion gate:** applicable adapter integration tests and measurable setup benefit
without weakening the deterministic flow. Providers without authorized live trials
remain unqualified.

### Task 7 — Complete assurance, decentralization and platform work

#### A. Implement the selected DNS policy

```rust
#[derive(serde::Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case",
        deny_unknown_fields)]
enum DnsBackend {
    HybridTls {
        upstream: std::net::SocketAddr,
        server_name: String,
    },
    OwnedRecursive,
}
```

**Hybrid TLS:** preserve hybrid key exchange/authenticated upstream; failure produces
DNS failure, not another mode. **Owned recursive:** dedicated exit-local loopback
Unbound, DNSSEC validation, QNAME minimization, RAM-only caches and no query logging;
validate before starting:
[Unbound documentation](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).

Explain that authoritative traffic beyond the exit may be plaintext and DNSSEC remains
classical. Never switch automatically. Authenticate new DNS policy in enrollment;
existing signed profiles retain their meaning. Verify before applying compatibility
defaults.

#### B. Extend assurance work

Add formal models for cloak role/exporter binding, dual-signature enrollment,
replay/expiry, and controller authorization/stale plans. Require executable traces and
broken variants falsifying each intended property.

Fuzz production enrollment, DNS, descriptor, control-message and proof parsers within
their production bounds:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= enrollment::MAX_BUNDLE_SIZE {
        let _ = enrollment::parse_untrusted(bytes);
    }
});
```

Review secret lifetimes; move additional secret-bearing operations to bounded Rust
helpers where exposure is reduced. Preserve Linux immutable-descriptor handoff and
document Python-copy limitations.

#### C. Reconcile mesh verification

The Rust token boundary rejects spends while Python/design material describes other
mechanisms. Reconcile interfaces/documentation before opening the public pool:
protocol versions, compatible vectors, epoch/issuer/request binding/replay checks,
forgery/inflation/restart tests, authenticated spent-state recovery and retention
privacy review. Keep public pool fail-closed until verifier and replay mechanism pass
review. Separate accurate classical-credit and hash-based-proof descriptions.

Distinguish identities, providers, ASNs and independently established operators.
Multiple keys do not prove multiple people. Evaluate existing I2P integration and
maintained upstream capabilities before adding another network integration.

#### D. Complete name migration

Add `cypherpunk` aliases, qualify package/launcher transitions, migrate service/state
paths with receipts/recovery, update release/attestation references, then rename the
repository after redirect/verification checks. Cryptographic contexts and signed
payload identifiers remain protocol identifiers until versioned migration passes.

#### E. Port platform-dependent code

Extract portable Rust protocol/enrollment code with byte-compatible vectors; keep
privileged networking in native adapters:

```rust
trait PlatformVpn {
    type Tunnel;
    fn capabilities(&self) -> PlatformCapabilities;
    fn establish(
        &mut self,
        policy: &VerifiedPolicy,
    ) -> anyhow::Result<Self::Tunnel>;
    fn protection_status(&self) -> VerifiedStatus;
}
```

Order: native aarch64 Linux → Android → macOS → Windows → iOS/iPadOS.
Use Android VpnService, Apple packet-tunnel extensions and Windows TUN/WFP. Native
components are required beyond shared GUI:
[Android](https://developer.android.com/develop/connectivity/vpn),
[Apple](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider.md).

Test reboot, network changes, sleep/wake, process death, DNS/IPv6, hardware access and
failed recovery on each. Do not assume Linux pacing is portable; qualify traffic
analysis separately per platform.

#### F. Obtain independent review

Freeze a reproducible review candidate; obtain scoped independent review; record
conflicts/findings; fix material issues and obtain retests. Review can be unpaid.
Maintainer and model analysis remain internal work.

## 3. Execution order

| Stage | Work |
|---|---|
| A | Record green baseline; prepare collector and freeze experiment |
| B | Run 720 attempts in a quiet window |
| C | Analyze; develop and freshly validate scheduling corrections |
| D | Native preflight, packages, upgrade/recovery transactions |
| E | Controller bridge and live Linux GUI |
| F | Provider adapters, documentation retrieval, assistant evaluation/training |
| G | DNS, assurance, mesh, migration and platform qualifications |
| H | Freeze release candidates; close applicable independent-review findings |

Add assurance tests with every subsystem. Schedule builds, fuzzing, training, VM load
tests and hardware administration outside CPU-sensitive collection periods.

## 4. Verification and release evidence

Each milestone records signed source, test commands/pinned environment, positive/
negative/skipped results, artifact/source hashes, support-matrix changes, limitations/
recovery instructions, published branch and CI verification. The release matrix
separates installation compatibility, physical hardware tests, guard/tunnel protection,
traffic-analysis measurements and independent review. Support requires applicable
acceptance tests.

## 5. Assumptions and external dependencies

- Linux is the first complete release target.
- Paid cloud trials, subscriptions and audit expenditure remain unauthorized.
- Live cloud changes require concrete resource/cost previews and applicable approval.
- Hardware signing/new release keys use trusted local prompts.
- Preserve existing keys, firmware, OTP slots and wallet material.
- Usability/review require actual participants, not simulated substitutes.
- Platform qualification needs physical devices and native tooling.
- Storage shortages stop collection before loss; preserve existing datasets.
- Failed gates remain open until their criteria pass.

## Owner-supplied research for the information-theoretic claim

On 17 November the owner supplied Ahlswede–Csiszár, *Common randomness in information
theory and cryptography. I. Secret sharing*, and Maurer, *Secret key agreement by
public discussion from common information*. Review their source/adversary/channel
assumptions against pad generation, extraction, sharing, storage and DC-net operation
before changing claim scope. The existing conditional claim and unintegrated-library
status remain the baseline until that review records its conclusions.

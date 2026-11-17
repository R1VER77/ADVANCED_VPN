# Independent review package

Prepared 17 November 2026. No independent review has been completed or commissioned.
No reviewer, fee or budget is appointed. A qualified volunteer can review without
funding; payment is not the test of independence. Maintainer and AI self-review must
remain labeled as such.

## Scope and starting material

Review a fixed signed commit, recording its full hash, signature verification, tool
versions and exact configuration. Start with [SECURITY.md](../SECURITY.md),
[architecture](architecture.md), [post-quantum inventory](PQ_INVENTORY.md),
[verification plan](VERIFICATION_PLAN.md) and [release history](../CHANGELOG.md).
The release tarball and attestation should identify the source/build provenance;
source signatures alone do not prove the distributed binary matches it.

| Boundary | Primary code / material | Questions and expected evidence |
|---|---|---|
| Privileged control and installation | `tools/avpnctl.py`, `tools/install.py`, `tools/sysexec.py`, `deploy/`, `src/sandbox.rs` | Trace attacker-controlled paths, environment, subprocess arguments, ownership, namespaces and recovery. Test stale status, child/controller death and root/unprivileged separation in a disposable VM. |
| Enrollment and key custody | `tools/keyguard.py`, enrollment paths in `tools/avpnctl.py`, `tools/setup_cli.py`, `tools/setup_flow.py`, `tools/hwkey.py` | Test tampered/replayed bundles, signature downgrade, key/counter handling, symlinks, ambiguous/locked hardware and canonical repair approval. Do not use real wallet material. |
| Cryptographic composition | Rust transport, cloak, link and membership modules; `formal/` if present; PQ inventory | Separate primitive security from composition. Trace hybrid inputs, role/context binding, authentication, rotation, replay and zeroization. Identify classical assumptions and unmodeled properties. |
| Traffic guard and shaping | `src/daita.rs`, `src/link.rs`, wire-clock implementation, controller guard and DNS paths | Independently reproduce busy-CPU behavior, dropped/missed slots, packet sizes, fail-closed transitions and reboots. Verify no cleartext escape rather than relying on a status string. |
| Optional control lanes and mesh | mesh, mix, DC-net and membership designs and matching code | Establish what is integrated, reviewed and disabled. Review membership/credit verification and fail-closed behavior; assess operator independence and real anonymity-set assumptions. |
| Dependencies and publication | `Cargo.lock`, hash-locked Python requirements, workflows and third-party notices | Check advisories, pinned downloads, build provenance, root-time network access and upgrade/removal behavior. CI success is an input, not the review conclusion. |

Locate module paths at the selected commit rather than assuming a document is current.
The four-key physical trials are [recorded](evidence/SETUP_HARDWARE_20261117.json);
these establish those units' tested behavior, not all models/firmware. The latest
[traffic report](WF_REAL_RERUN3.md) includes negative findings, selection limits and
the next experiment. Formal-model CI proves only each model's stated lemmas under
its assumptions, not the complete implementation or deployed system.

## Reproduction and safe handling

Clone the public repository, verify the chosen commit signature against an independently
obtained owner key, and record `git status --porcelain` before running tests. Follow
[verify.yml](../.github/workflows/verify.yml) for tool versions, hash-locked dependencies,
unit/rejection tests, formal proofs and namespace laboratories. Run privileged install,
upgrade, reboot and removal tests only in disposable VM snapshots. Keep an out-of-band
console for guard/recovery tests. Publish commands, hashes, environment, failures and
skips with the report. Never infer physical tests from mocks.

Use synthetic credentials and isolated test vaults. The repository's private security
reporting route is in SECURITY.md; do not publish exploit details, real traffic,
credential handles or operational logs before coordinated handling. Do not probe live
third-party systems as part of this package.

## Required report and closure record

Record reviewer identity or stable pseudonym, relevant experience, scope, commit,
dates, compensation (including none), affiliations/conflicts, methods, excluded paths,
findings and reproduction instructions. The reviewer must have control over their
findings; a maintainer editing their own work cannot stand in for this independence.

For each finding record severity and impact, affected versions, owner, fix commit,
regression evidence, reviewer retest and residual risk. Distinguish unreviewed,
reviewed-with-findings and retested scope. A narrow unpaid review must not be marketed
as a full audit. Broad production or anonymity claims need the applicable roadmap
gates as well as a report; neither a funding event nor a checklist closes them.

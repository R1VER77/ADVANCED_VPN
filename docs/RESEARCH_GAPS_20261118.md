# Additional research and remaining validation gaps

Reviewed 18 November 2026 (America/Chicago). This supplements
[the original review](RESEARCH_REVIEW_20261118.md), preserves the supplied files,
and follows the owner's latest instruction: use the already commissioned four
physical units as the baseline and determine VPN usability for additional devices.
Do not repeat their baseline tests merely to increase a test count.

## Download reconciliation

The supplied directory now contains **36 files**: all 26 previously reviewed files
are unchanged and 10 have been added. The
[incremental hash inventory](evidence/RESEARCH_INPUTS_REFRESH_20261118.json)
records each addition and its relationship to existing repository evidence.

| Addition | What it adds | Treatment |
|---|---|---|
| `ADVANCED_VPN_FIDO2_Compatibility_Matrix.pdf` and `.xlsx` | Eighteen candidate groups, reported firmware-source findings, MDS extracts and synthetic capability profiles. | Reuse the research leads; separate source, profile and firmware execution evidence. |
| `fido_mds_full.json` | A selected metadata extract reporting blob 302, 538 entries and nextUpdate 1 December. | Retain as supplied metadata. The original signed JWT and verified chain receipt were not included. |
| `IMPLEMENTATION_PROGRESS_20261119.md` | A candid report of skipped emulation, claimed mutation controls and fuzz scaffolding. | Reuse its requirements; do not import missing scripts or count skipped scenarios as executed. |
| `WAN_2HOP_CLI.bin` | Existing two-hop WAN report. | Parsed JSON equals `docs/evidence/WAN_2HOP_CLI.json`; no new run. |
| `WF_REAL_PILOT.bin` | Existing real-website pilot, including the busy-CPU leak. | Parsed JSON equals `docs/evidence/WF_REAL_PILOT.json`; no new run. |
| `WF_REAL_RERUN.bin` | Existing client-clock rerun and residual analysis. | Parsed JSON equals `docs/evidence/WF_REAL_RERUN.json`; no new run. |
| `WF_REAL_RERUN2.bin` | Existing comparison of one versus two clocked directions. | Parsed JSON equals `docs/evidence/WF_REAL_RERUN2.json`; no new run. |
| `WF_REAL_RERUN3.bin` | Existing later traffic-analysis report and follow-up plan. | Parsed JSON equals `docs/evidence/WF_REAL_RERUN3.json`; no new run. |
| `ZK_MEMBERSHIP.bin` | Existing membership experiment. | Parsed JSON equals `docs/evidence/ZK_MEMBERSHIP.json`; no new run. |

The six `.bin` files are JSON, not executable firmware. Source declarations, a
certificate listing, and a `diagnose()` call on a fabricated GetInfo dictionary
answer different questions from a verified assertion and fresh key unseal.

## Corrections to reuse the hardware research accurately

The spreadsheet's reported source inspection improves the older catalog: Solo 1,
OnlyKey and Trezor have Ed25519 acceptance paths even when GetInfo omits algorithms;
TKey lists both Ed25519 and ES256; Ledger advertises hmac-secret. These are useful
leads, not new physical tests. The actual Solo firmware run below independently
confirms the omitted-algorithms issue and Ed25519 acceptance for that build.

- Record **functional VPN compatibility** separately from **strict crypto-policy
  eligibility**. An Ed25519 credential does not change the P-256 exchange in CTAP
  PIN/UV protocols 1/2. A successful compatibility trial cannot waive that policy.
- Keep exact SKU, firmware, app and transport separate. In the supplied MDS extract,
  Token2 base T2F2 has hmac-secret while a separate PIN Plus entry lists Ed25519
  without listed extensions. Combining those entries does not prove one product
  meets both requirements. Split Thetis Pro from the separate HyperFIDO U2F entry.
- Missing algorithms or extensions in metadata is insufficient evidence of absence.
  The supplied metadata contains only the reported certified subset and has not
  been independently signature-verified here. AAGUID matching alone is not proof
  that a connected unit is genuine or runs the inspected source.
- CanoKey's generated GetInfo was assembled with manually supplied dynamic fields,
  including PIN/verification state. It is not output from a configured token and
  does not prove that PIN, hmac-secret or signing operations completed.
- A negative firmware grep does not establish that BitBoxApp implements FIDO2.
  Keep BitBox02 and Keystone compatibility unestablished until a supported native
  interface and required operations are demonstrated. Browser PRF claims alone
  do not establish this VPN's native CTAP path.
- Ellipal has no established interface supported by the current implementation.
  This does not prove that an alternative interactive QR protocol is impossible.
- The spreadsheet's claimed tier totals are inconsistent with its rows. Use the
  individual candidate records rather than repeating those aggregate counts.
- Several synthetic profile results retain a Nitrokey-specific diagnostic message
  for unrelated models. These are protocol-input fixtures, not vendor detection
  or successful repairs on those devices.

## Work already covered and actual gaps

| Area | Existing coverage to retain | Missing evidence or implementation |
|---|---|---|
| Four commissioned physical devices | Existing fresh-assertion, sealing/tamper, access and repair results in [the support matrix](SUPPORT_MATRIX.md). | Do not rerun baseline tests. Revisit only a specific changed behavior or unresolved requirement. Public records do not establish every exact model/firmware. |
| Additional device execution | New actual Solo PC firmware trial described below. | CanoKey, Solo 2, TKey and OnlyKey need their own runnable interface/build and role operations; shared code is not a separate vendor pass. Closed firmware may remain unverified without access. |
| Capability/refusal and repair controls | Existing `test_hwkey.py`, `test_keyguard.py`, `test_hardware_setup_test.py` and setup/controller tests. | The new report's four mutation controls cannot be independently replayed from prose: its referenced scripts and result files were not supplied. Reuse existing tests, then add a missing mutation only against the real boundary it exercises. |
| Claimed emulator matrix | Report explicitly records **148 skipped scenarios**, across four unavailable backends. | No executed emulator coverage is supplied. Its described `lab_runner.py` is absent from the downloaded files. Build genuine backends for additional candidates, rather than replacing skips with fabricated successes. |
| Formal models | Existing models and broken variants; the formal job passed on signed `15e7975`. | New cloak/exporter, dual-signature and controller claims in the main plan still require their own models and nonvacuity controls. Existing proofs do not cover unmodeled composition. |
| Fuzzing | Report describes 69 seeds, Python targets and Rust stubs. | Described scaffolding/corpus files are absent. There is no supplied million-execution or sanitizer record. Connect real parser APIs and publish actual bounded runs before closing the gate. |
| Traffic analysis | Retain the pilot, all reruns and their limitations. The downloaded copies add no collection. | Fresh positive-control, counterbalanced collection with varied seeds and valid capture, followed by held-out environments. Do not promote the wire clock or claim fingerprinting resistance from duplicates. |
| Distribution | Existing six-distribution native lifecycle records and real apt controls. | Production repository signing/provenance, RPM repository metadata and full enrolled release/recovery qualification remain open. |
| GUI/cloud installer | Existing native broker and WebKit work; scoped plan saved. | Whole-registry search, reviewed recipes, encrypted jobs, complete owner/provider flow and participant evaluation are not implemented by this report. |

The report references scripts/results under its producer's `/home/z/my-project`
directory; those paths are not delivered artifacts on this machine. The supplied
progress document also explicitly reports that it did not execute traffic,
distribution, GUI or provisioning tasks. Do not turn those descriptions into passes.

All four jobs in
[GitHub verification run 44421603036](https://github.com/R1VER77/ADVANCED_VPN/actions/runs/44421603036)
passed on the published signed checkpoint. That is existing checkpoint evidence,
not CI coverage for later uncommitted laboratory changes. A separate open desktop
dependency alert, GHSA-wrw7-89jp-8q8g in glib 0.18.5, still needs a verified fix;
successful CI does not close that alert.

## Gap completed: actual Solo 1 firmware operations

The new [laboratory](../tools/device_compatibility_lab.py) runs Solo's upstream
experimental PC authenticator at pinned source
`fc8d2867c5ba8161302b809c80fa1fd6a4df94a2`, with real CTAPHID frames over isolated
loopback UDP. It uses the production VPN's FIDO, envelope, signature, key-generation
and signed-enrollment implementations. Transport/discovery and virtual PIN input
are the test substitutions; cryptographic results are not mocked.

The [actual result](evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json) passed:

- Fresh verified assertion and sealing/unsealing, with corrupted-envelope refusal.
- Both halves of operator authentication, with wrong-message, corrupted FIDO and
  corrupted ML-DSA signature refusal.
- Stable, distinct two-salt hmac-secret outputs and a verified assertion.
- Generation, sealing and unsealing of five keys for each client, relay and exit role.
- Signed client enrollment import and hybrid delivery verification.
- Explicit Ed25519-only credential creation and verified Ed25519 assertion, despite
  an empty GetInfo algorithms list. The unchanged default path selected ES256.

This establishes software compatibility for the named experimental build, not a
shipped Solo model's physical security, strict-policy eligibility, USB access,
native prompt behavior or a connected tunnel. Disposable test state is removed.
[Build inputs](evidence/SOLO1_PC_BUILD_20261118.json) and
[reproduction instructions](HARDWARE_FIRMWARE_LAB.md) retain the boundary.

## Efficient remaining device validation

The owner clarified that the primary question is whether a device can perform VPN
operations. A genuine firmware run can answer that software question without waiting
for a physical purchase. Do not make a duplicate full physical regression suite a
prerequisite for continuing development.

Where an actual unit becomes available, use a small confirmation for the residual
differences: matching shipped firmware/configuration, native transport/access,
real PIN/touch or on-device verification, and seal/unseal after unplug/restart.
Expand only when a difference or a relevant threat requires it. Physical validation
is required to label those physical properties tested; its absence does not erase
a valid firmware compatibility result.

Continue with CanoKey's own core/virtual interface, then Solo 2 and the next usable
candidate. Keep the [candidate inventory](DEVICE_COMPATIBILITY_VALIDATION.md) current
with functional, evidence and strict-policy results separately. The existing
physical units stay commissioned and untouched.

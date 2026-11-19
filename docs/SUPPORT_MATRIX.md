# Platform and hardware validation matrix

Updated 18 November 2026. Compatibility, a detected capability and a completed physical
test are different claims. This project remains experimental; the matrix does not
certify production security, hardware authenticity or every model in a product family.

## Platforms

| Platform | Current evidence | Remaining gate |
|---|---|---|
| **Debian 13, x86_64 Linux — OFFLINE INSTALL TESTED** | Physical development/setup host; all four key families exercised. 17 November clean-VM offline system/user install, replacement and guarded removal passed. Historical three-VM reboot/recovery validation on 8 November. | Cross-release/live upgrades and current-version reboot/protection validation. |
| **Ubuntu 22.04, x86_64 Linux — OFFLINE INSTALL TESTED** | Release ABI build target (glibc 2.35); Python 3.10 CI. 17 November clean-VM offline install/replacement/guarded removal passed. Historical cloud validation is separate. | Cross-release/live upgrades and complete current-version protection/recovery validation. |
| **Ubuntu 24.04, x86_64 Linux — OFFLINE INSTALL TESTED** | Namespace protocol/sandbox/failover/shaping CI; 17 November clean-VM offline install/replacement/guarded removal passed. | Cross-release/live upgrades and current-version installed protection/reboot validation. |
| **Debian 12, x86_64 Linux — OFFLINE INSTALL TESTED** | 17 November clean-VM offline system/user install, replacement and guarded removal passed. | Cross-release/live upgrades and current-version protection/recovery validation. |
| aarch64 Linux | Planned build and test expansion; an installed compiler target is not a supported release. | Native builds, dependencies, seccomp/sandbox and protection tests on real ARM hardware. |
| **Fedora 45 / Rocky Linux 10.3, x86_64 — NATIVE PACKAGE TESTED** | Publisher-authenticated images; corrected software-test-signed RPM passed install/replace/repair/reboot, VM-authorized controller use, armed-removal refusal and recovered state-preserving removal on both. SELinux remained enforcing. [Evidence](evidence/NATIVE_RPM_MATRIX_20261118.json). | Full enrolled-tunnel/boot-guard fault qualification, native authentication agent, dedicated confined SELinux domain, production repository/provenance and release qualification. |
| Other Linux distributions / musl | Preflight can identify missing requirements and suggest package names; this is not support certification. | Distribution-specific packaging and protection tests; no musl data-plane release today. |
| Windows / macOS | Planned, no current supported client release. | Native tunnel, guard, DNS, privilege separation, hardware access and recovery implementation and validation. |
| Android / iOS | Planned, no current supported client release. | Platform VPN APIs, background/always-on behavior, battery/network changes, hardware-key transport and recovery validation on real devices. |

Current offline-installation evidence: [17 November record](evidence/OFFLINE_PACKAGE_20261117.json).
Historical evidence: [VM record](evidence/VM_VALIDATION.json),
[managed validation](MANAGED_VALIDATION.md). Check the commit/date and configuration of
each record before treating it as evidence for a new release. Passing Linux namespace
tests does not establish mobile protection. IPv6 is currently blocked, not tunneled.

The new native Debian candidate A passed the scoped
[Debian 13 lifecycle trial](evidence/NATIVE_PACKAGE_DEBIAN13_20261118.json), including
reboot and guarded removal. The same artifact was
[refused by Debian 12](evidence/NATIVE_PACKAGE_DEBIAN12_REJECTED_20261118.json): its GNU
core requires glibc 2.38 despite the metadata's 2.35 declaration. It is not a qualified
portable release. The builder now rejects this mismatch; a baseline rebuild and fresh
native package matrix follow. The 17 November offline tarball passes above refer to
their separately hashed artifact and do not transfer to this candidate.

Rebuilt candidate B passed the full local native-package lifecycle on **Debian 12,
Debian 13, Ubuntu 22.04 and Ubuntu 24.04**. The
[four-distribution record](evidence/NATIVE_PACKAGE_MATRIX_20261118.json) identifies
the shared artifact, base images, harness revisions and actual phases. Ubuntu 22.04
uses a VM-only legacy Polkit fixture; Ubuntu 24.04's final install phases ran without
external networking after system dependency preparation. Native authentication-agent
interaction, physical power loss and complete enrolled-counter recovery remain open.
The downgrade archive is a metadata-only fixture, not an older protocol implementation.

## Cloud setup coverage

The current catalog names AWS, OCI, Azure, GCP, seven additional non-US providers,
RackNerd and a generic own-server path. These are catalog entries, not thirteen
independently qualified provisioning adapters. Only AWS and OCI have dedicated
creation paths today. Other providers use an already-created compatible server over
SSH; the GCP catalog entry is not recommended as a hop. Catalog terms are dated
research, not a current pricing guarantee.

Thousands of provider-specific integrations, automatic navigation of arbitrary cloud
websites and a trained local setup model are not implemented. Planned provider
expansion must distinguish a documented provider, authenticated readiness check,
reviewed resource plan, successful provisioning and complete protection validation.
The model must not promote an unrecognized interface or device to supported status.

The desktop create screen now provides local discovery across 4,825 pinned OpenTofu
provider entries. Their IDs/paths were checked against the complete upstream tree.
Selection does not execute plugins or create resources; the eleven recipe candidates
are not reviewed runnable recipes. [Evidence](evidence/OPENTOFU_REGISTRY_CHECK_20261119.json).

## Security keys and wallets

The generic path needs the CTAP capabilities used by the requested operation, including
`hmac-secret` for sealing and the required assertion/signing algorithm for enrollment.
A FIDO2 label or vendor USB ID alone does not establish all of these. The setup probe
checks the connected interface and reports limitations. A successful sealing test does
not certify that the same device supports the operator's full enrollment/signing role.

| Device family | Physical setup result, 17 November | Version/model limits |
|---|---|---|
| **Nitrokey — TESTED** | Capability diagnosis, isolated test-vault fresh-assertion seal/unseal, tamper rejection, missing-access detection, confirmed udev repair and baseline restoration. | One connected unit. Exact model/firmware was not captured in the public result; do not infer all Nitrokey models. Separate Nitrokey RNG workflows require their own vendor support. |
| **YubiKey — TESTED** | Same setup checks, plus disabled USB FIDO2 diagnosis and actual enable repair; original credential and other USB/NFC applications preserved. | Vendor probe reported firmware **5.2.7**. Other firmware/models, configuration-locked repair and all disabled-app combinations remain untested physically. |
| **Trezor — TESTED** | Same setup checks with verification on the device; FIDO-only access rule and restoration. | USB `1209:53C1`. Exact model/firmware is not established by the result. The CTAP firmware field `0` is not a vendor firmware version. No wallet operation or recovery phrase used. |
| **Ledger — TESTED** | Same setup checks with the device unlocked and Security Key app open; FIDO-only access rule and restoration. | USB `2C97:5000`. Exact model/firmware/app version was not recorded. Locked/wrong-app physical recovery remains open. No wallet operation or recovery phrase used. |
| Other CTAP2/FIDO2 authenticators | Generic protocol path and read-only diagnostics may apply; no physical qualification claimed here. | Require a fresh capability and role-specific round trip. Vendor repair allowlists do not cover unknown hardware. |

The [public results](evidence/SETUP_HARDWARE_20261117.json) include negative findings
and source/provenance limitations. The [procedure](HARDWARE_SETUP_TESTS.md) explains
isolated vaults, restoration and cases still needed. These tests did not reset devices,
change PINs, update firmware or inspect wallet material. Nitrokey/YubiKey udev rules
and generic FIDO rules can coexist: removing one vendor rule need not remove access.

### Additional firmware compatibility

| Implementation | Actual software result | Limits |
|---|---|---|
| Solo 1 experimental PC firmware, upstream `fc8d286` | Real CTAPHID and production VPN code passed fresh-assertion sealing, tamper refusal, both operator-signature halves with negative controls, two-salt hmac-secret, client/relay/exit key generation and signed client enrollment. Explicit Ed25519 credential and assertion passed. [Evidence](evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json). | Software compatibility for this build; no physical USB/prompt/persistence or live-tunnel qualification. PIN/UV uses P-256 on USB: flagged, not blocking; ranked cypherpunk-preferred (open firmware, PIN typed on the computer). |
| Solo 2 authenticator `45311f0` (lpc55 configuration) on a PC | The same real VPN operations passed on PIN/UV protocol 2, including a real Ed25519 credential. [Evidence](evidence/SOLO2_PC_VPN_OPERATIONS_20261119.json). | Unmodified authenticator and Trussed runtime; CTAPHID framing is the project's UDP host (upstream's PC runner serves none); zero-seeded RNG, presence always granted; no Secure/Hacker unit or tunnel trial. PIN/UV P-256 on USB flagged, not blocking; ranked cypherpunk-preferred (open firmware, PIN typed on the computer). |
| TKey FIDO2 app `7fdf8ea` on Tillitis QEMU (Castor) | The same real VPN operations passed, including a real Ed25519 credential, with the client on PIN/UV protocol 1 (the app refuses hmac-secret under protocol 2, which it advertises). [Evidence](evidence/TKEY_QEMU_VPN_OPERATIONS_20261119.json). | Emulated Castor running upstream test firmware; touch reads as pressed; no physical TKey or tunnel trial. PIN/UV P-256 on USB flagged, not blocking; ranked cypherpunk-preferred (open hardware and firmware, PIN typed on the computer). |
| CanoKey upstream UDP virtual firmware, `a349b268` | The same real VPN operations passed, including both signature-half negative controls and actual Ed25519/hmac-secret. [Evidence](evidence/CANOKEY_UDP_VPN_OPERATIONS_20261119.json). | Upstream test build with simulated presence and actual CTAPHID over loopback; not a shipped Pigeon/Canary qualification or tunnel trial. PIN/UV P-256 on USB flagged, not blocking; ranked cypherpunk-preferred (open firmware, PIN typed on the computer). |

The [firmware laboratory](HARDWARE_FIRMWARE_LAB.md) and
[additional candidate inventory](DEVICE_COMPATIBILITY_VALIDATION.md) keep execution,
source inspection and supplied metadata separate. A firmware result permits continued
software development; physical confirmation can focus on the remaining device-specific
differences. It need not duplicate the full cryptographic suite or retest commissioned
units. The new downloaded matrices do not qualify other models by themselves.

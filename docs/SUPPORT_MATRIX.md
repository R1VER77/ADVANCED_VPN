# Platform and hardware validation matrix

Updated 17 November 2026. Compatibility, a detected capability and a completed physical
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
| Other Linux distributions / musl | Preflight can identify missing requirements and suggest package names; this is not support certification. | Distribution-specific packaging and protection tests; no musl data-plane release today. |
| Windows / macOS | Planned, no current supported client release. | Native tunnel, guard, DNS, privilege separation, hardware access and recovery implementation and validation. |
| Android / iOS | Planned, no current supported client release. | Platform VPN APIs, background/always-on behavior, battery/network changes, hardware-key transport and recovery validation on real devices. |

Current offline-installation evidence: [17 November record](evidence/OFFLINE_PACKAGE_20261117.json).
Historical evidence: [VM record](evidence/VM_VALIDATION.json),
[managed validation](MANAGED_VALIDATION.md). Check the commit/date and configuration of
each record before treating it as evidence for a new release. Passing Linux namespace
tests does not establish mobile protection. IPv6 is currently blocked, not tunneled.

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

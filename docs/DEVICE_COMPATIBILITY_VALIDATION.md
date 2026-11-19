# Additional device compatibility validation

Owner scope, 18 November 2026: determine whether research-listed devices not already
available/tested can be used for this VPN. The four commissioned Nitrokey, YubiKey,
Trezor and Ledger units are the existing physical baseline, not the next test targets.

## Required result

For each exact model/firmware/application and VPN role, record:

- **Functional compatibility:** verified in the named test environment, incompatible
  for a demonstrated requirement, or unverified because evidence is insufficient.
- **Evidence:** physical unit, actual firmware emulator, protocol implementation,
  source inspection or synthetic fixture. A shared-core or generic simulator pass
  does not prove a different vendor/model works.
- **Strict policy:** eligible, blocked or unknown, with credential and PIN/secret
  channel algorithms reported separately. An Ed25519 credential does not remove
  CTAP PIN/UV 1/2's P-256 exchange.

The primary functional check uses the production VPN code to create a disposable
credential, obtain a verified hmac-secret with required user verification, seal and
freshly unseal actual generated VPN keys, verify its assertion and import an
appropriately signed enrollment. Exercise an actual lab connection when the backend
can reach the installed client flow. Operator signing is a separate role test:
verify both its FIDO signature and sealed ML-DSA contribution. Report exactly where
the test stopped; a source claim or mocked return value is not a functional pass.

Raw TRNG/OTP export, side-channel resistance, wallet signing and every distribution's
USB stack are separate questions. Do not make them prerequisites for deciding whether
the basic VPN authenticator operations work. Conversely, a generic FIDO2 or browser
PRF label does not prove this native CTAP hmac-secret path works.

## Research inventory and current work order

The inventory comes from the retained 16 November whitepaper catalog and its source
`FIDO2 Hardware Authenticator Analysis.md` and `Hardware TRNG Extraction Analysis.md`.
These are research leads, not current support guarantees. The source snapshot also
contains outdated conclusions about the four subsequently tested devices; preserve
the originals and use actual project evidence for those units.
The newer supplied spreadsheet and metadata refine those leads; the
[gap reconciliation](RESEARCH_GAPS_20261118.md) records their limitations and corrections.

| Candidate | Immediate validation route | Current status |
|---|---|---|
| SoloKeys Solo 1 | Upstream standalone PC authenticator; exercise production VPN operations against actual CTAP code. | **Software operations verified** on experimental upstream `fc8d286`, including actual Ed25519, hmac-secret, operator dual signatures and signed enrollment. [Result](evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json). Physical/tunnel qualification absent; strict policy blocked by PIN/UV P-256. |
| CanoKey Pigeon/STM32 | Upstream CanoKey virtual card/core, recording the actual emulated build and hardware differences. | Unverified for this VPN; first open-core target after the Solo PC path. |
| SoloKeys Solo 2 Hacker/Secure | Inspect/run its upstream PC runner and actual authenticator; keep secure-boot/physical variant differences explicit. | Unverified; shared Nitrokey code is not a Solo 2 test. |
| Tillitis TKey | Inspect the official tkey-fido2 application and available virtual transport; validate host integration and required verification. | Unverified; app availability alone is insufficient. |
| OnlyKey | Check official firmware and its precise CTAP extension; run host/emulated portions where available. | Unverified; password challenge-response is not CTAP hmac-secret. |
| BitBox02 | Inspect/run the vendor simulator and FIDO interface, not only its wallet API. | Unverified; browser PRF notes do not prove native compatibility. |
| Other Nitrokey 3 variants | Use exact-model evidence only if it adds a requirement absent from the existing baseline. | Variant/firmware/transport gaps remain; no repeat of the commissioned unit. |
| Other Trezor models | Exact-model upstream emulator where available. | The public physical baseline does not establish an exact model/firmware; do not infer one or transfer its result to every model. |
| Other YubiKey 5 / Bio variants | Official capabilities and exact firmware evidence; executable firmware unavailable means no invented vendor emulator pass. | Unverified per SKU/transport. |
| Other Ledger models | Security Key app availability and supported Speculos build targets. | The public physical baseline does not establish an exact model/app version; no blanket Nano X/Stax/Flex qualification. |
| Google Titan v2/v3 | Official model/firmware evidence and genuine vendor simulator only if available. | Unverified without sufficient executable or physical evidence. |
| Token2 T2F2 PIN+ / Bio3 | Exact vendor capability reports and available real firmware/interface tests. | Unverified; do not combine base T2F2 hmac-secret metadata with a separate PIN Plus Ed25519 listing. |
| Feitian BioPass FIDO2 Pro | Exact-model hmac-secret/verification evidence; distinguish older ePass SKUs. | Unverified; certification alone does not prove the VPN operation. |
| Thetis Pro | Establish the extension and verification before attempting integration. | Supplied MDS extract lists Ed25519; required native operations remain unverified. |
| HyperFIDO Pro | Establish exact model/protocol before attempting integration. | Supplied matching entry is U2F-only; distinct from Thetis Pro, not a transferable FIDO2 pass. |
| OneSpan DIGIPASS | Establish exact model and native CTAP extension. | Unverified. |
| Identiv / Kensington / Crayonic | Split into exact models when primary evidence identifies them. | Unverified; no vendor-wide inference. |
| Keystone 3 Pro | Establish an accessible native CTAP path and required extension. | Not established; air-gapped wallet signing is not this interface. |
| Ellipal | Establish an accessible native CTAP path before any compatibility claim. | Not established. |

Original U2F-only Titan, YubiKey 4/NEO and any demonstrated U2F-only configuration
are negative controls. A candidate with no hmac-secret, no required verification,
incompatible crypto or no usable transport is reported with that precise reason.

## Evidence and installation behavior

Pin the source/build, run against isolated temporary state and publish sanitized
results. Never attach production wallets or change commissioned keys for simulation.
No emulated key may sign git commits or become a production trust root.

The installer checks the connected interface at runtime, requests and verifies an
Ed25519 signing credential when supported, and never silently falls back under the
strict policy. Missing algorithm advertisement is unknown evidence. A functional
compatibility pass can coexist with a strict-policy block. Research-only or
unverified devices stay clearly labelled; unavailable vendor firmware is an honest
limit, not a reason to substitute a generic device and call the vendor tested.

Firmware execution is sufficient to establish the named software operations without
waiting for hardware. Do not block continued development on repeating the entire suite
physically. If an actual candidate unit is available, target the remaining firmware,
transport, PIN/touch and unplug/restart differences before labelling those properties
physically tested. [Laboratory procedure](HARDWARE_FIRMWARE_LAB.md).

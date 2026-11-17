# cypherpunk_vpn compatibility migration

Plan adopted 17 November 2026. The public project name is `cypherpunk_vpn`.
Existing `avpn` commands, `advanced-vpn` binaries/services, configuration paths and
cryptographic context strings remain compatibility identifiers until the gates below
pass. A cosmetic rename must not strand enrolled devices or disable a traffic guard.

| Surface | Migration and acceptance gate |
|---|---|
| GitHub repository | Prepare links, clone/remote instructions, Actions attestations, release URLs and downstream references. Rename only after testing redirects and provenance verification; retain the existing signed history. Current repository remains `R1VER77/ADVANCED_VPN`. |
| CLI / binaries | Add a `cypherpunk` alias to the same validated front end before deprecating `avpn`. Preserve argument behavior, JSON schemas and recovery commands through a documented compatibility period. Test both names end to end. |
| Packages and install location | Give packages stable ownership and explicit replace/conflict rules. Detect an unmanaged `/opt/advanced-vpn` installation and never silently overwrite it. Test source/tar/package transitions, downgrade refusal and rollback in clean VMs. |
| systemd units / traffic guard | Keep the old guard effective through upgrade, reboot and recovery. Do not disable a guard simply to rename it. Test service aliases, dependencies, child death, initramfs/network ordering and interrupted upgrades before switching canonical names. |
| State and key custody | Inventory `/etc/advanced-vpn`, runtime/state directories, private vaults, operator/cloud inventory and recovery paths. Use explicit migration receipts, ownership checks and atomic replacement. Preserve enrolled identities, counters and signatures; never export hardware keys or erase the only recovery copy. |
| Signed chains / protocol domains | Treat contexts, magic values, schemas and signed payloads as protocol identifiers. Do not search-and-replace them. Any wire/schema migration needs explicit version negotiation, downgrade rejection, cross-version vectors and re-enrollment instructions where necessary. |
| Documentation and provenance | Label old identifiers as compatibility names. Update help, onboarding, release notes, checksums, attestation-verification commands and security-report links together. Test both old and new release verification/recovery paths. |

Implement aliases first. Run the complete install/upgrade/reboot/disconnect/recovery
matrix on old and new paths before changing canonical services or state. Publish the
supported transition window and exact recovery commands with the release. Do not mark
the repository, package or protocol migration complete because the README changed.

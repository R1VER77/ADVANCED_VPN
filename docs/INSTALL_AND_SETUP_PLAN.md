# Installation, preflight, cloud and security-key plan

Status: agreed with the owner on 16 Nov 2026; implementation update 17 Nov. Branch `feat/install-preflight`.
Phase 1 Python/setup paths are implemented and physically tested. After the CPU-sensitive
measurement finished, Python/Rust validation passed and verified source was integrated
into the main local tree. Installed binaries/services were not upgraded. Packaging, OpenTofu
and vendor-library migration below remain planned.
Names follow the CYPHERPUNK_VPN rename when it lands (`avpn` becomes `cypherpunk`);
nothing here depends on the old name.

## Goals

1. Installation works the same on every supported system, and says *before* it changes
   anything what the system is missing and how to fix it.
2. The tool sets up cloud servers on many providers, without depending on each vendor's
   own command-line tool for everything.
3. Security-key management (YubiKey, Nitrokey, any FIDO2 key) works without a GUI and
   stays current.

## What exists today (checked against `main` at cfd79af)

| Piece | Where | State |
|---|---|---|
| Data plane, `avpn` command | Rust, `src/` | Release tarball, x86_64, glibc ≥ 2.35 (built on Ubuntu 22.04) |
| Controller, cloud, enrollment | Python, `tools/` | Runs in a hash-locked venv at `/opt/advanced-vpn/venv` |
| Installer | `tools/install.py` | Needs the host's Python ≥ 3.10 with `venv`, and fetches packages from PyPI at install time |
| Post-install self-check | `avpnctl.doctor()` (`avpn doctor`) | Checks `ip`, `nft`, `mount` and `systemctl`, the PQ library, keys, enrollment, units and the kill-switch table |
| Cloud | `tools/cloud.py`, `providers.py` | Creates servers on AWS and OCI through their CLIs; Azure, GCP and own servers are joined over SSH (`cloud host add/setup`) |
| Security keys | `tools/hwkey.py`, `tools/setup_flow.py`, `tools/setup_cli.py` | Implemented in this branch, not released: typed diagnostics, confirmed repairs and current-evidence resumable setup; physical four-device evidence in `docs/evidence/SETUP_HARDWARE_20261117.json` |

What the host must actually provide, read from the code rather than assumed:
- `/dev/net/tun` (`src/tun.rs`). WireGuard runs in user space (GotaTun), so no kernel module.
- `nft` and the kernel's nf_tables (kill switch, `avpnctl.nft`).
- `ip` (iproute2), `mount`, `systemctl`; `resolvectl` when systemd-resolved manages DNS.
- seccomp (required: the sandbox refuses an unsupported architecture). Landlock is best effort: without it the filesystem stays open, so this is a warning, not a blocker.
- systemd ≥ 250 only for `--protect systemd-creds`. Ubuntu 22.04 has 249 (known bug 9).
- glibc at least what the binaries' symbol versions need (`cloud.glibc_needed`).
- **Not** the host's OpenSSL. The Rust side uses its bundled aws-lc. The Python side uses
  the `cryptography` wheel, which carries its own OpenSSL (4.0.1 in the current lock). An
  earlier draft of this plan listed host OpenSSL ≥ 3.5; that was wrong.

## Decisions

- **Language:** keep the split.
  - Rust: the `avpn` command and everything privileged or on the network.
  - Python: orchestration, shipped with its own interpreter (python-build-standalone, pinned by sha256, as CI already does), so the host's Python version stops mattering.
  - Not C, for memory safety and because it adds no compatibility over static Rust.
  - Go stays an option only if a native multi-cloud SDK layer is ever needed.
- **No gdebi.** It only resolves a local `.deb`'s `Depends` from apt, which
  `apt install ./file.deb` already does. It also can't see kernel features, sessions or
  cloud accounts. Instead:
  - proper packages, so the package manager resolves libraries;
  - a **preflight** that checks everything else before anything is installed.
- **Cloud breadth comes from one engine, OpenTofu** (the MPL-licensed Terraform fork), not
  from wrapping every vendor CLI. Bring-your-own server over SSH is the universal fallback.
  The existing hand-written AWS and OCI paths stay until the engine matches them in tests.
- **Security keys:** standard CTAP2 (python-fido2) for everything; vendor libraries only
  for vendor-specific repairs:
  - `yubikey-manager` as a library;
  - `pynitrokey`.

  Both are pinned by hash and updated through reviewed releases. Never update key firmware
  automatically.

## Phases

### Phase 1: `avpn preflight` (built first)
The host checks needed *before* installing, as typed findings in the style of `hwkey.py`:
each has a severity (blocker / warning / info), a plain-language reason, and a repair plan
that is shown, never run silently.

Checks:

| Check | Severity if failing |
|---|---|
| OS and version supported, from `/etc/os-release` | Blocker on unknown family, warning on untested version |
| Architecture x86_64 (the only release build today) | Blocker |
| glibc against the package's need | Blocker |
| `/dev/net/tun` present | Blocker |
| `nft` and nf_tables usable | Blocker |
| `ip`, `mount`, `systemctl` present | Blocker |
| seccomp present | Blocker |
| Landlock enabled in the LSM list | Warning |
| systemd version, and whether `systemd-creds` sealing is possible | Info, or a warning when `--protect systemd-creds` is requested |
| Python ≥ 3.10 with `venv`, until the bundled runtime ships | Blocker |
| Free space at the install target | Blocker below the package size plus margin |
| Other VPNs active (WireGuard interfaces, OpenVPN, NetworkManager VPNs) | Info: nothing is replaced, but routes may conflict |

- **Missing packages:** mapped to the right package names for apt, dnf, pacman and zypper, and shown as one install command.
- **Output:** a human summary, or `--json` for the `avpn` front end and the setup checklist.
- **Shared with `doctor`:** the host checks live in one module, so before and after installation report the same facts the same way.
- **Security-key and cloud-login checks** plug in through the same registry:
  - `hwkey.py`, implemented alongside this phase;
  - `providers.readiness`.
- **Code rules:** standard library only, and it must run on Python 3.8+ (older hosts must still be able to *say* what's missing).
- **Phase 1b:** the same checks compiled into a static (musl) binary, for hosts with no Python at all. Deferred while a CPU-sensitive measurement runs on the build host.

Acceptance:
- unit tests against a simulated system tree (os-release, /proc, /sys, `PATH`) for every finding;
- mutation checks for each blocker;
- a run on this machine whose findings match reality.

### Phase 2: packages and an apt repository
- **The `.deb`:** built from the tree `install.py --out` already stages, with `dpkg-deb` (no new build tool).
  - `Depends` computed from the binaries' glibc need plus `nftables`, `iproute2` and `systemd`.
  - `Recommends: systemd-resolved`.
- **Bundled Python:** the interpreter and the hash-locked environment, so installation needs no PyPI access and no host Python.
- **Package scripts:** non-interactive and offline, as Debian policy requires. They never enable services (same rule as today).
- **Signed apt repository:** published from the release workflow, with the signing key on a hardware key.
  - The repository's attestation and SHA256SUMS chain matches the tarball's.
- **`.rpm`** follows with the same contents.

Acceptance:
- install, upgrade and remove in clean Debian 12, Debian 13, Ubuntu 22.04 and Ubuntu 24.04 VMs;
- preflight passes beforehand, and `doctor` agrees afterwards.

### Phase 3: cloud through OpenTofu, SSH as the universal fallback
- **A small provider contract,** the only things a hop needs:
  - a server from an image, with cloud-init;
  - a UDP port open only to the previous hop;
  - a static address;
  - teardown by tag;
  - a monthly cost estimate.
- **OpenTofu modules per provider** implement that contract.
- **The OpenTofu binary and plugins are pinned:**
  - OpenTofu: by sha256 plus its release signature;
  - providers: by `.terraform.lock.hcl` hashes.
- **State stays local,** encrypted with OpenTofu's client-side state encryption.
- **Account limits are discovered, not assumed:** region locks (for example AWS accounts restricted to one region), quotas and spend limits.
- **Logins** use each provider's own flow (its CLI login or an API token); the tool never stores cloud credentials itself.
- **Tier 1, each with a real create-and-destroy test:** AWS, GCP, Azure, OCI, Hetzner, DigitalOcean, Vultr, Akamai/Linode, Scaleway, OVH, UpCloud.
- **Bring-your-own over SSH** (today's `cloud host add/setup`) becomes a first-class tier and is documented for providers with no API. Crypto-paying, privacy-jurisdiction hosts mostly fall here.
- **The provider catalogue gains fields:** jurisdiction, accepted payment methods, and whether an API exists.

Acceptance:
- the AWS and OCI OpenTofu modules match the hand-written paths (same resources, same tags, clean teardown) before those paths retire;
- per-provider tests only touch resources they tagged.

### Phase 4: security-key vendor tools
- **Vendored libraries,** in `hardware-requirements.in`, pinned by hash:
  - `yubikey-manager` replaces calls to the `ykman` CLI in `hwkey.py`'s repairs (switching the YubiKey's FIDO2 function on);
  - `pynitrokey` for Nitrokey specifics.
- **Algorithm check:** enrollment shows only the algorithms the key reports (`getInfo`), so the Ed25519/Ed448 choice fails early on a P-256-only key instead of after a PIN prompt.
- **Staying current:**
  - Dependabot pull requests for the pinned libraries;
  - CI against the simulated devices;
  - a real-key smoke test before each release.
- **Firmware updates** stay a manual, confirmed action with the vendor's tool.

## Order and coordination
- **Order:** 1 → 2 → 3 → 4. Phase 1 needs no Rust build, so it can proceed during measurement runs.
- **Rust builds** (phase 1b, the `avpn preflight` subcommand wiring) wait until the CPU-sensitive measurement on the build host has finished.
- **`hwkey.py`, `setup_flow.py` and `setup_cli.py`** are consolidated in this branch. The
  preflight registry and controller use the same diagnostics; no separate session handoff
  or model is required for their operation.
- **Commits** are signed (hardware key touch). Since 17 Nov the owner has given standing
  authorization to automatically push and integrate verified signed commits into GitHub
  `main`, following required checks and branch protections, without another confirmation.

## Physical validation completed 17 Nov

Nitrokey, YubiKey, Trezor and Ledger each passed a separate test-credential vault round
trip using a fresh verified assertion, actual missing-device-access diagnosis, the
confirmed setup CLI's udev repair and restoration of original rules/access. YubiKey
firmware 5.2.7 also passed USB-FIDO2 disabled-state detection and enable-only repair,
with its original credential secret and USB/NFC application settings preserved.

The trials caught and fixed a stale-udev-tag diagnostic error. Current-event tags now
take precedence; vendor output is separated from JSON results. These are tests of the
connected units and setup paths, not all models/firmware, full host installation, cloud
provisioning or the finished GUI. See `docs/HARDWARE_SETUP_TESTS.md` and the physical
evidence JSON for scope and negative results.

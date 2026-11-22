<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/cypherpunk-vpn-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/cypherpunk-vpn-logo.png">
    <img src="docs/assets/cypherpunk-vpn-logo.png" alt="Cypherpunks VPN" width="520" />
  </picture>
</p>

# cypherpunk_vpn — managed Linux client

A Rust VPN data plane with signed enrollment, hardware-bound sessions, automatic networking, a persistent kill switch, DNS isolation, real GotaTun/Maybenot DAITA on your link to the first hop and paced, encrypted constant-rate links (over UDP or TCP) between every pair of servers behind it, and the original two hybrid post-quantum QUIC layers. The cloud relay never holds the inner tunnel keys. No existing VPN is automatically replaced during build or installation.

```mermaid
flowchart LR
    App[Protected applications] --> Client[Client]
    Client <-->|WireGuard + DAITA; two PQ layers inside| Relay[Cloud relay]
    Relay <-->|Paced, forward-secret PQ link; inner PQ ciphertext| Exit[Owned exit]
    Exit --> Internet[Destination]
```

WireGuard is the outer carrier, implemented by a vendored **GotaTun 0.10.2** (`vendor/gotatun`), with its actual DAITA integration and public **Maybenot 2.2.2** defense machines. Its ChaCha20-Poly1305 encryption and 256-bit PSK supplement the existing **two TLS 1.3 X25519 + ML-KEM-768 / AES-256-GCM layers**. WireGuard alone is not advertised as native ML-KEM. Authentication is post-quantum too: both QUIC layers accept **only ML-DSA-65** (FIPS 204) certificate chains and TLS 1.3 CertificateVerify signatures, and operator enrollment bundles require **both the classical operator signature and ML-DSA-65** (plus an optional **third operator signature half** from an **ML-DSA-44** FIDO2 credential on a separate hardware key, `avpn init --pq-vault`, schema 3). The hardware path uses the enrolled FIDO2 credential’s COSE algorithm; the software laboratory signer uses Ed25519. A correctly pinned classical (ECDSA) deployment is refused; the Rust tests prove this and fail if the restriction is removed. The listed VPN network layers enforce their hybrid key-exchange policy; compatibility dependencies and exceptions are named in the inventory. Authentication is post-quantum on the inner tunnels (ML-DSA-65, augmented by per-session hardware FIDO2 authorization when a device key is pinned) and on the cloak (protocol v2: both ends prove the enrolled key with a role-separated HMAC over the hybrid exchange; its browser-facing certificate is an ECDSA facade), while exit DNS either authenticates its DoT upstream (`X25519MLKEM768` enforced) with classical WebPKI signatures or resolves names directly on the exit with a local DNSSEC-validating recursive Unbound resolver (`avpn init --dns-recursive`). [docs/PQ_INVENTORY.md](docs/PQ_INVENTORY.md) separates key exchange from authentication for each layer, with enforcing code, tests and the five named exceptions. The local FIDO PIN/secret channel over USB uses P-256 (CTAP PIN/UV protocols 1 and 2) and is flagged on every key; the full-stack PQ/SafeCurves mandate is a migration target, not a qualification of that hardware boundary.

## Principles and roadmap

`cypherpunk_vpn` aims to make verifiable private communication practical: open source,
user-controlled keys, independently operated infrastructure and clear evidence of what
is protected. The repository, executable names and installation paths retain
`ADVANCED_VPN` / `avpn` / `advanced-vpn` alongside the compatibility migration shim
(`tools/name_migration.py`, `cypherpunk` CLI alias; [docs/NAME_MIGRATION.md](docs/NAME_MIGRATION.md))
so existing commands, state paths and signed protocol domains remain recoverable while
canonical names transition.

The [project roadmap](docs/ROADMAP.md) includes commitments informed by the CCC's
[Hacker Ethics](https://www.ccc.de/en/hackerethik),
[statutes](https://www.ccc.de/en/satzung) and
[incompatibility declaration](https://www.ccc.de/en/club/unvereinbarkeitserklaerung-des-ccc):
protect private data, promote decentralization and accessible knowledge, and make the
project's rejection of racism, fascism and the trivialization of violence explicit in
community governance. These are project commitments, not CCC affiliation or endorsement.

Project participation follows the [principles](docs/PRINCIPLES.md),
[conduct policy](CODE_OF_CONDUCT.md) and [governance](docs/GOVERNANCE.md).
The [voluntary funding record](docs/FUNDING.md), [hardware and operating cost breakdown](docs/HARDWARE_COSTS.md),
[revenue architecture](docs/REVENUE_ARCHITECTURE.md), [independent review package](docs/INDEPENDENT_REVIEW.md)
and [decision log](docs/DECISIONS.md) (D001–D017) make current responsibilities, declined
features and limitations explicit. Community governance must preserve users' privacy; it is
not a reason to inspect traffic or collect identities. Technical progress and remaining
limitations are tracked in the roadmap, [changelog](CHANGELOG.md), [incident log](docs/INCIDENTS.md)
and [security scope](SECURITY.md).

## What is automatic

- A signed role bundle supplies endpoints, identities, pins and safe defaults. No JSON, firewall, route or DNS editing is needed on an enrolled device.
- The supervisor creates WireGuard/TUN interfaces, addresses, routes, atomic `nftables` rules, an application namespace, owned-exit NAT, local DNS blocklist filtering (`NXDOMAIN` before upstream resolution, including CNAME-cloaking checks and signed allowlists), and DNS-over-TLS forwarding (or exit-local recursive Unbound DNSSEC resolution with `--dns-recursive`).
- The carrier rides inside `advanced-vpn-cloak` on port 443: HTTP/3 (QUIC, BBR congestion control, or FixedWindow when clocked) on UDP 443 by default, with automatic 2-second fallback to TCP/TLS 1.3 on port 443 when UDP is blocked or the path MTU is below 1448 bytes, periodic 10-second QUIC recovery probes, mutual role-separated exporter HMAC confirmation (cloak protocol v2), and a realistic `200 OK` HTML5 decoy page for unauthenticated HTTP/3 or HTTPS probes.
- The app namespace has no physical interface. The optional whole-device mode blocks direct IPv4/IPv6 fallback routes, and `TableWatch` restores the guard atomically if altered. Disconnect, controller death and data-plane death retain the guard. Optional auto-connect on untrusted networks (`tools/autoconnect.py`, decision D015) triggers fail-closed protection with a posture-only GUI surface (SSID counts only; SSIDs never cross the controller boundary).
- All five data-plane daemons run under a dedicated non-root service UID, have no Linux capabilities, cannot gain privileges, are confined by **seccomp-BPF and Landlock** (`src/sandbox.rs`), and die if their supervisor dies. On hardware-protected clients, **long-term ML-DSA-65 identity keys never enter the running VPN processes** ([hardware-bound sessions](docs/HARDWARE_BOUND_SESSIONS.md), Phase 2): a short-lived, undumpable (`PR_SET_DUMPABLE=0`, `mlockall`) signer process (`tools/session_signer.py`) unseals the long-term identities during the PIN+touch ceremony, certifies fresh per-session ML-DSA-65 layer keys alongside the FIDO2 hardware session statement (at most 12 hours), and exits immediately. The data plane receives only the per-session keys via immutable memory descriptors (`memfd`), and every hop pins the client's FIDO2 key (`peer_device`) and refuses any leaf without both the identity signature and the hardware session authorization. Renewal prompts one hour before expiry and fails closed if unanswered.
- `avpn status` (which works without root while the service runs) reports `"protected"` only with fresh evidence of all three: cloak v2 mutual key confirmation, a WireGuard handshake, and a 5-second end-to-end `.invalid` DNS probe answered by the exit (`tools/protection.py`). When a connected chain stops answering for a minute, a desktop notification and `avpn status` flag the stall and point to `avpn cloud health`.
- **No fees from a free account ([the fee guard](docs/FEE_GUARD.md)).** Every production server requires and enforces a monthly outbound cap derived from the account's free allowance (shared across all servers in that account and divided by the streams each hop sends, minus a 10% margin: Oracle Cloud 9,000 GB, AWS 90 GB, Azure 90 GB, Fly.io ~55 GB in Europe / ~75 GB in `iad`/`ewr` under its $5 personal waiver). An `nftables` kernel quota (`advanced_vpn_quota`) drops traffic the instant the cap is reached (status reads `capped` until the 1st of the next UTC month, while rate-limited SSH replies survive), and an IPv4/IPv6 **egress lock** (`advanced_vpn_egress`) drops all non-VPN outbound packets, pings and unlisted ports while running a daily security-only `unattended-upgrade` in a metered maintenance window. On the client, there is **no daily cap by default**, while an optional client-only daily cap (`preferences --daily-limit-mib N`, `--no-daily-limit`) is metered in the kernel and fail-closed.

There is one defense posture: **strong**. Your link to the first hop runs a **bidirectional constant-rate packet stream** (`src/daita.rs`: `stream_grid` + self-sustaining `cover` under GotaTun's strict-blocking scheduler, `strict: true`, `Replace: true`), and since v0.8.0 every link between two servers runs the same invariant as paced, AES-256-GCM-encrypted fixed-size cells (`src/link.rs`, over UDP by default or over TCP with `avpn init --link-transport tcp` for IPv6/TCP-only exits such as Fly.io), each hop on its own clock, keyed by an ephemeral X25519 + ML-KEM-768 exchange every two minutes, so a recording of a link stays sealed even against someone who later steals its pre-shared key. Every data packet is padded to constant size (1380 bytes inside WireGuard, 1420 bytes on the outer cloak, 1242-byte link cells), and every clock tick sends either a queued real packet or an indistinguishable decoy packet — so the outer packet rate and packet size stay flat while the shaper keeps its clock (not on a busy CPU: see below): between idle and full-speed transfers the wire packet rate changed by 0–3.7% in every measured class and hop count (`docs/evidence/RATE_CLASSES.json`; CI fails above 15%). Four rate classes, signed into the chain (`avpn init --rate auto|metered|standard|fast|line`), trade cover bandwidth for application throughput without weakening the constant-rate invariant:

| Rate class | Grid pacing | Wire rate / direction | 2-hop app throughput (v0.10.1, median of 3) | Cover volume / direction |
|---|---|---|---|---|
| `metered` | 20 ms × 1 slot (50 pps) | ~0.55 Mbit/s | 0.30 Mbit/s | ~5.7 GiB/day (~171 GiB/mo) |
| `standard` | 2 ms × 1 slot (500 pps) | ~5.5 Mbit/s | 3.0 Mbit/s | ~57 GiB/day |
| `fast` | 2 ms × 8 staggered slots (4,000 pps) | ~44 Mbit/s | 27.9 Mbit/s | ~455 GiB/day |
| `line` | 2 ms × 32 staggered slots (16,000 pps) | ~177 Mbit/s | 115.3 Mbit/s | ~1.8 TiB/day |

Wire rate and cover volume follow from the grid. A relay sends two streams (back to the client and on to the next hop), so its outbound volume is roughly twice the per-direction figure (`avpn cloud cap` and `init --rate auto` account for both). Throughput was measured on v0.10.1 (14 Nov 2026) in the namespace benchmark (`tools/throughput_bench.py`, SHA-checked, `docs/evidence/RATE_CLASSES_v0_10_1.json`); every run kept the wire rate within 1.5% between idle and transfer. The paced link into the exit carries 0.29 Mbit/s (`metered`) and 28.0 Mbit/s (`fast`) on 2 hops, and 24.5 Mbit/s (`fast`) on 3. An interleaved A/B against v0.9.1 shows the move to BBR congestion control (v0.10.0) cost nothing: at `line` on 3 hops it is faster (median 115.0 vs 106.8 Mbit/s) and much steadier from a cold start (115–119 vs 77–113). Earlier figures: v0.7.0 in `docs/evidence/RATE_CLASSES.json`.

The default is `--rate auto`: the fastest class whose stream fits the smallest hop's monthly allowance (`--allowance-gib`) at the hours connected per day; with no allowance given, `metered` (manual `avpn init` requires either `--allowance-gib` or `--accept-cost`). **`metered` is a messaging class, not a browsing one**: on real websites only 31 of 900 page loads completed through it (`docs/evidence/WF_REAL_PILOT.json`). Browsing needs `standard` or faster.

Website fingerprinting, against a 500-tree random-forest classifier across 30 synthetic sites (`tools/daita_lab.py`, `tools/wf_attack.py`, chance = **3.3%**, fixed 6 s observation window):
- **v0.7.0** (11 Nov 2026): the camouflaged carrier scored **3.3%** on `metered` and **1.7%** on `fast`, while the link between servers, then unshaped, scored **27.0–74.7%**.
- **v0.8.0** (12 Nov 2026), with every link between servers paced: that link scored **2.3%** (`metered`) and **2.7%** (`fast`), and the carrier 3.7% and 4.3%, all at or near chance.

Those are synthetic sites. On **real websites** (pilot, 12–14 Nov 2026, 20 monitored sites, headless Firefox, k-FP, DF and Tik-Tok; chance 5%; `docs/evidence/WF_REAL_PILOT.json`):
- Undefended, k-FP recognises **99.2%** (DF 94.6%, Tik-Tok 96.8%): the attacks work.
- `fast` with the browser off the data plane's CPU: **14.8%** closed world, open-world true positives near zero.
- **`fast` on a busy CPU leaks: 81%** when the browser shares cores with the client's data plane, as on most laptops. The shaper skips grid ticks it misses, so the missed ticks follow the page's own work (`throughput_bench.py --cpu-probe`, `docs/evidence/CPU_LEAK_PROBE.json`). A higher priority gives 75%; a bounded catch-up (`AVPN_CATCH_UP_MS=50`, off by default) about 50% (restoring packet counts while timing still leaks); a dedicated core or `SCHED_FIFO` 27–42%. None reaches the quiet-CPU level. The experimental **wire clock** (`AVPN_WIRE_CLOCK_PPS`, with FixedWindow congestion control on both ends so delayed ACKs do not collapse the relay's BBR window; `docs/evidence/KERNEL_PACING.json`), which hands packet departures to the kernel on both ends of your link, brought k-FP to chance on real websites in the 600-load interleaved re-run (5.15% against 5%, p = 0.58; the client's clock alone left 10.4%), at a cost of 3.5 points of page-load success and about 0.8 s per load ([docs/evidence/WF_REAL_RERUN2.json](docs/evidence/WF_REAL_RERUN2.json)).

A subsequent **400-load relay-look-ahead A/B** (16–17 Nov, [docs/WF_REAL_RERUN3.md](docs/WF_REAL_RERUN3.md), [docs/evidence/WF_REAL_RERUN3.json](docs/evidence/WF_REAL_RERUN3.json)) gave whole-round holdout scores of **10.94% at 30 ms** and **15.15% at 5 ms** (nominal chance 5%), with the 5 ms setting completing 193/200 loads vs 182/200 but skipping **0.572%** of relay clock slots vs **0.00145%** at 30 ms. A **frozen 6-round, 720-attempt fresh-control replication** on 20 November ([docs/WF_REPLICATION.md](docs/WF_REPLICATION.md), commit `efb2bc4`, counterbalanced `undefended`, `relay30` and `relay5` arms with kernel `time64` timestamps, zero packet drops and 1,000 round-grouped permutations) scored **100%** on `undefended` (97.1% upstream, 99.6% downstream; Holm p = 0.009) and brought both defended arms near the 5% chance floor with no statistically significant signal after Holm correction (**3.8%** both-directions on `relay30`, **8.3%** on `relay5`, all Holm p ≥ 0.18). However, the strict local acceptance gate **failed** on three checks: 95% bootstrap upper bounds reached **12.1%** (above the 10% ceiling), load-success non-inferiority lower bounds were **−6.3** and **−7.1** points (below the −5 point threshold, adding 1.4–1.9 s median latency), and one window per arm had 1–2 unprotected half-second status samples out of 6,232. Defaults therefore remain unchanged (`promotes_default: false`, decision D001).

Until a fix clears every acceptance gate across held-out days, networks and devices, **do not count on `fast` against website fingerprinting while the device is busy.** Fixing it remains the project's first technical priority.

Sources: `docs/evidence/DAITA_LAB.json`, `avpn help threat-model`. The 100-site exit-vantage simulation is in `tools/mesh_wf_sim.py` (`docs/evidence/MESH_WF_SIM.json`), the mesh design is in [docs/MESH_DESIGN.md](docs/MESH_DESIGN.md), and a side-by-side comparison with Mullvad and IVPN is in [docs/COMPARISON.md](docs/COMPARISON.md).

## Installation checks and resumable setup

Offline packaging ships a pinned Python runtime (Python 3.13 / OpenSSL 3.5+, pinned for `x86_64` and `aarch64`) and hash-locked dependencies.
From a verified runtime-bearing tarball, use `./install.sh --user` or
`sudo ./install.sh --apply`; installation never activates the VPN, and crash-interrupted
slot upgrades (`tools/release_slots.py`) sweep stale `.prepare-*` / `.current-*` links
under lock while preserving live environments. Inactive system removal refuses to
dismantle a retained guard and preserves keys/state. See
[offline installation](docs/OFFLINE_INSTALLATION.md) for authentication, validation and
the remaining distribution/signing work. Native candidates passed local package lifecycle trials on [Debian 12/13 and Ubuntu 22.04/24.04](docs/evidence/NATIVE_PACKAGE_MATRIX_20261118.json), and on [Fedora 45 and Rocky Linux 10.3](docs/evidence/NATIVE_RPM_MATRIX_20261118.json) with SELinux enforcing. Those records retain exact hashes, test authorization/signing fixtures and limitations. This has not yet been published as a tagged release.

Before installation, `python3 tools/preflight.py` checks host requirements without changing
anything; its standard-library bootstrap runs on Python 3.8+. The installed command is
`avpn preflight`, with machine-readable output from `avpn --json preflight`. It lists
blockers and suggests the appropriate package-manager command. `avpn doctor` shares the
same host checks. System installation runs this preflight before staging or host changes;
command-line-only user installation keeps its separate requirements. Optional hardware
and provider checks are explicit; provider sign-ins
stay with the ordinary user's existing CLI credentials.

`sudo avpn setup` rechecks a private, resumable client checklist: host, FIDO2 capabilities,
public credential record, enrolled route, configured endpoints, traffic guard and fresh
end-to-end protection. A saved checkpoint cannot certify a connection. The command uses
existing enrollment/provisioning workflows; it does not create servers, enroll a key or
connect on its own.

**Gemma-centric setup flow and desktop GUI ([docs/GEMMA_SETUP_FLOW.md](docs/GEMMA_SETUP_FLOW.md), decision D007):**
Setup is designed as one ordered flow led conversationally by a local Gemma model over the
narrowed, qualified provider catalog (`tools/providers.py`), calling only the deterministic
engine's typed tools (no shell access, no secrets or PINs in the model context, and explicit
human approval for every privileged or billable action):
1. **Provisioning and hardware-key setup** through pinned **OpenTofu 1.13.9** modules (`tools/tofu.py`, `tools/tofu_run.py`, SHA256SUMS and signing-key verified, with state and saved plans encrypted under a key sealed in the operator's Nitrokey vault via `avpn state-key`), currently covering `oci-server` (Oracle Cloud) and `azure-server` (Azure Trusted Launch with vTPM) alongside AWS, Fly.io and bring-your-own SSH hosts.
2. **The Vue/Tauri Linux GUI** ([`apps/cypherpunk-vpn`](apps/cypherpunk-vpn/README.md)) appears when provisioning completes, backed by a native D-Bus adapter, the read-side controller extension (`tools/controller_extension.py`: posture-only auto-connect, multi-hop presets, streaming eligibility table), and the create/join write side (`tools/controller_create_join.py`: branch-bound operator keys, operator-locked exit requests, and signing a route with a stated allowance, with exact hardcoded argv previews and an append-only action journal; `--accept-cost` is unreachable from the GUI).
3. **Viable-profile checks** on every subsequent launch verify signature validity, current protocol schema, key sealing and server health (`avpn cloud health`). Multi-profile storage and the trained local Gemma model evaluation remain open roadmap gates.

Hardware repairs are separate, exact plans: `avpn setup --repair ID` diagnoses and shows
an available fix. Applying it requires approval of the current plan and fresh verification
afterwards. A missing YubiKey HID interface alone never proves FIDO2 is disabled. The vendor
must identify the target and disabled application first. No repair resets FIDO, overwrites
OTP slots, guesses a PIN or updates firmware. PIN and signing prompts stay in trusted UI
(and ask only once per command in memory when an operation uses the key more than once).

See [preflight](docs/cli/preflight.md) and [setup](docs/cli/setup.md) for options, limits
and recovery, and the [installation plan](docs/INSTALL_AND_SETUP_PLAN.md) for later packaging,
cloud-engine and vendor-library phases.

The [support matrix](docs/SUPPORT_MATRIX.md) distinguishes tested hardware from protocol
compatibility and planned platforms. Every FIDO2 key's PIN/UV channel on USB is
P-256 (CTAP PIN/UV 1 and 2): since 19 November it is flagged rather than blocking, and
keys are ranked, open firmware with the PIN entered on the device first
([ranking](docs/DEVICE_COMPATIBILITY_VALIDATION.md#ranking-and-the-usb-channel-owner-decision-19-november-2026)).
Entering the PIN on the device protects the PIN, not the keys the computer then holds, so
a hardware-protected client's key also signs each session (at most 12 hours), a short-lived
undumpable signer certifies fresh per-session layer keys so long-term identities never stay
in the data plane, and every hop refuses leaves it did not authorize: keys copied off the
computer stop working when the session ends ([hardware-bound sessions](docs/HARDWARE_BOUND_SESSIONS.md)).

The firmware lab has verified the production VPN key/signing/enrollment and Phase 1/2
hardware-bound session operations across **four unmodified open-source FIDO2 firmwares**
(**Solo 1** `fc8d286`, **Solo 2** `45311f0` via the project's CTAPHID-over-UDP host,
**CanoKey** `a349b26`, and **Tillitis TKey** `tkey-fido2 7fdf8ea` on QEMU Castor), plus dual
Solo 2 instances for the optional **ML-DSA-44 (`COSE -48`) third operator signature half**;
[results and limits](docs/DEVICE_COMPATIBILITY_VALIDATION.md) remain separate from physical
tests. The create screen also searches a pinned local index of **4,825 OpenTofu providers**
with no query telemetry or plugin execution (discovery only; only reviewed, pinned recipes
may provision).

## Command line

`avpn` (and its compatibility alias `cypherpunk`) is the front end. Run it with no arguments in a terminal for the interactive
view: a session header (chain, mode, key protection, service state), a history of
results, and key hints (`c` connect, `d` disconnect, `h` hops, `s` status, `i` info,
`o` doctor). Long-running operations (`avpn cloud chain --apply`, installs, enrollments)
render a live terminal checklist, and PIN prompts use a desktop pop-up (also under `sudo`)
with a terminal fallback. Every action is also a command, and `--json` prints the controller's
result object for scripts.

```
$ avpn hops
• Chain  2-hop
  └ client → relay 198.51.100.80:443 → exit 203.0.113.80:4444

$ avpn doctor
• Doctor  11 passed · 0 failed
  ✓ trusted nft  /usr/sbin/nft
  ✓ keys bound to TPM2  sealed with host+tpm2; TPM2 usable now
  ...
```

`avpn help` lists every command and concept page; `avpn help COMMAND` shows one. The
same pages are in [`docs/cli/`](docs/cli/). [`docs/architecture.md`](docs/architecture.md)
explains how the pieces fit together.

- **Layering:** `avpn` renders results. The privileged controller (`avpnctl`) does all the work and validates every option.
- **Cloud:** `avpn cloud` finds free and low-cost places to run servers, provisions them with your own `aws`/`oci`/`az`/`fly` sign-in or pinned OpenTofu modules (or records servers you already have, over SSH), plans and enforces per-account monthly fee-guard caps (`avpn cloud cap`), checks fleet and account health on demand (`avpn cloud health`), unlocks TPM-less servers in RAM after a reboot (`avpn cloud unlock`), rotates exit addresses (`avpn cloud rotate`), and joins hops into one multi-hop chain.
- **Mesh:** `avpn mesh` browses the community directory, verifies gateway key consistency across independent beacons, contributes nodes and builds chains across members' servers ([`docs/cli/mesh.md`](docs/cli/mesh.md)).
- **Style:** the layout and colour rules follow the OpenAI Codex CLI's terminal style (Apache-2.0). Only the design rules were followed; no code was copied.

## Three tiers of setup

Pick how far to go. Each tier includes the one before it.

| | **1. General VPN** | **2. Hardened** | **3. Cypherpunk** |
|---|---|---|---|
| Who it's for | everyday privacy on any laptop | people a capable observer may target | people who want to trust as little hardware as they can (it reduces that trust, it cannot remove it) |
| Tunnel | post-quantum multi-hop chain, hardware-bound sessions, kill switch, Nitrokey unlock | plus a padded rate class (`fast` or higher), optional recursive exit DNS (`--dns-recursive`), and the wire clock (experimental) | plus I2P front (`--front i2p`) or Katzenpost PQ Sphinx mix lane (`avpn mix`), and DC-net cells for control events (a library today, not yet in a command), with one-time pad books handed over in person (information-theoretic only under stated source assumptions) |
| Servers | free cloud hops with mandatory fee-guard caps and TPM2 or operator-locked keys | hops on different providers and in different countries, administered via private bastions or Instance Connect Endpoints | hops on AMD (SEV-SNP where offered) or ARM, never all on one CPU vendor |
| Laptop | any | `avpn doctor` reports the Intel ME / AMD PSP state | Intel ME neutralized or absent (see below), or an AMD or ARM laptop |
| Randomness | the kernel | the kernel and the Nitrokey | plus assessed raw CPU-jitter entropy, extracted (`tools/padbook.py`), stored in deniable multi-layer stores (`tools/padstore.py`) |

**The Intel Management Engine.** Every Intel laptop since 2008 has an always-on coprocessor
with full access to memory; on vPro models with Intel AMT provisioned, it also reaches the
network on its own (what is enabled depends on the SKU, firmware and provisioning). AMD's
equivalent, the PSP, also has full memory access, but no network stack of its own, which
is why tier 3 prefers AMD. (Some AMD PRO business models offer remote management, DASH,
but it runs in the network card's firmware, not the PSP: choose a model without it.)
Neither choice makes hostile hardware safe: both coprocessors are privileged, and a
compromised endpoint (root, or the firmware) is outside this VPN's boundary. Tier 3
reduces what you must trust; it does not prove the absence of a backdoor.
- The ME cannot be removed, only reduced to running at boot. The proven tool is
  [me_cleaner](https://github.com/corna/me_cleaner) (with coreboot).
- me_cleaner lists the firmware it recognises: ME up to 11.x, TXE and SPS. Newer CSME
  versions (12 and later, about 2019 on) are not recognised.
- Writing the change normally needs an external SPI programmer: the ME region is usually
  locked against writes from the running system, and a bad image can brick the machine.
- `avpn` therefore never touches firmware. `avpn doctor` reports what it finds, read-only:
  the ME version and operating mode from the MEI driver, whether me_cleaner recognises
  that version, or AMD's PSP. The change itself is a manual, backed-up step the owner
  chooses.
- Simpler routes to tier 3: laptops sold with the ME disabled or coreboot installed
  (Purism, System76, NovaCustom, Star Labs), or AMD or ARM hardware.
- What `avpn doctor` reports about the coprocessor is informational, read from the
  driver: it is not hardware attestation.

## Getting started: free servers, one chain

After installing, `avpn` on a device that is not enrolled yet lists free and low-cost places to
run the servers (`avpn help endpoints`): Oracle Cloud Always Free (no expiry, 10 TB/month out,
9,000 GB cap) is the highest-capacity exit; the AWS free plan (6 months, 100 GB/month, 90 GB
cap) and Azure free account (100 GB/month, 90 GB cap, provisioned with Trusted Launch vTPM via
pinned OpenTofu) make good entry relays or exits on a second provider; and a **Fly.io Machine**
([docs/FLY_EXIT.md](docs/FLY_EXIT.md)) provides a lightweight 256 MB RAM-only IPv6 TCP exit
(~55 GB/month cap in Europe under Fly's <$5 monthly waiver).

```
avpn cloud suggest                                    # ranked, with your sign-ins checked
avpn cloud oci server --apply --name avpn-exit --bastion OCID   # or: fly server, azure server, or host add
avpn cloud aws relay --apply --name avpn-relay --profile P
avpn cloud chain --apply --client-request ~/advanced-vpn-client.req --vault VAULT
sudo avpn enroll ~/.config/advanced-vpn/chains/*/bundles/client.avpn --operator-key .../operator.pub --replace
sudo avpn connect
```

`chain --apply` plans and writes every server's monthly fee-guard cap first (refusing any
account without a recorded allowance), orders the servers (the largest allowance at the exit,
a different provider at the entry; it refuses the same provider at both ends without
`--allow-same-provider`), locks the relay's IPv6 egress to the next hop's `/128:port` when the
exit is IPv6-only, installs the packages, signs the bundles and unwraps any operator-locked
server keys in **one PIN + touch**, and starts them. Servers can be administered without public
SSH IP rules through an **AWS EC2 Instance Connect Endpoint** (`avpn cloud aws admin-endpoint`),
an **OCI Bastion** (`--bastion OCID`, with automatic 3-hour session renewal via `avpn cloud host bastion`),
an **Azure relay jump**, or the **Fly.io Machines API** (`tools/fly-ssh`, `tools/fly-scp`) so
your home or VPN address is only looked up when a hop's firewall actually needs it. The
first hop is open to any address on UDP/TCP 443, because the cloak and WireGuard never answer
a peer they were not enrolled with, so no provider's firewall configuration names you.
Providers still record who calls their API and see their own hop; `avpn help privacy` lists
exactly what each can see.

## Install

Each version tag publishes a release built by GitHub Actions: the binaries, tools and
reference pages in one package, with SHA256 checksums. The repository is public, so no
GitHub account is needed:

```bash
curl -fsSLO https://github.com/R1VER77/ADVANCED_VPN/releases/download/v0.10.2/SHA256SUMS
curl -fsSLO https://github.com/R1VER77/ADVANCED_VPN/releases/download/v0.10.2/advanced-vpn-v0.10.2-x86_64-linux-gnu.tar.gz
sha256sum -c SHA256SUMS
mkdir advanced-vpn && tar -C advanced-vpn -xzf advanced-vpn-v0.10.2-x86_64-linux-gnu.tar.gz && cd advanced-vpn
```

Releases are built from signed tags. Releases after v0.10.1 also carry a signed
build-provenance attestation (Sigstore) that names this repository, its release
workflow and the exact commit. The release workflow checks it before publishing; check
it yourself with
`gh attestation verify FILE -R R1VER77/ADVANCED_VPN --signer-workflow R1VER77/ADVANCED_VPN/.github/workflows/release.yml`.

There are two ways to install from there:
- **Command line only, for you (an operator machine):** `python3 tools/install.py --user`. It needs no root and starts no services. `avpn` goes in `~/.local/bin`, with its own hash-locked Python environment. It covers `avpn help`, `init` (with the Nitrokey), `cloud`, `mesh` and the read-only commands. Run it again to upgrade; `--user --uninstall` removes it.
- **The VPN itself (a client or a server), in one step:**

  ```bash
  sudo python3 tools/install.py --apply --role client --protect nitrokey
  ```

  This installs into `/opt/advanced-vpn` with the systemd units, which are never enabled. It also:
  - puts `avpn` on root's PATH, so `sudo avpn …` works;
  - creates this device's own Nitrokey vault in `/etc/advanced-vpn/vault` (PIN + touch);
  - generates the device's keys (PIN + touch again);
  - leaves the public request in your home directory as `advanced-vpn-client.req`.

  The operator signs that request (`avpn init`); then run `sudo avpn enroll BUNDLE --operator-key operator.pub` and `sudo avpn connect`. Running the same command again upgrades in place and never replaces existing keys.

  On a server (`relay`, `middle` or `exit`), the installer and `avpnctl request` (`tools/sealing.py`) enforce that keys are **sealed to a working TPM2 or locked to the operator's Nitrokey, never plain and never sealed with the host key alone** (whose secret sits on the same disk):
  - **with a usable TPM2** (systemd 250+, a TPM, the TSS2 libraries): `--protect systemd-creds`. The installer tests this first, by sealing and opening a throwaway credential, and refuses before installing if it does not work;
  - **without one** (Ubuntu 22.04's systemd 249, OCI's Always Free shapes, Fly.io Machines): `--protect operator --unlock-key FILE`, where FILE is the operator's unlock key (`avpn unlock-key` on the operator's computer). Each private key is encrypted under a fresh random data key wrapped to the operator's hybrid `X25519 + ML-KEM-768` unlock key; the unwrapped data key lives only in `/run` (RAM) and vanishes on reboot, so the server stays locked after every reboot until the operator unlocks it (`avpn cloud unlock NAME`; [design](docs/HARDWARE_BOUND_SESSIONS.md)). Existing plain or host-key-only server keys are replaced with new keys—never re-wrapped—at the next `chain`.

  `avpn cloud host setup` and `avpn cloud chain` make this choice for you.

Both need Python 3.10+ with `venv` (`sudo apt install python3-venv`). The release binaries are
built on Ubuntu 22.04 (glibc 2.34), so they run on Ubuntu 22.04+ and Debian 12/13 (`x86_64`, with `aarch64` CI and pinned runtime support).

To cut a release: bump `version` in `Cargo.toml`, commit, and push a matching tag
(`git tag -s v0.10.2 && git push origin v0.10.2`). The release workflow (`tools/release_gate.py`)
builds only if the tag matches the version and **every** `verify` run on that commit passed:
the tag's own run and the branch's. A cancelled run doesn't block, and a re-run that passes counts.
A public tag is never moved; a failed release is followed by the next patch version.

## Build and verify

Requires Linux, Rust 1.95.0, a C compiler/CMake, Python 3.12+, iproute2, nftables, ping and `/dev/net/tun`. Hardware operations additionally require a PIN-configured FIDO2 hmac-secret device and local pinentry (see [Hardware keys](#hardware-keys)).

```sh
cargo build --release --locked
uv venv .venv
uv pip install --python .venv/bin/python --require-hashes -r tools/hardware-requirements.txt
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
export PATH="$PWD/.venv/bin:$PATH"
cargo test --locked --lib --bin advanced-vpn
.venv/bin/python -m unittest discover -s tools -p 'test_*.py' -v

# Both tests refuse host-root execution or an inherited external interface.
# ML-DSA requires the hash-locked environment (cryptography 49), including for cargo test.
unshare -Urnm python3 tools/namespace_test.py --state /tmp/avpn-legacy-01
unshare --user --map-root-user --map-auto --net --mount python3 tools/managed_test.py --state /tmp/avpn-managed-01
unshare --user --map-root-user --map-auto --net --mount python3 tools/budget_test.py --state /tmp/avpn-budget-01
unshare --user --map-root-user --map-auto --net --mount python3 tools/server_egress_test.py

# Symbolic and bounded formal proofs (Tamarin 1.12.0 + Maude 3.5.1, ProVerif 2.05, Kani):
python3 tools/tamarin_check.py
python3 tools/proverif_check.py
python3 tools/formal_model_vectors.py

# Installed units, reboot guard ordering, impaired links and a disconnect soak in three
# local KVM guests (Debian 13 genericcloud image; host networking is not changed).
python3 tools/vm_validation.py --base debian-13-genericcloud-amd64.qcow2 --work /tmp/avpn-vm-01
```

The managed test exercises actual WireGuard/DAITA, both PQ layers, TCP and UDP paced server links, server fee-guard caps and egress locks, system DNS over an isolated TLS upstream, NAT, IPv4/IPv6 and WebRTC/STUN leak blocking, certificate rotation, hardware-bound session authorization, the defense profile, crashes, recovery, and explicit unlock. It first demonstrates a working unencrypted fallback route, then verifies that the whole-device guard blocks it. All network/DNS changes are confined to disposable namespaces. See [current validation](docs/MANAGED_VALIDATION.md).

## Hardware keys

The Nitrokey is an example, not a requirement. `--protect nitrokey` works with **any FIDO2 (CTAP2) security key that supports the `hmac-secret` extension and verifies you**, with a PIN typed on the computer or on the key's own screen (as on a Trezor or unlocked Ledger): the key releases a secret and signs the session authorization only after that and a touch. Only one such key may be plugged in while you unlock. Enrollment requests no attestation (`attestation="none"`) and publishes only the credential's bare COSE public key. The private local vault retains the credential handle, salt and counter needed to unlock. Setup diagnostics read USB identification and protocol capabilities for compatibility checks; these are not hardware attestation.

Every supported key is ranked by `tools/hwkey.py` (`tier`, `rank`, `usb_channel`): open-source firmware is **cypherpunk-preferred** over closed firmware, and entering the PIN on the device itself ranks above typing it on the computer ([device compatibility and ranking](docs/DEVICE_COMPATIBILITY_VALIDATION.md)). Every FIDO2 key's local USB PIN/UV channel uses P-256 ECDH (CTAP PIN/UV protocols 1 and 2) and is flagged on all tiers rather than blocking.

Fully open-source firmware (Cypherpunk-preferred, Ranks 1–2):

| Rank | Key | Open source | `hmac-secret` & VPN operations | Notes |
|---|---|---|---|---|
| **1** | **Trezor** (Safe 3, Safe 5, Safe 7, Model T) | firmware and hardware (Safe models add a closed secure element) | ✅ **physically tested** (Safe 3, fw 2.12.1) | You confirm and enter the PIN on the Trezor's own screen (`uv: true`, no `clientPin`), so the PIN never reaches the laptop. Creates Ed25519 credentials (tested). FIDO2 secrets derive from the wallet's recovery phrase. (Trezor One is U2F-only and refused.) |
| **2** | **Nitrokey 3** | firmware and hardware | ✅ **physically tested** (fw 1.8.3) | The key this project is developed with and runs on the live chain. Creates Ed25519 credentials and signs hardware-bound sessions (tested). |
| **2** | **SoloKeys Solo 2** | firmware and hardware | ✅ **verified in firmware lab** (`45311f0`, CTAPHID-over-UDP host) | Verified for Ed25519, two-salt `hmac-secret` (protocol 2), operator dual signatures, and hardware-bound sessions ([evidence](docs/evidence/SOLO2_PC_VPN_OPERATIONS_20261119.json)). The Hacker build also offers FIDO2 **ML-DSA-44 (`COSE -48`)** credentials, verified in emulation as an optional **third operator signature half** (`--pq-vault`). |
| **2** | **SoloKeys Solo 1** | firmware and hardware | ✅ **verified in firmware lab** (`fc8d286`) | Verified for Ed25519, `hmac-secret`, operator dual signatures, and hardware-bound sessions ([evidence](docs/evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json)). |
| **2** | **CanoKey** (Pigeon / STM32) | firmware and hardware | ✅ **verified in firmware lab** (`canokey-core a349b26`, USB `20A0:42D4`) | Verified for Ed25519, two-salt `hmac-secret`, operator dual signatures, and hardware-bound sessions ([evidence](docs/evidence/CANOKEY_UDP_VPN_OPERATIONS_20261119.json)). |
| **2** | **Tillitis TKey** (`tkey-fido2`) | firmware and hardware (FPGA) | ✅ **verified in firmware lab** (`tkey-fido2 7fdf8ea` on QEMU Castor, USB `1207:8887`) | Verified for Ed25519, two-salt `hmac-secret`, operator dual signatures, and hardware-bound sessions ([evidence](docs/evidence/TKEY_QEMU_VPN_OPERATIONS_20261119.json)). `keyguard` automatically negotiates CTAP PIN/UV protocol 1 for the TKey AAGUID because `tkey-fido2`'s `hmac-secret` refuses protocol-2 salts. |

Closed firmware, and still usable (Ranks 3–4):

| Rank | Key | `hmac-secret` & VPN operations | Notes |
|---|---|---|---|
| **3** | **Ledger** (Security Key app) | ✅ **physically tested** (Nano S Plus, app 1.7.8) | Unlock the Ledger and keep the Security Key app open (a locked Ledger answers as U2F-only and is refused). Confirm on its screen and **do not set a FIDO2 client PIN** so verification stays on the device's own PIN. Creates Ed25519 credentials (tested). The app is open source; the OS and secure element firmware are not. |
| **4** | **YubiKey 5** series | ✅ **physically tested** (5C NFC, fw 5.2.7); needs fw 5.2.3+ | Creates Ed25519 credentials (tested). Firmware cannot be inspected or updated; below 5.7 it is affected by EUCLEAK (CVE-2024-45678), a physical side channel against P-256 signing, so prefer an Ed25519 credential. |
| **5** (unranked) | **OnlyKey**, **BitBox02**, **Google Titan** (v2/v3), **Feitian**, **Token2** | not confirmed | Other FIDO2 keys that pass the runtime `hmac-secret` and user-verification check are supported and reported as `unranked` until their firmware and USB IDs are verified from primary sources ([validation inventory](docs/DEVICE_COMPATIBILITY_VALIDATION.md)). |

**Curve.** Setup requests and verifies an Ed25519 (`SafeCurves`) signing credential when the key supports it, records the actual stored COSE algorithm per credential, and never silently falls back when an explicit algorithm is requested.

**Not usable:** U2F-only keys (Trezor One, the first Google Titan, YubiKey 4 and NEO, HyperFIDO Pro, many older keys), and any key that verifies no one (no PIN, no on-device check).

**Setup validation (17–19 November 2026):** the physical Nitrokey 3, YubiKey 5C NFC, Trezor Safe 3 and Ledger Nano S Plus units passed a disposable vault round trip using a fresh hardware assertion, real missing-access detection, the confirmed udev repair and restoration of original rules/access ([physical results](docs/evidence/SETUP_HARDWARE_20261117.json), [test procedure](docs/HARDWARE_SETUP_TESTS.md)), and the YubiKey passed disabled-USB-FIDO2 detection and enable-only repair. Solo 1, Solo 2, CanoKey and Tillitis TKey passed the full production-crypto and hardware-bound session suite in the [firmware lab](docs/HARDWARE_FIRMWARE_LAB.md).

**Check any key** before relying on it (libfido2's tools): `fido2-token -I /dev/hidrawN` must list `hmac-secret` under extensions, and either `clientPin` as set or `uv` (on-device verification). `avpn request --protect nitrokey` refuses a key that lacks them.

**Without a hardware key on a client or server:** on servers, `--protect systemd-creds` seals keys with a verified TPM2, and `--protect operator --unlock-key FILE` locks them to the operator's Nitrokey when the server has no TPM2 (plain or host-key-only server keys are refused). On a client without a token or TPM2, `--protect none` keeps keys in plaintext only when explicitly passed `--insecure-plaintext-keys`.

## One-time enrollment, then connect

First stage the native package; staging does not install or activate anything:

```sh
python3 tools/install.py --out /tmp/new-avpn-package
```

An operator can install with `sudo python3 tools/install.py --out /path/to/new-stage --apply`. Installation creates `/opt/advanced-vpn`, a hash-locked Python environment and service files, but **does not enable them**. Review [deployment](docs/DEPLOYMENT.md) before activation.

Designed for one person running their own client, relay and exit from the command line — and, through AVPN/Mesh, for a community of such people contributing one server each (see below). **Every device generates its own private keys, and no private key ever leaves the device it was made on.** Your laptop, with the Nitrokey, is both the client and the operator.

1. On each device, generate its keys and write a public request. The laptop seals its keys with the Nitrokey (and includes its FIDO2 device public key for hardware-bound sessions), so they're never written in plaintext. Servers seal to their TPM2 (`systemd-creds`) or lock to the operator's Nitrokey unlock key (`--protect operator --unlock-key operator-unlock.pub`).

```sh
# laptop (client): PIN + touch
sudo /opt/advanced-vpn/bin/avpn request --role client --protect nitrokey --vault ~/.config/advanced-vpn/vault --out client.req
# relay with a TPM2, and exit without a TPM2 (locked to the operator's Nitrokey)
sudo /opt/advanced-vpn/bin/avpn request --role relay --protect systemd-creds --out relay.req
sudo /opt/advanced-vpn/bin/avpn request --role exit  --protect operator --unlock-key operator-unlock.pub --out exit.req
```

2. Copy only `relay.req` and `exit.req` to the laptop. They contain public keys only (plus the exit's KEM-wrapped data key). Then sign all three bundles (and optionally emit the locked server's unwrap token) in **one PIN + touch**:

```sh
/opt/advanced-vpn/bin/avpn init --out ./enrollment --vault ~/.config/advanced-vpn/vault \
  --allowance-gib 90 --relay 192.0.2.10:443 --exit 198.51.100.20:4444 \
  --request client=client.req --request relay=relay.req --request exit=exit.req
```

Replace the documentation IP addresses with your own.
- The classical half of the signature is made by the hardware key's FIDO2 credential (Ed25519 or P-256, whichever the key creates), whose private key can't be exported.
- The ML-DSA-65 half is an operator key that stays sealed under that same credential, created on the first `init`. It is in plaintext only in memory, during that one touch.
- An optional **third operator half** (`--pq-vault PQ_DIR`, enrolled via `keyguard enroll-pq-signer`) adds a hardware **ML-DSA-44 (`COSE -48`)** FIDO2 signature from a separate security key (schema-3 `operator.pub`), requiring all three signatures at enrollment.
- Bundles contain public data only, plus the WireGuard and hop-link PSKs, which are encrypted separately to each recipient with hybrid X25519 + ML-KEM-768.

3. Copy each bundle and `operator.pub` to its device, then enroll and connect:

```sh
sudo /opt/advanced-vpn/bin/avpn enroll client.avpn --operator-key operator.pub   # PIN + touch on the laptop
sudo /opt/advanced-vpn/bin/avpn connect                                          # PIN + touch authorizes the <=12 h session
```

Enrollment checks:
- **all required** operator signatures (classical + ML-DSA-65, and ML-DSA-44 when schema 3 is used);
- that the bundle names this device's own keys, so a bundle made for another device is refused;
- the PSK, which it decrypts and stores under the device's protection.

It then deletes the one-time KEM key. `init` keeps no device private keys, and there are no CA keys.

**Recovery:** if a device or the Nitrokey is lost, run `request` → `init` → `enroll` again. Keys are cheap to regenerate, so the tool doesn't keep backups of them.

The default client protects explicitly launched applications and can coexist with an existing host VPN:

```sh
sudo /opt/advanced-vpn/bin/avpn run -- curl https://example.com
avpn status
sudo /opt/advanced-vpn/bin/avpn preferences --defense strong --rate fast
sudo /opt/advanced-vpn/bin/avpn preferences --daily-limit-mib 1024   # optional fail-closed cap
sudo /opt/advanced-vpn/bin/avpn preferences --no-daily-limit         # default
```

Whole-device mode is explicit. Test from a local console on the target OS, and first stop any conflicting VPN through its own controls:

```sh
sudo /opt/advanced-vpn/bin/avpn preferences --mode whole-device
sudo systemctl enable --now advanced-vpn-guard.service advanced-vpn.service
```

The early guard unit precedes normal networking services. Its boot ordering must still be validated on the actual distribution, including any initramfs networking. The build/test process never enables it on the development laptop.

`disconnect` leaves traffic blocked (and also stops a foreground supervisor started with `connect --foreground`). After disconnecting, `reset --allow-cleartext` explicitly restores recorded routes/DNS and removes this project's guard; enabled boot services can rearm it at the next start. Ordinary disconnect never silently restores a direct route.

## One, two or three hops

| Mode | Path | What each server can see |
|---|---|---|
| `--hops 1` | client → exit | The exit sees both your IP and your destinations. |
| `--hops 2` (default) | client → relay → exit | The relay sees your IP (unless `--front i2p` is used) but only ciphertext; the exit sees destinations but only the relay. |
| `--hops 3` | client → relay → middle → exit | Each server sees only its neighbours. Neither the relay nor the exit sees both ends, and the middle sees neither. (3 hops is the confirmed chain ceiling, decision D013.) |

How the layers work:
- There is one post-quantum QUIC layer per server, wrapped inside each other like an onion. Each layer uses X25519 + ML-KEM-768 key exchange, ML-DSA-65 authentication, and (for hardware-protected clients) the pinned FIDO2 key's per-session hardware authorization.
- WireGuard + DAITA runs between the client and the first hop; every link between two servers is a paced, encrypted constant-rate link (per-hop shaping, `src/link.rs`, 1,242-byte cells over UDP or over TCP with `--link-transport tcp` for IPv6-only/TCP-only exits), keyed by a link key the operator seals to both servers and re-keyed every 120 seconds with an ephemeral in-cell X25519 + ML-KEM-768 exchange.
- Each server removes exactly one layer and forwards the rest to the next hop it was enrolled with. The client knows only the first hop's address.
- **Standby exits** (`init --standby-exit NAME=IP:PORT`): the server before the exit fails over to a live standby within seconds when the exit goes silent, and rotates sessions among live exits in a signed window (default 15–60 minutes); your entry, the guard, never changes. Lab (v0.8.0, 12 Nov 2026): 4.2 s outage, no leak ([FAILOVER.json](docs/evidence/FAILOVER.json)).
- QUIC needs at least 1200 bytes of UDP payload per layer, so the layers are budgeted from the inside out: 1312, 1256 and 1200 bytes, all inside the 1340-byte WireGuard MTU. Apps see the same inner MTU of 1100 bytes in every mode.

```sh
# middle relay (three hops only): its own keys, like every device
sudo /opt/advanced-vpn/bin/avpn request --role middle --protect systemd-creds --out middle.req
# laptop: sign a chain (one PIN + touch)
/opt/advanced-vpn/bin/avpn init --hops 3 --out ./chain3 --vault ~/.config/advanced-vpn/vault \
  --allowance-gib 90 --relay 192.0.2.10:443 --middle 198.18.0.20:4445 --exit 198.51.100.20:4444 \
  --request client=client.req --request relay=relay.req --request middle=middle.req --request exit=exit.req
```

**Switching modes** reuses every device's keys:
1. Run `init` again with another `--hops` value and the same requests.
2. On each device in the new chain, run `sudo avpn disconnect`, then `sudo avpn enroll <bundle> --operator-key operator.pub --replace`, then `connect`.

Traffic stays blocked while you switch. In single-hop mode, give `--exit` the exit's port-443 endpoint: it is then the first hop. For an IPv6-only TCP exit (such as Fly.io), pass `--link-transport tcp` and `--exit [2001:db8::1]:4444`.

```sh
# a standby exit: give its request under its name; the relay fails over and rotates
/opt/advanced-vpn/bin/avpn init --hops 2 --out ./chain2 --vault ~/.config/advanced-vpn/vault \
  --allowance-gib 90 --relay 192.0.2.10:443 --exit 198.51.100.20:4444 --standby-exit exit2=198.51.100.30:4444 \
  --request client=client.req --request relay=relay.req --request exit=exit.req --request exit2=exit2.req
```

Measured on v0.10.1 in the namespace benchmark (`tools/throughput_bench.py --rate line --mib 32 --shape-idle 5`, SHA-checked, medians of 3–5 runs; `docs/evidence/RATE_CLASSES_v0_10_1.json`, 14 Nov 2026):

| Hops | Throughput (`line` class) |
|---|---|
| 1 | about 124 Mbit/s |
| 2 | about 115 Mbit/s |
| 3 | about 115 Mbit/s |

Every run also proves two things on the wire. Raw packet observers on each server's ingress never see the payload, and only the first hop ever sees the client's address. The same runs check that no server writes anything persistent while carrying traffic. CI enforces all three.

## The community mesh (AVPN/Mesh)

`cypherpunk_vpn` is becoming a community mesh: every member contributes at least one server — an always-free cloud VM is enough, protected against unexpected bills by the mandatory server-side [fee guard](docs/FEE_GUARD.md), and `avpn mesh offer --guided` ranks the options (Oracle Cloud Always Free first, ~10 TB/month egress) and provisions through the existing cloud machinery — and in return can build chains across nodes contributed by other members, browsable and selectable from the CLI:

```
avpn mesh nodes --fetch          # the directory: roles, providers, latency, uptime, concentration
avpn mesh chain --hops 3         # every hop a distinct operator, provider and country
avpn mesh quota                  # credits earned relaying vs spent on chains
```

There is **no account anywhere**: a member is their hardware device — an open-source FIDO2 token by preference. The member ID is the hash of the device public key; the private key never leaves the token, and mesh descriptors are signed with the operator's `operator-mldsa65` key (`mesh-sign --role`) and carry typed `exit_policy` and `streaming` fields validated identically by the Python control plane and every Rust node (`tests/fixtures/descriptor_fields.json`). Nodes can also be kept private (`avpn mesh offer --private`, `tools/mesh_voprf.py`), usable only by you or an invited group. Defense is strong-only and per-hop: the client's link runs the constant-rate carrier stream and every server-to-server link a paced, encrypted constant-rate stream; your own node is your entry, and the exit must answer to another legal sphere than the entry.

Control-plane requests travel over **Oblivious HTTP (HPKE `X25519 + ML-KEM-768`)** with two anti-correlation defenses enforced in code and proved in ProVerif 2.05 (`formal/ohttp/ohttp_unlinkability.pv`):
- **Gateway key consistency (RFC 9458 §7):** a beacon signs `ohttp_gateway` into its descriptor (`avpn mesh publish --gateway-key`), and a member uses an OHTTP route beyond directory fetches only after at least two other independent beacons present that same signed key; key equivocation is refused (`tools/test_gateway_consistency.py`).
- **Relay-clock timestamp bucketing:** requests carry a 30-second bucket of the entry relay's `Date` header (`GET /time`, refreshed on each answer), so client clock skew cannot link requests and no third-party time server is polled from your host.

The contribution economy uses unlinkable blind-signed credits (Chaum RSA-FDH in `tools/mesh_tokens.py`, with RFC 9474 Finalize verification against issuer tagging attacks, daily epoch keys, an inflation alarm, and ProVerif unlinkability proofs in `formal/credits/credits_unlinkability.pv`), alongside newly implemented RFC 9497 `ristretto255` VOPRF and blind vouchers (`tools/voprf.py`, `tools/voucher.py`), a two-server XOR/DPF Private Information Retrieval (PIR) directory (`tools/pir_directory.py`), and a hash-based post-quantum STARK membership prototype (`docs/ZK_MEMBERSHIP_DESIGN.md`, forward-private nullifiers bound to `SHA-256(request)` in `tools/zkid.py`). See [docs/MESH_DESIGN.md](docs/MESH_DESIGN.md) and [docs/cli/mesh.md](docs/cli/mesh.md).

## No retained data

Like Mullvad, servers are built to hold nothing that could be handed over:
- **No accounts, no logs.** Process output goes to `/dev/null`, and `LogLevelMax=emerg` (or the silent `deploy/fly/init.sh` supervisor on Fly.io) stops even the service manager from logging start and stop times for the VPN units.
- **Everything written while running lives in RAM** (`/run/advanced-vpn/`): status, PIDs, locks, unwrapped operator data keys, rotated certificates, carrier counters and the resolver file.
- **A server's persistent disk holds only its enrollment and one aggregate monthly byte counter:** keys (TPM2-sealed or encrypted under an operator-locked data key), pins, peer addresses, and the fee guard's single host-wide monthly outbound integer (rounded up to 16 MiB, with no per-member, per-session, per-destination or timestamp record).
- **The daily data cap is client-only,** so no server stores per-user byte counts.
- **The DNS forwarder** logs and caches nothing.
- **Flow state** (kernel conntrack and WireGuard handshakes) exists only in RAM, while a session is active.

In installed Debian 13 VMs, after real traffic, the relay and exit had **written no files** under `/etc/advanced-vpn` and had **no journal entries** for the VPN units. The client keeps only its own preferences and a pre-VPN network snapshot, which it needs to restore its routes after a reboot.

**Zero-knowledge proofs aren't used in the single-operator design, and nothing there needs them.** Mullvad and Nym use ZK credentials to separate a paying account from what that account does on someone else's servers. With one person owning every device and every hop, there's no account or payment to unlink. AVPN/Mesh is the point where that changes: once strangers use each other's servers, usage must be decoupled from identity, so mesh contribution credits use blind signatures and VOPRF tokens today ([docs/MESH_DESIGN.md](docs/MESH_DESIGN.md)), and the v1.0 design replaces them with zero-knowledge membership proofs as hash-based STARKs with forward-private nullifiers bound to the authorized request ([docs/ZK_MEMBERSHIP_DESIGN.md](docs/ZK_MEMBERSHIP_DESIGN.md)).

## Key exposure

| Stage | Where private keys exist |
|---|---|
| Generation (`request`) | Only on the device. Nitrokey mode seals before writing (no plaintext file). Server `systemd-creds` mode tests and seals with the TPM2 (refusing if unavailable). Server `operator` mode encrypts each key under a random AES-256-GCM data key wrapped by hybrid `X25519 + ML-KEM-768` to the operator's Nitrokey unlock key (`avpn unlock-key`) and never stores the data key on disk. Client `none` mode requires explicit `--insecure-plaintext-keys` (`0600`). |
| Operator (`init`) | No device key. The FIDO2 classical key (and optional second-key ML-DSA-44 key) never leaves the token. The operator ML-DSA-65 key (and unlock key when `--emit-unlock` is used) is unsealed in memory for one signing operation. |
| Transfer | Requests and bundles carry public data only. The WireGuard PSK, link PSKs, and operator-locked server data keys are encrypted with hybrid X25519 + ML-KEM-768 to each recipient. |
| Session signing (`session_signer.py`, Phase 2) | On a hardware-protected client, only the short-lived, undumpable (`PR_SET_DUMPABLE=0`, core dumps off, `mlockall`) signer process unseals the long-term ML-DSA-65 TLS identities during the connect/renewal PIN + touch, certifies fresh per-session ML-DSA-65 layer keys alongside the FIDO2 hardware session statement (≤12 h), and exits immediately. |
| Running | The running supervisor and data-plane processes hold **no long-term ML-DSA-65 identity keys** on hardware-protected clients — only the per-session TLS keys (plus the carrier keys, which reach only the entry's outer carrier; [design](docs/HARDWARE_BOUND_SESSIONS.md)). Keys pass through immutable memory descriptors (`memfd`) into network daemons confined by seccomp-BPF, Landlock, non-root UID, zero capabilities, `PR_SET_DUMPABLE=0` and no swap. On operator-locked servers, the unwrapped data key lives only in `/run` (RAM) until reboot. |

The active session's traffic keys (WireGuard X25519 and the per-session ML-DSA-65 TLS keys) are used for handshakes and packet encryption, so they must reside in endpoint RAM while the session runs. Root, the kernel or a hypervisor on that endpoint can read active session memory, and dumping a single-hop VPN server captures both the client's IP and traffic keys at once — whereas across a 2- or 3-hop chain, a live memory dump of the relay holds only inner post-quantum ciphertext (never the inner keys), a dump of the exit holds no client IP address, and stolen client session keys expire at the end of their ≤12-hour hardware-authorized window (proved in Tamarin: `stolen_session_key_expires`). Python can't guarantee memory is wiped (though `padbook.py` and `session_signer.py` zero buffers in place and disable dumps; `tools/test_secret_review.py` audits secret handling), and deleting a file doesn't erase old disk blocks. Use encrypted disks.

Cold start with a Nitrokey-sealed client needs the PIN and a touch:
- **In a desktop session (including under `sudo`),** a desktop PIN pop-up appears, with a terminal fallback.
- **In a terminal without a display,** `avpn` asks on the command line.
- **As a service, including whole-device mode at boot,** it asks through systemd's password agents. The prompt appears on the boot console, as a disk-encryption passphrase does, or you answer it from any terminal with `sudo avpn unlock`. The PIN is never cached in the kernel keyring; within a single multi-step CLI command it is held in memory for that command only and dropped on any error.

If nobody answers, the prompt times out after 5 minutes. The service restarts and asks again, and traffic stays blocked the whole time.

## Limits and provenance

The relay/provider can still observe addresses, sizes, timing and outages. The owned exit sees traffic after VPN decryption; HTTPS retains its independent TLS. In a single-owner deployment, the exit's cloud provider knows its account holder by billing, and a Fly.io exit shares Fly's host-level outgoing IPv4 NAT address with other customers on that host (which can move when Fly migrates the Machine; [docs/FLY_EXIT.md](docs/FLY_EXIT.md)). Streaming eligibility (`avpn stream-check`, [docs/STREAMING_GEO_PARITY_20261120.md](docs/STREAMING_GEO_PARITY_20261120.md), decision D014) is recorded only as a dated measurement with its transport profile, never as an unblocking promise. No provider-no-logging, anonymity, TEE attestation, WAN-performance or independent-audit guarantee is made.

A global passive adversary remains out of scope for any low-latency system, ours included; per-hop defense raises its cost, it does not produce mixnet-grade unlinkability. For traffic that can wait seconds, the mix lane (`avpn mix`, Katzenpost) does: with live websites such an adversary named 10.7% of senders on the mix lane against 88.2% on a low-latency path (chance 10%, post-quantum X-Wing Sphinx, `docs/evidence/MIX_LANE.json`). The mix lane's at-chance protection is a property of the delay and rate together, not of one bandwidth number (parameter sweep, v0.10.2, 10 clients, `docs/evidence/MIX_LANE_SWEEP.json`): at 200 ms mean delay per hop the adversary stays at chance down to half the client uplink (~287 kbit/s, 11.6% [7.9–15.2] against a 10% chance), and doubling the payload rate buys a shorter queue, not weaker protection (9.1% at ~917 kbit/s); but half the uplink **with** 100 ms delays leaks above chance (12.8% [10.5–15.1]). Shorter delays are therefore only safe at the full rate, and slower links only at the full delay. An I2P front (`avpn init --front i2p`) keeps your address from the entry and its provider (`docs/evidence/I2P_FRONT.json`), though I2P's internal tunnel routing remains classical (exception 2 in [docs/PQ_INVENTORY.md](docs/PQ_INVENTORY.md)). On real websites, the low-latency carrier's experimental wire clock brought k-FP accuracy to near chance (3.8–8.3% vs 100% undefended, Holm p ≥ 0.18) in the 20 November frozen 720-attempt replication ([docs/WF_REPLICATION.md](docs/WF_REPLICATION.md)), but failed the local promotion gate on 95% upper bounds (up to 12.1%), page-load success non-inferiority (−6.3 to −7.1 points) and two brief unprotected sample windows; wire-clock controls therefore remain opt-in and do not cover the TCP/TLS fallback or the I2P front.

DNS offers two explicit post-quantum / privacy trade-offs ([docs/PQ_INVENTORY.md](docs/PQ_INVENTORY.md) exceptions 4 and 5):
- **Default (`advanced-vpn-dns` DoT forwarder):** the exit forwards lookups only over TLS 1.3 with the hybrid `X25519MLKEM768` group and fails closed otherwise. Because few public resolvers offer the hybrid group today, the default upstream is Cloudflare (`1.1.1.1:853`; Google also works), which concentrates your lookups at one provider (seeing them from your exit's IP, never yours) and authenticates the resolver with classical WebPKI certificates (exception 4).
- **Opt-in exit recursive resolver (`avpn init --dns-recursive`, `tools/exit_resolver.py`):** the exit runs its own local Unbound resolver with DNSSEC validation and QNAME minimisation (verified live on 20/20 domains with `dnssec-failed.org` refused), removing any central public DNS provider. Those queries leave from the exit to authoritative DNS servers as plain DNS authenticated by classical DNSSEC (exception 5).

**Formal verification, bounded model checking and fuzzing ([formal/README.md](formal/README.md), [docs/VERIFICATION_PLAN.md](docs/VERIFICATION_PLAN.md)):**
- **Tamarin 1.12.0 (16 symbolic models, 57 verified lemmas, 26 falsified mutants in CI, `docs/evidence/TAMARIN.json`):** covers DC-net frame authenticity/decoding/collusion bounds, mix-lane re-blinding, cloak v2 mutual channel/role-bound proofs, hop-link hybrid forward secrecy (safe after a PSK leak unless both X25519 and ML-KEM are broken for that session), hybrid `kem_seal`, OHTTP response binding, credit redemption, dual-signature enrollment, and Phase 1/2 hardware-bound sessions (`stolen_session_key_expires`), each pinned to production crypto vectors by `tools/formal_model_vectors.py`.
- **ProVerif 2.05 (`tools/proverif_check.py`, `docs/evidence/PROVERIF.json`):** proves observational equivalence (unlinkability) for OHTTP requests against the gateway and for blind-credit issuance/spending against the ledger (after closing an issuer multiplicative-tagging attack via RFC 9474 Finalize verification).
- **Kani & CI fuzzing:** `crates/avpn-kani` (`src/link_bounds.rs`, 4 mutants caught) proves the hop link's replay window and reply-credit invariants on the Rust code; five `cargo-fuzz` targets and the Python mutation fuzzer test all external byte parsers in CI.
- **Scope caveats:** every symbolic proof holds only within the abstractions and assumptions stated in [formal/README.md](formal/README.md) (for example, credit `no_double_spend` assumes a single shared `Ledger` spent set across relays, OHTTP freshness is modelled as a restriction, and symbolic models do not prove timing or side-channel immunity).

`src/dcnet.rs` is a tested DC-net round core for anonymous mesh control events (72-bit truncated SHA-256 event integrity, end-to-end cell lab in `tools/dcnet_cell_lab.py`, deniable multi-layer storage in `tools/padstore.py` v2 with copy-on-write dual headers and Elligator 2 envelopes in `tools/elligator.py`, plus DLEQ batch, authenticated event-effect and jamming/fallback validation in `tools/dcnet_validation.py`). No VPN command calls it yet. Its one-time-pad construction supports information-theoretic sender anonymity within an honest group connected by jointly secret, uniform, never-reused pad edges. The current generator (`tools/padbook.py`) combines kernel/Nitrokey output (whose internal RNG was verified in firmware source to be a once-per-boot seeded ChaCha8 stream, hence computational alone) with assessed raw CPU-jitter noise (NIST SP 800-90B `ea_non_iid` + Toeplitz extractor); it has not established the required joint entropy, independent extractor-seed and physical custody assumptions. Its `conditional-information-theoretic` label records declared provenance, not qualification. Network-seeded hash chains remain computational. See the [design](docs/DCNET_CONTROL_DESIGN.md), [paper and implementation review](docs/INFORMATION_THEORETIC_REVIEW_20261117.md), and [pad exposure validation guide](docs/PAD_EXPOSURE_VALIDATION.md) for the precise passive-round claim and remaining gates. This does not qualify the VPN as information-theoretically secure.

The proposed four-plane architecture is documented in the
[CYPHERPUNKS research specification](docs/CYPHERPUNKS_PROTOCOL_SPECIFICATION.md).
While the RFC 9497 `ristretto255` VOPRF and voucher modules (`tools/voprf.py`, `tools/voucher.py`, `tools/mesh_voprf.py`), the two-server XOR/DPF PIR directory (`tools/pir_directory.py`), the full-tree curve inventory (`tools/curve_inventory.py`) and secret-handling audit (`tools/secret_review.py`) are now implemented and unit-tested in the tree, synthetic/reference benchmarks do not qualify live traffic immunity, post-quantum voucher unlinkability proofs, deployed multi-operator DPF network timings or production throughput. See the [18 November artifact review](docs/RESEARCH_REVIEW_20261118.md) and [roadmap §6](docs/ROADMAP.md#6-cypherpunks-research-qualification) for incorporation decisions and the remaining qualification gates.

Inside the client tunnel, traffic is currently Linux/IPv4 only while **client-side IPv6 is deliberately blocked fail-closed** in every mode so it cannot escape around the tunnel — verified by the 19-gate dual-stack IPv6 leak suite (`tools/ipv6_leak_suite.py`; native inside-tunnel IPv6 is designed and staged in [docs/IPV6_TUNNELING_DESIGN.md](docs/IPV6_TUNNELING_DESIGN.md), decision D009). **Between servers**, IPv6 is supported today: paced server-to-server links run over IPv6 TCP (`avpn init --link-transport tcp`) to IPv6-only exits such as Fly.io, and the server-side egress lock and fee-guard quota enforce `inet` rules across both IPv4 and IPv6 ([docs/FEE_GUARD.md](docs/FEE_GUARD.md)). The managed profile uses inner MTU 1100 and WireGuard MTU 1340; HTTP/3 QUIC cloak requires an IPv4 underlay MTU of at least 1448 bytes, automatically falls back to TLS 1.3 over TCP 443 on paths between 576 and 1447 bytes, and refuses to connect below 576 bytes with the kill switch held. The native Linux GUI, OpenTofu onboarding, router deployment target designs ([GL.iNet GL-MT6000/GL-MT3000](docs/ROUTER_DEPLOYMENT.md), decision D010) and [Tor-over-the-tunnel recipe](docs/TOR_RECIPE.md) (decision D012) still require packaged-release, hardware-in-the-loop and full-onboarding qualification. The standalone v0.1 QUIC interface remains available; see [historical interface](docs/LEGACY_QUIC.md).

Current project terms are in [LICENSE](LICENSE), under **GNU AGPL-3.0-or-later** with the Cypherpunk Hardware Linking Exception and Commercial Dual-Licensing Terms ([docs/REVENUE_ARCHITECTURE.md](docs/REVENUE_ARCHITECTURE.md)). Historical file provenance remains documented separately. Vendored GotaTun (`vendor/gotatun`, modified for strict-blocking stall recovery) is an MPL-2.0 dependency; Maybenot components are MIT/Apache-2.0; Katzenpost mix-lane binaries run as separate unmodified AGPL-3.0 processes; `i2pd` runs as a separate unmodified BSD-3-Clause daemon. See [provenance](docs/PROVENANCE.md) and [upstream source/notice information](third_party/SOURCES.json). No VP.NET implementation was copied or ported; this is not represented as a clean-room project.

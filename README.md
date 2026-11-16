<p align="center">
  <img src="docs/assets/cypherpunk-vpn-logo.png" alt="Cypherpunk VPN" width="520" />
</p>

# ADVANCED_VPN — managed Linux client

A Rust VPN data plane with signed enrollment, automatic networking, a persistent kill switch, DNS isolation, real GotaTun/Maybenot DAITA on your link to the first hop and paced, encrypted constant-rate links between every pair of servers behind it, and the original two hybrid post-quantum QUIC layers. The cloud relay never holds the inner tunnel keys. No existing VPN is automatically replaced during build or installation.

```mermaid
flowchart LR
    App[Protected applications] --> Client[Client]
    Client <-->|WireGuard + DAITA; two PQ layers inside| Relay[Cloud relay]
    Relay <-->|Inner PQ ciphertext| Exit[Owned exit]
    Exit --> Internet[Destination]
```

WireGuard is the outer carrier, implemented by **GotaTun 0.10.2**, with its actual DAITA integration and public **Maybenot 2.2.2** defense machines. Its ChaCha20-Poly1305 encryption and 256-bit PSK supplement the existing **two TLS 1.3 X25519 + ML-KEM-768 / AES-256-GCM layers**. WireGuard alone is not advertised as native ML-KEM. Authentication is post-quantum too: both QUIC layers accept **only ML-DSA-65** (FIPS 204) certificate chains and TLS 1.3 CertificateVerify signatures, and operator enrollment bundles carry a **hybrid Ed25519 + ML-DSA-65** signature pair that must both verify. A correctly pinned classical (ECDSA) deployment is refused; the Rust tests prove this and fail if the restriction is removed. Every layer the system encrypts, authenticates or terminates, including the cloak front, the exit's DNS upstream and the whole mix lane, refuses a classical peer; [docs/PQ_INVENTORY.md](docs/PQ_INVENTORY.md) lists each layer, its enforcing code and test, and the three named exceptions.

## What is automatic

- A signed role bundle supplies endpoints, identities, pins and safe defaults. No JSON, firewall, route or DNS editing is needed on an enrolled device.
- The supervisor creates WireGuard/TUN interfaces, addresses, routes, nftables rules, an application namespace, owned-exit NAT, local DNS blocklist filtering (`NXDOMAIN` before upstream resolution), and DNS-over-TLS forwarding.
- The carrier rides inside `advanced-vpn-cloak` on port 443: HTTP/3 (QUIC) on UDP 443 by default, with automatic 2-second fallback to TCP/TLS 1.3 on port 443 when UDP is blocked, periodic 10-second QUIC recovery probes, and a realistic `200 OK` HTML5 decoy page for unauthenticated HTTP/3 or HTTPS probes.
- The app namespace has no physical interface. The optional whole-device mode blocks direct IPv4/IPv6 fallback routes. Disconnect, controller death and data-plane death retain the guard.
- Data-plane children run under a dedicated non-root service UID, have no Linux capabilities, cannot gain privileges, and die if their supervisor dies. Private keys enter through immutable memory descriptors. The controller restarts failed children under the active guard.
- Twelve-hour TLS leaves rotate every six hours using the enrolled device key and its pinned SPKI. TLS/WebPKI/name validation is retained; no CA private key is deployed to a peer. Pin revocation requires an operator-authorized enrollment change.
- There is **no data cap by default**. An optional daily cap (`preferences --daily-limit-mib N`) is metered in the kernel and fail-closed: durable reservations survive crashes and clock rollback, unused bytes are refunded when the carrier stops, and an exhausted cap blocks traffic (never disabling DAITA) while the supervisor stays up and resumes at the next UTC day or when the cap is raised. `--no-daily-limit` removes it.

There is one defense posture: **strong**. Your link to the first hop runs a **bidirectional constant-rate packet stream** (`src/daita.rs`: `stream_grid` + self-sustaining `cover` under GotaTun's strict-blocking scheduler, `strict: true`, `Replace: true`), and since v0.8.0 every link between two servers runs the same invariant as paced, AES-256-GCM-encrypted fixed-size cells (`src/link.rs`), each hop on its own clock, keyed by an ephemeral X25519 + ML-KEM-768 exchange every two minutes, so a recording of a link stays sealed even against someone who later steals its pre-shared key. Every data packet is padded to constant size (1380 bytes inside WireGuard, 1420 bytes on the outer cloak), and every clock tick sends either a queued real packet or an indistinguishable decoy packet — so the outer packet rate and packet size stay flat while the shaper keeps its clock (not on a busy CPU: see below): between idle and full-speed transfers the wire packet rate changed by 0–3.7% in every measured class and hop count (`docs/evidence/RATE_CLASSES.json`; CI fails above 15%). Four rate classes, signed into the chain (`avpn init --rate auto|metered|standard|fast|line`), trade cover bandwidth for application throughput without weakening the constant-rate invariant:

| Rate class | Grid pacing | Wire rate / direction | 2-hop app throughput (v0.10.1, median of 3) | Cover volume / direction |
|---|---|---|---|---|
| `metered` | 20 ms × 1 slot (50 pps) | ~0.55 Mbit/s | 0.30 Mbit/s | ~5.7 GiB/day (~171 GiB/mo) |
| `standard` | 2 ms × 1 slot (500 pps) | ~5.5 Mbit/s | 3.0 Mbit/s | ~57 GiB/day |
| `fast` | 2 ms × 8 staggered slots (4,000 pps) | ~44 Mbit/s | 27.9 Mbit/s | ~455 GiB/day |
| `line` | 2 ms × 32 staggered slots (16,000 pps) | ~177 Mbit/s | 115.3 Mbit/s | ~1.8 TiB/day |

Wire rate and cover volume follow from the grid. Throughput was measured on v0.10.1 (14 Nov 2026) in the namespace benchmark (`tools/throughput_bench.py`, SHA-checked, `docs/evidence/RATE_CLASSES_v0_10_1.json`); every run kept the wire rate within 1.5% between idle and transfer. The paced link into the exit carries 0.29 Mbit/s (`metered`) and 28.0 Mbit/s (`fast`) on 2 hops, and 24.5 Mbit/s (`fast`) on 3. An interleaved A/B against v0.9.1 shows the move to BBR congestion control (v0.10.0) cost nothing: at `line` on 3 hops it is faster (median 115.0 vs 106.8 Mbit/s) and much steadier from a cold start (115–119 vs 77–113). Earlier figures: v0.7.0 in `docs/evidence/RATE_CLASSES.json`.

The default is `--rate auto`: the fastest class whose stream fits the smallest hop's monthly allowance (`--allowance-gib`) at the hours connected per day; with no allowance given, `metered`. **`metered` is a messaging class, not a browsing one**: on real websites only 31 of 900 page loads completed through it (`docs/evidence/WF_REAL_PILOT.json`). Browsing needs `standard` or faster.

Website fingerprinting, against a 500-tree random-forest classifier across 30 synthetic sites (`tools/daita_lab.py`, `tools/wf_attack.py`, chance = **3.3%**, fixed 6 s observation window):
- **v0.7.0** (11 Nov 2026): the camouflaged carrier scored **3.3%** on `metered` and **1.7%** on `fast`, while the link between servers, then unshaped, scored **27.0–74.7%**.
- **v0.8.0** (12 Nov 2026), with every link between servers paced: that link scored **2.3%** (`metered`) and **2.7%** (`fast`), and the carrier 3.7% and 4.3%, all at or near chance.

Those are synthetic sites. On **real websites** (pilot, 12–14 Nov 2026, code between v0.8.0 and v0.10.0, whose tick skipping is unchanged since: 20 monitored sites, headless Firefox, k-FP, DF and Tik-Tok; chance 5%; `docs/evidence/WF_REAL_PILOT.json`):
- Undefended, k-FP recognises **99.2%** (DF 94.6%, Tik-Tok 96.8%): the attacks work.
- `fast` with the browser off the data plane's CPU: **14.8%** closed world, open-world true positives near zero.
- **`fast` on a busy CPU leaks: 81%** when the browser shares cores with the client's data plane, as on most laptops. The shaper skips grid ticks it misses, so the missed ticks follow the page's own work. A higher priority gives 75%; a bounded catch-up (`AVPN_CATCH_UP_MS=50`, off by default) about 50%; a dedicated core or `SCHED_FIFO` 27–42%. None reaches the quiet-CPU level.

Until a fix removes this signal and passes the same run, **do not count on `fast` against website fingerprinting while the device is busy.** Fixing it is the project's first technical priority.

Sources: `docs/evidence/DAITA_LAB.json`, `avpn help threat-model`. The 100-site exit-vantage simulation is in `tools/mesh_wf_sim.py` (`docs/evidence/MESH_WF_SIM.json`), the mesh design is in [docs/MESH_DESIGN.md](docs/MESH_DESIGN.md), and a side-by-side comparison with Mullvad and IVPN is in [docs/COMPARISON.md](docs/COMPARISON.md).

## Command line

`avpn` is the front end. Run it with no arguments in a terminal for the interactive
view: a session header (chain, mode, key protection, service state), a history of
results, and key hints (`c` connect, `d` disconnect, `h` hops, `s` status, `i` info,
`o` doctor). Every action is also a command, and `--json` prints the controller's
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
- **Cloud:** `avpn cloud` finds free places to run servers, creates them with your own `aws`/`oci` sign-in (or records servers you already have, over SSH), and joins them into one multi-hop chain.
- **Mesh:** `avpn mesh` browses the community directory, contributes nodes and builds chains across members' servers ([`docs/cli/mesh.md`](docs/cli/mesh.md)).
- **Style:** the layout and colour rules follow the OpenAI Codex CLI's terminal style (Apache-2.0). Only the design rules were followed; no code was copied.

## Three tiers of setup

Pick how far to go. Each tier includes the one before it.

| | **1. General VPN** | **2. Hardened** | **3. Cypherpunk** |
|---|---|---|---|
| Who it's for | everyday privacy on any laptop | people a capable observer may target | people who assume the hardware itself may be hostile |
| Tunnel | post-quantum multi-hop chain, kill switch, Nitrokey unlock | plus a padded rate class (`fast` or higher) and the wire clock (experimental) | plus DC-net cells for control events, with one-time pad books handed over in person |
| Servers | free cloud hops | hops on different providers and in different countries | hops on AMD (SEV-SNP where offered) or ARM, never all on one CPU vendor |
| Laptop | any | `avpn doctor` reports the Intel ME / AMD PSP state | Intel ME neutralized or absent (see below), or an AMD or ARM laptop |
| Randomness | the kernel | the kernel and the Nitrokey | plus assessed raw CPU-jitter entropy, extracted (`tools/padbook.py`) |

**The Intel Management Engine.** Every Intel laptop since 2008 has an always-on coprocessor
with its own network stack (Intel AMT on vPro models) and full access to memory. AMD's
equivalent, the PSP, also has full memory access, but no network stack of its own, which
is why tier 3 prefers AMD. (Some AMD PRO business models offer remote management, DASH,
but it runs in the network card's firmware, not the PSP: choose a model without it.)
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

## Getting started: free servers, one chain

After installing, `avpn` on a device that is not enrolled yet lists free places to
run the servers (`avpn help endpoints`): Oracle Cloud Always Free (no expiry, 10
TiB/month out) is the best exit, and the AWS free plan (6 months, 100 GiB/month) a
good entry relay on a second provider.

```
avpn cloud suggest                                    # ranked, with your sign-ins checked
avpn cloud oci server --apply --name avpn-exit        # or: aws relay, or host add for your own
avpn cloud aws relay --apply --name avpn-relay --profile P
avpn cloud chain --apply --client-request ~/advanced-vpn-client.req --vault VAULT
sudo avpn enroll ~/.config/advanced-vpn/chains/*/bundles/client.avpn --operator-key .../operator.pub --replace
sudo avpn connect
```

`chain` orders the servers (the largest allowance at the exit, a different provider
at the entry), installs them, signs once with your Nitrokey and starts them. The
first hop is open to any address, because WireGuard never answers a peer it was not
enrolled with, so no provider's firewall configuration names you. Providers still
record who calls their API and see their own hop; `avpn help privacy` lists exactly
what each can see.

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

  The operator signs that request (`avpn init`); then run `sudo avpn enroll BUNDLE --operator-key operator.pub` and `sudo avpn connect`. On servers, use `--protect systemd-creds`. Running the same command again upgrades in place and never replaces existing keys.

Both need Python 3.10+ with `venv` (`sudo apt install python3-venv`). The binaries are
built on Ubuntu 22.04, so they run on Ubuntu 22.04+ and Debian 12/13 (x86-64).

To cut a release: bump `version` in `Cargo.toml`, commit, and push a matching tag
(`git tag -s v0.10.2 && git push origin v0.10.2`). The release workflow builds only if the
tag matches the version and every `verify` run on that commit passed: the tag's own run
and the branch's. A cancelled run doesn't block, and a re-run that passes counts.
A public tag is never moved; a failed release is followed by the next patch version.

## Build and verify

Requires Linux, Rust 1.95.0, a C compiler/CMake, Python 3.12+, iproute2, nftables, ping and `/dev/net/tun`. Hardware operations additionally require a PIN-configured FIDO2 hmac-secret device and local pinentry (see [Hardware keys](#hardware-keys)).

```sh
cargo build --release --locked
uv venv .venv
uv pip install --python .venv/bin/python --require-hashes -r tools/hardware-requirements.txt
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
.venv/bin/python -m unittest discover -s tools -p 'test_*.py' -v

# Both tests refuse host-root execution or an inherited external interface.
# ML-DSA requires the hash-locked environment (cryptography 49), including for cargo test.
export PATH="$PWD/.venv/bin:$PATH"
unshare -Urnm python3 tools/namespace_test.py --state /tmp/avpn-legacy-01
unshare --user --map-root-user --map-auto --net --mount python3 tools/managed_test.py --state /tmp/avpn-managed-01
unshare --user --map-root-user --map-auto --net --mount python3 tools/budget_test.py --state /tmp/avpn-budget-01

# Installed units, reboot guard ordering, impaired links and a disconnect soak in three
# local KVM guests (Debian 13 genericcloud image; host networking is not changed).
python3 tools/vm_validation.py --base debian-13-genericcloud-amd64.qcow2 --work /tmp/avpn-vm-01
```

The managed test exercises actual WireGuard/DAITA, both PQ layers, system DNS over an isolated TLS upstream, NAT, leak blocking, certificate rotation, the defense profile, crashes, recovery, and explicit unlock. It first demonstrates a working unencrypted fallback route, then verifies that the whole-device guard blocks it. All network/DNS changes are confined to disposable namespaces. See [current validation](docs/MANAGED_VALIDATION.md).

## Hardware keys

The Nitrokey is an example, not a requirement. `--protect nitrokey` works with **any FIDO2 (CTAP2) security key that supports the `hmac-secret` extension and verifies you**, with a PIN typed on the computer or on the key's own screen (as on a Trezor): the key releases a secret only after that and a touch, and the secret seals the device's VPN keys. Only one such key may be plugged in while you unlock. ADVANCED_VPN asks the key for nothing about itself (no attestation, so no make, model or batch) and keeps only its credential's public key.

Fully open source first: firmware and hardware designs you can read, build and check.

| Key | Open source | `hmac-secret` | Notes |
|---|---|---|---|
| **Nitrokey 3** | firmware and hardware | ✅ tested by us | The key this project is developed with. Also creates Ed25519 credentials (tested). |
| **Trezor** (Safe 3, Safe 5, Safe 7, Model T) | firmware and hardware | ✅ tested by us (Safe 3, firmware 2.12.1; older versions untested) | A hardware wallet with a FIDO2 app; you confirm and enter its PIN on the Trezor's own screen, never on the computer. Creates Ed25519 credentials (tested). Its FIDO2 secrets are derived from the wallet's recovery phrase, so restoring the phrase on a new Trezor restores your vault, and anyone holding the phrase holds it too. Safe models add a closed secure element. |
| **SoloKeys Solo 2** | firmware and hardware | not confirmed (it shares the Nitrokey 3's FIDO2 code) | No longer receives firmware updates. |

Closed firmware, and still usable:

| Key | `hmac-secret` | Notes |
|---|---|---|
| **YubiKey 5** series | ✅ tested by us (5C NFC, firmware 5.2.7); needs firmware 5.2.3 or later (Yubico) | Creates Ed25519 credentials (tested). Firmware cannot be inspected or updated; below 5.7 it is affected by EUCLEAK (CVE-2024-45678), a physical side channel against P-256 signing, so prefer an Ed25519 credential. |
| **Ledger** (Security Key app) | ✅ tested by us (Nano S Plus, app 1.7.8) | Unlock the Ledger and keep the Security Key app open: a locked Ledger answers as a U2F-only key and is refused. You confirm on its own screen. Creates Ed25519 credentials (tested). The app is open source; the device firmware is not. |
| **OnlyKey**, **Google Titan** (v2, FIDO2), **Feitian**, **Token2** | not confirmed | FIDO2 keys; most FIDO2 keys support `hmac-secret`, but check yours. |

**Curve.** In this release the key chooses its credential's curve, and most choose P-256. Choosing the curve at enrollment, with Ed25519 (which passes [SafeCurves](https://safecurves.cr.yp.to/)) as the default, comes in the next release.

**Not usable:** U2F-only keys (the first Google Titan, YubiKey 4 and NEO, many older keys), and any key that verifies no one (no PIN, no on-device check).

**Check any key** before relying on it (libfido2's tools): `fido2-token -I /dev/hidrawN` must list `hmac-secret` under extensions, and either `clientPin` as set or `uv` (on-device verification). `avpn request --protect nitrokey` refuses a key that lacks them.

**Without a hardware key**, `--protect systemd-creds` seals keys with the machine's TPM2 when it has one (the default for servers), and `--protect none` keeps them in plaintext only with `--insecure-plaintext-keys`.

## One-time enrollment, then connect

First stage the native package; staging does not install or activate anything:

```sh
python3 tools/install.py --out /tmp/new-avpn-package
```

An operator can install with `sudo python3 tools/install.py --out /path/to/new-stage --apply`. Installation creates `/opt/advanced-vpn`, a hash-locked Python environment and service files, but **does not enable them**. Review [deployment](docs/DEPLOYMENT.md) before activation.

Designed for one person running their own client, relay and exit from the command line — and, through AVPN/Mesh, for a community of such people contributing one server each (see below). **Every device generates its own private keys, and no private key ever leaves the device it was made on.** Your laptop, with the Nitrokey, is both the client and the operator.

1. On each device, generate its keys and write a public request. The laptop seals its keys with the Nitrokey, so they're never written in plaintext. Servers without a token use `systemd-creds`, which is bound to the TPM2 when one is present.

```sh
# laptop (client): PIN + touch
sudo /opt/advanced-vpn/bin/avpn request --role client --protect nitrokey --vault ~/.config/advanced-vpn/vault --out client.req
# relay and exit servers
sudo /opt/advanced-vpn/bin/avpn request --role relay --protect systemd-creds --out relay.req
sudo /opt/advanced-vpn/bin/avpn request --role exit  --protect systemd-creds --out exit.req
```

2. Copy only `relay.req` and `exit.req` to the laptop. They contain public keys only. Then sign all three bundles in **one PIN + touch**:

```sh
/opt/advanced-vpn/bin/avpn init --out ./enrollment --vault ~/.config/advanced-vpn/vault \
  --relay 192.0.2.10:443 --exit 198.51.100.20:4444 \
  --request client=client.req --request relay=relay.req --request exit=exit.req
```

Replace the documentation IP addresses with your own.
- The classical half of the signature is made by the hardware key's FIDO2 credential (P-256 or Ed25519, whichever the key creates), whose private key can't be exported.
- The ML-DSA-65 half is an operator key that stays sealed under that same credential, created on the first `init`. It is in plaintext only in memory, during that one touch.
- Bundles contain public data only, plus the WireGuard PSK, which is encrypted separately to the client and the relay with hybrid X25519 + ML-KEM-768.

3. Copy each bundle and `operator.pub` to its device, then enroll and connect:

```sh
sudo /opt/advanced-vpn/bin/avpn enroll client.avpn --operator-key operator.pub   # PIN + touch on the laptop
sudo /opt/advanced-vpn/bin/avpn connect
```

Enrollment checks:
- **both** operator signatures;
- that the bundle names this device's own keys, so a bundle made for another device is refused;
- the PSK, which it decrypts and stores under the device's protection.

It then deletes the one-time KEM key. `init` keeps no device private keys, and there are no CA keys.

**Recovery:** if a device or the Nitrokey is lost, run `request` → `init` → `enroll` again. Keys are cheap to regenerate, so the tool doesn't keep backups of them.

The default client protects explicitly launched applications and can coexist with an existing host VPN:

```sh
sudo /opt/advanced-vpn/bin/avpn run -- curl https://example.com
sudo /opt/advanced-vpn/bin/avpn status
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

`disconnect` leaves traffic blocked. After disconnecting, `reset --allow-cleartext` explicitly restores recorded routes/DNS and removes this project's guard; enabled boot services can rearm it at the next start. Ordinary disconnect never silently restores a direct route.

## One, two or three hops

| Mode | Path | What each server can see |
|---|---|---|
| `--hops 1` | client → exit | The exit sees both your IP and your destinations. |
| `--hops 2` (default) | client → relay → exit | The relay sees your IP but only ciphertext; the exit sees destinations but only the relay. |
| `--hops 3` | client → relay → middle → exit | Each server sees only its neighbours. Neither the relay nor the exit sees both ends, and the middle sees neither. |

How the layers work:
- There is one post-quantum QUIC layer per server, wrapped inside each other like an onion. Each layer uses X25519 + ML-KEM-768 key exchange and ML-DSA-65 authentication.
- WireGuard + DAITA runs between the client and the first hop; every link between two servers is a paced, encrypted constant-rate link (per-hop shaping, `src/link.rs`), keyed by a link key the operator seals to both servers.
- Each server removes exactly one layer and forwards the rest to the next hop it was enrolled with. The client knows only the first hop's address.
- **Standby exits** (`init --standby-exit NAME=IP:PORT`): the server before the exit fails over to a live standby within seconds when the exit goes silent, and rotates sessions among live exits in a signed window; your entry, the guard, never changes. Lab (v0.8.0, 12 Nov 2026): 4.2 s outage, no leak ([FAILOVER.json](docs/evidence/FAILOVER.json)).
- QUIC needs at least 1200 bytes of UDP payload per layer, so the layers are budgeted from the inside out: 1312, 1256 and 1200 bytes, all inside the 1340-byte WireGuard MTU. Apps see the same inner MTU of 1100 bytes in every mode.

```sh
# middle relay (three hops only): its own keys, like every device
sudo /opt/advanced-vpn/bin/avpn request --role middle --protect systemd-creds --out middle.req
# laptop: sign a chain (one PIN + touch)
/opt/advanced-vpn/bin/avpn init --hops 3 --out ./chain3 --vault ~/.config/advanced-vpn/vault \
  --relay 192.0.2.10:443 --middle 198.18.0.20:4445 --exit 198.51.100.20:4444 \
  --request client=client.req --request relay=relay.req --request middle=middle.req --request exit=exit.req
```

**Switching modes** reuses every device's keys:
1. Run `init` again with another `--hops` value and the same requests.
2. On each device in the new chain, run `sudo avpn disconnect`, then `sudo avpn enroll <bundle> --operator-key operator.pub --replace`, then `connect`.

Traffic stays blocked while you switch. In single-hop mode, give `--exit` the exit's port-443 endpoint: it is then the first hop.

```sh
# a standby exit: give its request under its name; the relay fails over and rotates
/opt/advanced-vpn/bin/avpn init --hops 2 --out ./chain2 --vault ~/.config/advanced-vpn/vault \
  --relay 192.0.2.10:443 --exit 198.51.100.20:4444 --standby-exit exit2=198.51.100.30:4444 \
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

ADVANCED_VPN is becoming a community mesh: every member contributes at least one server — an always-free cloud VM is enough, and `avpn mesh offer --guided` ranks the options (Oracle Cloud Always Free first, ~10 TiB/month egress) and provisions through the existing cloud machinery — and in return can build chains across nodes contributed by other members, browsable and selectable from the CLI:

```
avpn mesh nodes --fetch          # the directory: roles, providers, latency, uptime
avpn mesh chain --hops 3         # every hop a distinct operator, provider and country
avpn mesh quota                  # credits earned relaying vs spent on chains
```

There is **no account anywhere**: a member is their hardware device — a Nitrokey (open source) by preference, but any token that can generate the required keys. The member ID is the hash of the device public key; the private key never leaves the token. Nodes can also be kept private (`avpn mesh offer --private`), usable only by you. Defense is strong-only and per-hop: the client's link runs the constant-rate carrier stream and every server-to-server link a paced, encrypted constant-rate stream; your own node is your entry, and the exit must answer to another legal sphere than the entry. The full design, the contribution economy (unlinkable blind-signed credits — Chaum RSA-FDH in the control plane today, VOPRF in the data plane once the verifier is vendored), the trust model for stranger-run nodes, and the website-fingerprinting measurements (100-site run: [docs/evidence/MESH_WF_SIM.json](docs/evidence/MESH_WF_SIM.json)) are in [docs/MESH_DESIGN.md](docs/MESH_DESIGN.md); the command reference is [docs/cli/mesh.md](docs/cli/mesh.md).

## No retained data

Like Mullvad, servers are built to hold nothing that could be handed over:
- **No accounts, no logs.** Process output goes to `/dev/null`, and `LogLevelMax=emerg` stops even the service manager from logging start and stop times for the VPN units.
- **Everything written while running lives in RAM** (`/run/advanced-vpn/`): status, PIDs, locks, rotated certificates, carrier counters and the resolver file.
- **A server's persistent disk holds only its enrollment:** keys, pins and peer addresses.
- **The data cap is client-only,** so no server stores byte counts.
- **The DNS forwarder** logs and caches nothing.
- **Flow state** (kernel conntrack and WireGuard handshakes) exists only in RAM, while a session is active.

In installed Debian 13 VMs, after real traffic, the relay and exit had **written no files** under `/etc/advanced-vpn` and had **no journal entries** for the VPN units. The client keeps only its own preferences and a pre-VPN network snapshot, which it needs to restore its routes after a reboot.

**Zero-knowledge proofs aren't used in the single-operator design, and nothing there needs them.** Mullvad and Nym use ZK credentials to separate a paying account from what that account does on someone else's servers. With one person owning every device and every hop, there's no account or payment to unlink. AVPN/Mesh is the point where that changes: once strangers use each other's servers, usage must be decoupled from identity, so mesh contribution credits are blind-signed tokens today (Chaum blind RSA, see [docs/MESH_DESIGN.md](docs/MESH_DESIGN.md)) — not accounts, and still no ledger — and the v1.0 design replaces them with zero-knowledge membership proofs as hash-based STARKs, post-quantum and measured on a prototype ([docs/ZK_MEMBERSHIP_DESIGN.md](docs/ZK_MEMBERSHIP_DESIGN.md)).

## Key exposure

| Stage | Where private keys exist |
|---|---|
| Generation (`request`) | Only on the device. Nitrokey mode seals before writing (no plaintext file). `systemd-creds` mode encrypts with the TPM2 when present, otherwise with the host credential key. `none` mode is explicit plaintext (`0600`). |
| Operator (`init`) | No device key. The FIDO2 Ed25519 key never leaves the token. The operator ML-DSA key is unsealed in memory for one signing operation. |
| Transfer | Requests and bundles carry public data only. The PSK is encrypted with hybrid X25519 + ML-KEM-768 to each recipient. |
| Running | Unsealed into immutable memory files, then into network processes that run as the service user with no capabilities. Those processes and the controller are non-dumpable, and the unit forbids swap. The controller keeps no copy of the keys; certificate rotation reads them back from the sealed file descriptors. |

The data-plane keys (WireGuard X25519 and the ML-DSA TLS keys) are used for every handshake, so they have to be in endpoint memory. No security key supports ML-DSA, so they can't live on the token. Root, the kernel or a hypervisor on that endpoint can therefore still read them. Python can't guarantee memory is wiped, and deleting a file doesn't erase old disk blocks. Use encrypted disks.

Cold start with a Nitrokey-sealed client needs the PIN and a touch:
- **In a terminal,** `avpn` asks on the command line.
- **As a service, including whole-device mode at boot,** it asks through systemd's password agents. The prompt appears on the boot console, as a disk-encryption passphrase does, or you answer it from any terminal with `sudo avpn unlock`. The PIN is never cached in the kernel keyring.
- **In a desktop session with neither,** `pinentry-gnome3` is the fallback.

If nobody answers, the prompt times out after 5 minutes. The service restarts and asks again, and traffic stays blocked the whole time.

## Limits and provenance

The relay/provider can still observe addresses, sizes, timing and outages. The owned exit sees traffic after VPN decryption; HTTPS retains its independent TLS. No provider-no-logging, anonymity, TEE attestation, WAN-performance or independent-audit guarantee is made. A global passive adversary remains out of scope for any low-latency system, ours included; per-hop defense raises its cost, it does not produce mixnet-grade unlinkability. For traffic that can wait seconds, the mix lane (`avpn mix`, Katzenpost) does: with live websites such an adversary named 10.7% of senders on the mix lane against 88.2% on a low-latency path (chance 10%, post-quantum Sphinx, `docs/evidence/MIX_LANE.json`). The mix lane's at-chance protection is a property of the delay and rate together, not of one bandwidth number (parameter sweep, v0.10.2, 10 clients, `docs/evidence/MIX_LANE_SWEEP.json`): at 200 ms mean delay per hop the adversary stays at chance down to half the client uplink (~287 kbit/s, 11.6% [7.9–15.2] against a 10% chance), and doubling the payload rate buys a shorter queue, not weaker protection (9.1% at ~917 kbit/s); but half the uplink **with** 100 ms delays leaks above chance (12.8% [10.5–15.1]). Shorter delays are therefore only safe at the full rate, and slower links only at the full delay. An I2P front (`avpn init --front i2p`) keeps your address from the entry and its provider (`docs/evidence/I2P_FRONT.json`).

DNS is post-quantum or nothing: the exit forwards lookups only over TLS 1.3 with the hybrid X25519MLKEM768 group, and fails closed otherwise. That is a trade: few public resolvers offer the group today, so the default upstream is Cloudflare (`1.1.1.1:853`, Google also works), which concentrates your lookups at one provider (it sees them coming from your exit, not from you). A resolver run on the exit itself is on the roadmap ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/COMPARISON.md](docs/COMPARISON.md) §4 item 14).

`src/dcnet.rs` is a DC-net round core (pads, frame codec, aggregation) for anonymous mesh control events, kept as a tested reference: its vectors match an independent Python mirror (`docs/evidence/DCNET_VECTORS.json`), and its Tamarin models are in `formal/dcnet/`. Its pads come from hardware only (`tools/padbook.py`): one-time pads for pairs who met in person, made from the Nitrokey and an assessed raw CPU-jitter source, which make sender anonymity information-theoretic among them under stated source assumptions (an entropy estimate is evidence, not proof), and a forward-secure chain for pairs who cannot meet (computational). The Nitrokey alone is not enough: its RNG command returns a ChaCha8 stream seeded per boot. No binary calls it yet; the design and its limits are in [docs/DCNET_CONTROL_DESIGN.md](docs/DCNET_CONTROL_DESIGN.md).

The data plane is Linux/IPv4 only. **IPv6 is deliberately blocked** in every mode, so it can't escape around the tunnel. The managed profile uses inner MTU 1100 and WireGuard MTU 1340, requiring an IPv4 underlay MTU of at least 1420. A native desktop GUI, multi-user fleet control and a statistically evaluated defense dataset are not included. The standalone v0.1 QUIC interface remains available; see [historical interface](docs/LEGACY_QUIC.md).

Our original files are Apache-2.0. Unmodified GotaTun is an MPL-2.0 dependency; Maybenot components are MIT/Apache-2.0. See [provenance](docs/PROVENANCE.md) and [upstream source/notice information](third_party/SOURCES.json). No VP.NET implementation was copied or ported; this is not represented as a clean-room project.

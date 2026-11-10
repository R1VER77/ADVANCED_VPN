# ADVANCED_VPN — managed Linux client

A Rust VPN data plane with signed enrollment, automatic networking, a persistent kill switch, DNS isolation, real GotaTun/Maybenot DAITA, and the original two hybrid post-quantum QUIC layers. The cloud relay never holds the inner tunnel keys. No existing VPN is automatically replaced during build or installation.

```mermaid
flowchart LR
    App[Protected applications] --> Client[Client]
    Client <-->|WireGuard + DAITA; two PQ layers inside| Relay[Cloud relay]
    Relay <-->|Inner PQ ciphertext| Exit[Owned exit]
    Exit --> Internet[Destination]
```

WireGuard is the outer carrier, implemented by **GotaTun 0.10.2**, with its actual DAITA integration and public **Maybenot 2.2.2** defense machines. Its ChaCha20-Poly1305 encryption and 256-bit PSK supplement the existing **two TLS 1.3 X25519 + ML-KEM-768 / AES-256-GCM layers**. WireGuard alone is not advertised as native ML-KEM. Authentication is post-quantum too: both QUIC layers accept **only ML-DSA-65** (FIPS 204) certificate chains and TLS 1.3 CertificateVerify signatures, and operator enrollment bundles carry a **hybrid Ed25519 + ML-DSA-65** signature pair that must both verify. A correctly pinned classical (ECDSA) deployment is refused; the Rust tests prove this and fail if the restriction is removed.

## What is automatic

- A signed role bundle supplies endpoints, identities, pins and safe defaults. No JSON, firewall, route or DNS editing is needed on an enrolled device.
- The supervisor creates WireGuard/TUN interfaces, addresses, routes, nftables rules, an application namespace, owned-exit NAT and DNS-over-TLS forwarding.
- The app namespace has no physical interface. The optional whole-device mode blocks direct IPv4/IPv6 fallback routes. Disconnect, controller death and data-plane death retain the guard.
- Data-plane children run under a dedicated non-root service UID, have no Linux capabilities, cannot gain privileges, and die if their supervisor dies. Private keys enter through immutable memory descriptors. The controller restarts failed children under the active guard.
- Twelve-hour TLS leaves rotate every six hours using the enrolled device key and its pinned SPKI. TLS/WebPKI/name validation is retained; no CA private key is deployed to a peer. Pin revocation requires an operator-authorized enrollment change.
- There is **no data cap by default**. An optional daily cap (`preferences --daily-limit-mib N`) is metered in the kernel and fail-closed: durable reservations survive crashes and clock rollback, unused bytes are refunded when the carrier stops, and an exhausted cap blocks traffic (never disabling DAITA) while the supervisor stays up and resumes at the next UTC day or when the cap is raised. `--no-daily-limit` removes it.

The `balanced` profile uses NetFlow padding and FRONT decoys re-armed for every burst of traffic; `strong` adds Tamaraw constant-rate shaping that rounds each trace to a multiple of 100 packets on its own clock (`src/daita.rs`). These are not Mullvad's private/current production profiles. Nonempty WireGuard data packets are padded to constant size; handshake/empty keepalive control packets remain distinguishable. Measured against a website-fingerprinting classifier (8 sites, chance 12.5%): `balanced` 60%, `strong` 26% (`docs/evidence/DAITA_LAB.json`, `avpn help threat-model`).

Measured in the namespace benchmark (`tools/throughput_bench.py`, 32 MiB, SHA-checked): `balanced` carries about **290 Mbit/s** through the full tunnel. `strong` is a low-bandwidth mode: Tamaraw paces packets at a constant rate, which gave about **0.34 Mbit/s**. Use it only when traffic-shape hiding matters more than speed. The WireGuard + DAITA carrier on its own measured about 960 Mbit/s.

## Command line

`avpn` is the front end. Run it with no arguments in a terminal for the interactive
view: a session header (chain, mode, key protection, service state), a history of
results, and key hints (`c` connect, `d` disconnect, `h` hops, `s` status, `i` info,
`o` doctor). Every action is also a command, and `--json` prints the controller's
result object for scripts.

```
$ avpn hops
• Chain  2-hop
  └ client → relay 198.51.100.80:41194 → exit 203.0.113.80:4444

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
- **Style:** the layout and colour rules follow the OpenAI Codex CLI's terminal style (Apache-2.0). Only the design rules were followed; no code was copied.

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
reference pages in one package, with SHA256 checksums. The repository is private, so
download while signed in to GitHub:

```bash
gh release download v0.5.0 -R R1VER77/ADVANCED_VPN
sha256sum -c SHA256SUMS
mkdir advanced-vpn && tar -C advanced-vpn -xzf advanced-vpn-v0.5.0-x86_64-linux-gnu.tar.gz && cd advanced-vpn
```

There are two ways to install from there:
- **Command line only, for you (an operator machine):** `python3 tools/install.py --user`. It needs no root and starts no services. `avpn` goes in `~/.local/bin`, with its own hash-locked Python environment. It covers `avpn help`, `init` (with the Nitrokey), `cloud` and the read-only commands. Run it again to upgrade; `--user --uninstall` removes it.
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
(`git tag -s v0.5.0 && git push origin v0.5.0`). The release workflow builds only if the
tag matches the version and that commit's `verify` run passed.

## Build and verify

Requires Linux, Rust 1.95.0, a C compiler/CMake, Python 3.12+, iproute2, nftables, ping and `/dev/net/tun`. Hardware operations additionally require a PIN-configured FIDO2 hmac-secret device and local pinentry.

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

The managed test exercises actual WireGuard/DAITA, both PQ layers, system DNS over an isolated TLS upstream, NAT, leak blocking, certificate rotation, both defense profiles, crashes, recovery, and explicit unlock. It first demonstrates a working unencrypted fallback route, then verifies that the whole-device guard blocks it. All network/DNS changes are confined to disposable namespaces. See [current validation](docs/MANAGED_VALIDATION.md).

## One-time enrollment, then connect

First stage the native package; staging does not install or activate anything:

```sh
python3 tools/install.py --out /tmp/new-avpn-package
```

An operator can install with `sudo python3 tools/install.py --out /path/to/new-stage --apply`. Installation creates `/opt/advanced-vpn`, a hash-locked Python environment and service files, but **does not enable them**. Review [deployment](docs/DEPLOYMENT.md) before activation.

Designed for one person running their own client, relay and exit from the command line. **Every device generates its own private keys, and no private key ever leaves the device it was made on.** Your laptop, with the Nitrokey, is both the client and the operator.

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
  --relay 192.0.2.10:41194 --exit 198.51.100.20:4444 \
  --request client=client.req --request relay=relay.req --request exit=exit.req
```

Replace the documentation IP addresses with your own.
- The classical half of the signature is made by the Nitrokey's FIDO2 credential, an Ed25519 key that can't be exported.
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
sudo /opt/advanced-vpn/bin/avpn preferences --defense strong
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
- WireGuard + DAITA runs between the client and the first hop.
- Each server removes exactly one layer and forwards the rest to the next hop it was enrolled with. The client knows only the first hop's address.
- QUIC needs at least 1200 bytes of UDP payload per layer, so the layers are budgeted from the inside out: 1312, 1256 and 1200 bytes, all inside the 1340-byte WireGuard MTU. Apps see the same inner MTU of 1100 bytes in every mode.

```sh
# middle relay (three hops only): its own keys, like every device
sudo /opt/advanced-vpn/bin/avpn request --role middle --protect systemd-creds --out middle.req
# laptop: sign a chain (one PIN + touch)
/opt/advanced-vpn/bin/avpn init --hops 3 --out ./chain3 --vault ~/.config/advanced-vpn/vault \
  --relay 192.0.2.10:41194 --middle 198.18.0.20:4445 --exit 198.51.100.20:4444 \
  --request client=client.req --request relay=relay.req --request middle=middle.req --request exit=exit.req
```

**Switching modes** reuses every device's keys:
1. Run `init` again with another `--hops` value and the same requests.
2. On each device in the new chain, run `sudo avpn disconnect`, then `sudo avpn enroll <bundle> --operator-key operator.pub --replace`, then `connect`.

Traffic stays blocked while you switch. In single-hop mode, give `--exit` the exit's WireGuard endpoint.

Measured in the namespace benchmark (32 MiB, SHA-checked):

| Hops | Throughput |
|---|---|
| 1 | about 360 Mbit/s |
| 2 | about 250 Mbit/s |
| 3 | about 160 Mbit/s |

Every run also proves two things on the wire. Raw packet observers on each server's ingress never see the payload, and only the first hop ever sees the client's address. The same runs check that no server writes anything persistent while carrying traffic. CI enforces all three.

## No retained data

Like Mullvad, servers are built to hold nothing that could be handed over:
- **No accounts, no logs.** Process output goes to `/dev/null`, and `LogLevelMax=emerg` stops even the service manager from logging start and stop times for the VPN units.
- **Everything written while running lives in RAM** (`/run/advanced-vpn/`): status, PIDs, locks, rotated certificates, carrier counters and the resolver file.
- **A server's persistent disk holds only its enrollment:** keys, pins and peer addresses.
- **The data cap is client-only,** so no server stores byte counts.
- **The DNS forwarder** logs and caches nothing.
- **Flow state** (kernel conntrack and WireGuard handshakes) exists only in RAM, while a session is active.

In installed Debian 13 VMs, after real traffic, the relay and exit had **written no files** under `/etc/advanced-vpn` and had **no journal entries** for the VPN units. The client keeps only its own preferences and a pre-VPN network snapshot, which it needs to restore its routes after a reboot.

**Zero-knowledge proofs aren't used, and nothing here needs them.** Mullvad and Nym use ZK credentials to separate a paying account from what that account does on someone else's servers. Here one person owns every device and every hop, so there's no account or payment to unlink. A cloud provider can still see packet metadata on its own hop, and ZK doesn't hide that. Splitting the hops across providers does. ZK credentials would only matter if other people used these relays, or if you rented relays you don't control.

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

The relay/provider can still observe addresses, sizes, timing and outages. The owned exit sees traffic after VPN decryption; HTTPS retains its independent TLS. No provider-no-logging, anonymity, TEE attestation, WAN-performance or independent-audit guarantee is made.

The data plane is Linux/IPv4 only. **IPv6 is deliberately blocked** in every mode, so it can't escape around the tunnel. The managed profile uses inner MTU 1100 and WireGuard MTU 1340, requiring an IPv4 underlay MTU of at least 1420. A native desktop GUI, multi-user fleet control and a statistically evaluated defense dataset are not included. The standalone v0.1 QUIC interface remains available; see [historical interface](docs/LEGACY_QUIC.md).

Our original files are Apache-2.0. Unmodified GotaTun is an MPL-2.0 dependency; Maybenot components are MIT/Apache-2.0. See [provenance](docs/PROVENANCE.md) and [upstream source/notice information](third_party/SOURCES.json). No VP.NET implementation was copied or ported; this is not represented as a clean-room project.

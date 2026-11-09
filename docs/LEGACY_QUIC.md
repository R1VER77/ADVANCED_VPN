# Historical v0.1 low-level interface

The managed v0.2 interface is documented in the main README. The following is the original standalone QUIC prototype documentation; its missing-feature statements describe v0.1.

# ADVANCED_VPN

Experimental Linux VPN in Rust: an end-to-end hybrid post-quantum tunnel carried through a separately authenticated cloud relay. The relay never terminates the inner encryption. This is a working local prototype, not an independently audited VPN service or a proof of anonymity.

```mermaid
flowchart LR
    App[Isolated application namespace] <-->|IP packets| Client[Client: inner + outer QUIC]
    Client <-->|Outer PQ QUIC; inner ciphertext| Relay[Cloud relay: outer keys only]
    Relay <-->|Inner PQ QUIC ciphertext| Exit[Owned exit: inner QUIC + TUN]
    Exit <-->|Routing / NAT| Internet[Destination]
```

Both layers require **TLS 1.3, X25519 + ML-KEM-768 key exchange, AES-256-GCM, mutual certificates and exact certificate pins**. No classical-only negotiation, 0-RTT, resumption or plaintext fallback. Certificate and handshake signatures are **ML-DSA-65** only (v0.2); classical certificates are refused. QUIC Initial packets use the standard AES-128 initial protection; application data uses AES-256-GCM.

The cloud can still record outer addresses, packet sizes, timing and outages, and can deny service. The owned exit sees traffic after VPN decryption; HTTPS retains its independent TLS. Placing the exit in another ordinary cloud moves that trust problem. There is no SGX/TDX/SEV attestation implementation in this release.

## Build and test

Requires Linux, Rust 1.95.0, a C compiler/CMake, Python 3.12+ and `cryptography`. The hardware tool additionally needs `fido2`, a configured FIDO2 PIN, and a compatible hmac-secret device.

```sh
cargo build --release --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

uv venv .venv
uv pip install --python .venv/bin/python --require-hashes -r tools/hardware-requirements.txt
.venv/bin/python -m unittest discover -s tools -p 'test_*.py' -v

# New isolated user, mount and network namespaces; new output directory required.
# iproute2, ping, sysctl, nftables and /dev/net/tun must be available.
unshare -Urnm python3 tools/namespace_test.py --state /tmp/advanced-vpn-test-01
```

The lab refuses host-root execution or an inherited external interface. It creates a client underlay, relay, owned exit, destination and application namespace; only loopback and TUN exist in the application namespace. All network changes disappear with the isolated namespace tree. Synthetic credentials, logs and ciphertext captures stay in the private test directory; only sanitized evidence belongs in Git.

The lab exercises real hybrid handshakes, TUN traffic, an owned-exit NAT, MTU boundaries, invalid/unlisted/expired/revoked identities, tampered/replayed ciphertext, relay outages and reconnects. Rust tests additionally reject classical-only and anonymous TLS clients. See [validation](docs/VALIDATION.md) for the measured build and limits.

## Provision separate peers

```sh
python3 tools/provision.py --out /private/new-vpn-state \
  --relay 192.0.2.10:4433 --exit 198.51.100.20:4444

target/release/advanced-vpn --config /private/new-vpn-state/relay/config.json --check
```

Replace the documentation IPs with approved real endpoints. This writes separate `client/`, `relay/`, `exit/` and `offline/` directories. Deploy **only the matching peer directory**, with its configuration paths adjusted to the new absolute location. Never deploy the entire state root to a cloud relay. Two independent offline CAs prevent the outer authority from authorizing an inner peer. No CA private key is in a peer directory.

The JSON schema rejects unknown fields. Each role has one exact peer, one active session, bounded rates and 64 KiB QUIC datagram buffers. The relay has one fixed numeric exit address and no destination selected by the client. No public management API exists. Leaf validity defaults to 12 hours, with a maximum of 23 hours from issuance plus five minutes of clock tolerance. Sessions end within five minutes and before either leaf expires. Certificate rotation/revocation requires coordinated pin updates and service restarts; automatic certificate renewal is not implemented.

A relay needs no network-admin privileges. A client/exit requires an operator-prepared TUN, addresses and routes. The daemon does **not** alter host routing, DNS, firewall or VPN settings. The current profile is IPv4-only, with inner MTU 1280 and a **1500-byte IPv4 underlay MTU**; it deliberately does not negotiate fragmentation or a smaller fallback. Inspect [deployment](docs/DEPLOYMENT.md) before running a peer outside the lab.

## Hardware-protected keys

```sh
.venv/bin/python tools/keyguard.py enroll --vault /private/new-hardware-vault

.venv/bin/python tools/keyguard.py seal \
  --vault /private/new-hardware-vault \
  --config /private/new-vpn-state/client/config.json \
  --age /absolute/path/to/age \
  --recovery-recipient /private/recipient.txt \
  --verify-recovery-with /private/offline-age-identity \
  --remove-plaintext

.venv/bin/python tools/keyguard.py run \
  --vault /private/new-hardware-vault \
  --config /private/new-vpn-state/client/config.json \
  --binary /absolute/path/to/advanced-vpn --check
```

Enrollment creates a separate non-discoverable FIDO2 credential, without resetting the token, changing its PIN or replacing other credentials. PIN entry uses local `pinentry`; user verification and presence are required. Hardware-derived material wraps keys using HKDF-SHA256 and AES-256-GCM, bound to the role, certificate and credential. The encrypted recovery copy is decrypted and checked before plaintext removal. Recovery credentials deliberately provide an alternative to the token and must remain offline.

At runtime the wrapper passes unwrapped keys through immutable, sealed Linux memfds, with no key bytes in CLI arguments or environment variables. The Rust loader requires the seals and reads with `pread` so reconnects can reuse the descriptor. Keys exist in software memory while running; they are **not non-exportable hardware TLS keys**. Root/host memory inspection is outside this protection. Python cannot promise complete memory erasure, and unlinking does not guarantee erasure of old disk blocks. Keep local state on encrypted storage, protect swap, and use the bounded service templates.

`offline/` initially contains software-generated CA private keys. Keep it off all peers and encrypt/seal it separately before operational use. No unattended token unlock or hardware-backed CA renewal service is claimed. Token loss recovery requires the separate encrypted recovery file and its offline identity; preserve hardware credential metadata as well.

## Provenance and remaining work

This is original application code around Quinn, rustls/AWS-LC and standard QUIC/TLS; no VP.NET implementation was copied or ported. It is not represented as a clean-room project because the author previously reviewed that source. No Mullvad, IVPN or Quincy source is bundled. The specific ideas adopted and their limits are documented in [provenance](docs/PROVENANCE.md).

Before production: independent security review, real two-site WAN/MTU/loss tests, hardened deployment and DNS verification on owned hardware, certificate lifecycle automation, reproducible cross-environment builds, sustained overload testing, and validation of the actual hardware/runtime threat model. No cloud VPN had been deployed at that point, and no existing route was changed.

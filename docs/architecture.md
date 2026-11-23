# Architecture

## Processes

```mermaid
flowchart LR
    CLI["cypherpunk (Rust): renders results"] -->|"--json"| CTL["cypherpunkctl (Python, root): validates, builds network, supervises"]
    CLI -->|"as you"| CLOUD["cpvpn-cloud: aws / oci CLIs, tagged resources only"]
    CTL --> CLOAK["cypherpunk-vpn-cloak: HTTP/3 camouflage"]
    CTL --> WG["cypherpunk-vpn-wireguard: GotaTun + DAITA carrier"]
    WG <-->|"loopback"| CLOAK
    CTL --> CORE["cypherpunk-vpn: nested QUIC layers"]
    CTL --> DNS["cypherpunk-vpn-dns: DNS over TLS"]
```

- **`cypherpunk`** never runs privileged logic itself. It calls the controller with `--json` and renders the single result object. When it runs as root, it only executes root-owned, write-protected programs.
- **The controller** owns everything privileged: keys, nftables, namespaces, routes and supervision. Data-plane children run under an unprivileged service UID with no capabilities. They receive keys through sealed memfds and die with their supervisor.
- **`cpvpn-cloud`** uses your own provider sign-in. It touches only the resources it tagged.

## Data path

See `cypherpunk help chains`:
- one QUIC layer per server hop (X25519MLKEM768, ML-DSA-65), nested inside-out;
- the WireGuard + DAITA carrier innermost on the client's link, itself carried as QUIC
  datagrams on UDP 443 (`cypherpunk-vpn-cloak`), so that link looks like HTTP/3;
- the inner IP MTU is 1100 for every chain length;
- the WireGuard carrier keeps a persistent keepalive, so the chain survives roaming between networks (`cypherpunk help threat-model`).

## Threat model

See `cypherpunk help threat-model`:
- the design is a multi-party relay (like iCloud Private Relay) using the MASQUE
  QUIC-datagram mechanism, with post-quantum mutual authentication and DAITA traffic
  shaping that OHTTP, MASQUE and Private Relay do not have;
- the honest limits are global-passive flow correlation (DeepCorr/Var-CNN) and the
  non-collusion assumption; constant-cell padding reduces, but does not erase, what an
  observer can learn.

## Keys

See `cypherpunk help keys`:
- keys are generated on each device and sealed to a Nitrokey, or to TPM2 + host;
- the operator signs with a hybrid FIDO2 Ed25519 + ML-DSA-65 key;
- bundles contain no private keys.

## What servers keep

See `cypherpunk help retention`:
- runtime state lives in RAM only;
- server units run with `LogLevelMax=emerg`;
- servers keep no byte counters.

## What hops can see

See `cypherpunk help privacy`:
- the first hop sees your address, unless upstream entry routes it through another network;
- the exit sees destinations, but not you.

## Reference

- One page per command: [`docs/cli/`](cli/), also available as `cypherpunk help`.
- Rust API documentation: `cargo doc --open` (every public item is documented; `#![deny(missing_docs)]`).
- Python: every public function in the product modules has a docstring (ruff `D1`, enforced in CI).

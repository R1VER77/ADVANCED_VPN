# avpn init

Operator only. Sign a chain from the devices' public requests and produce one `.avpn`
bundle per device.

## Usage

    avpn init --out DIR --hops N --exit IP:PORT [--relay IP:PORT] [--middle IP:PORT] \
        --request ROLE=FILE ... (--vault DIR | --software-operator DIR) \
        [--rate auto|metered|standard|fast|line] [--allowance-gib N] \
        [--hours-per-day H] [--accept-cost] [--daily-limit-mib N] \
        [--dns-blocklist FILE] [--cover-name NAME]

## Options

- `--out DIR`: a new directory for the bundles and `operator.pub`.
- `--hops N`: the chain length. `1` is client → exit, `2` adds an entry relay, `3` also adds a middle relay.
- `--relay IP:PORT`: the entry relay's public endpoint, normally port 443 (2 and 3 hops).
- `--middle IP:PORT`: the middle relay's public QUIC endpoint (3 hops).
- `--exit IP:PORT`: the exit's public QUIC endpoint, or with 1 hop its port-443 endpoint.
- `--request ROLE=FILE`: repeat once for the client and once for every server in the chain.
- `--vault DIR`: production. Signs with the Nitrokey's FIDO2 Ed25519 credential plus the ML-DSA-65 operator key sealed in the vault (PIN + touch).
- `--software-operator DIR`: LAB ONLY. Plaintext operator keys.
- `--rate`: the constant-rate stream's class (`auto`, `metered`, `standard`, `fast`, or `line`; default `auto`, which selects the fastest class whose outbound cost fits `--allowance-gib` at `--hours-per-day`).
- `--allowance-gib N`: the smallest hop's monthly outbound data allowance in GiB, used by `--rate auto` and the cost guard.
- `--hours-per-day H`: expected hours connected per day for the monthly GiB cost calculation (default `8`).
- `--accept-cost`: sign a rate class even when its monthly GiB exceeds `--allowance-gib`.
- `--daily-limit-mib N`: an optional fail-closed daily cap for the client.
- `--dns-blocklist FILE`: optional domain blocklist file (one domain per line) signed into the exit bundle so the exit's DoT forwarder immediately answers `NXDOMAIN` for matching domains and subdomains.
- `--cover-name NAME`: the server name the first hop's HTTP/3 camouflage presents. Use a name that resolves to that hop's address, such as its provider-assigned DNS name; `avpn cloud chain --apply` fills this in for AWS. Without it, no server name is sent.

## What it changes

Writes `DIR/<role>.avpn` and `DIR/operator.pub`. Nothing on any host changes.

## Security notes

Every chain is padded to constant cells on every hop, runs the constant-rate stream on the carrier, and camouflages the link to the first hop as HTTP/3 on UDP 443 with automatic fallback to TLS 1.3 on TCP 443; there is no option to turn any of these off (`avpn help threat-model`).

Bundles hold no private keys. The PSK is encrypted to each device's KEM key, so a
bundle is useless on another device.

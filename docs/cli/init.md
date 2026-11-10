# avpn init

Operator only. Sign a chain from the devices' public requests and produce one `.avpn`
bundle per device.

## Usage

    avpn init --out DIR --hops N --exit IP:PORT [--relay IP:PORT] [--middle IP:PORT] \
        --request ROLE=FILE ... (--vault DIR | --software-operator DIR) \
        [--defense balanced|strong] [--daily-limit-mib N] [--cover-name NAME]

## Options

- `--out DIR`: a new directory for the bundles and `operator.pub`.
- `--hops N`: the chain length. `1` is client → exit, `2` adds an entry relay, `3` also adds a middle relay.
- `--relay IP:PORT`: the entry relay's public endpoint, normally port 443 (2 and 3 hops).
- `--middle IP:PORT`: the middle relay's public QUIC endpoint (3 hops).
- `--exit IP:PORT`: the exit's public QUIC endpoint, or with 1 hop its port-443 endpoint.
- `--request ROLE=FILE`: repeat once for the client and once for every server in the chain.
- `--vault DIR`: production. Signs with the Nitrokey's FIDO2 Ed25519 credential plus the ML-DSA-65 operator key sealed in the vault (PIN + touch).
- `--software-operator DIR`: LAB ONLY. Plaintext operator keys.
- `--defense`: the initial DAITA defense (see `avpn help preferences`).
- `--daily-limit-mib N`: an optional fail-closed daily cap for the client.
- `--cover-name NAME`: the server name the first hop's HTTP/3 camouflage presents. Use a name that resolves to that hop's address, such as its provider-assigned DNS name; `avpn cloud chain --apply` fills this in for AWS. Without it, no server name is sent.

## What it changes

Writes `DIR/<role>.avpn` and `DIR/operator.pub`. Nothing on any host changes.

## Security notes

Every chain is padded to constant cells on every hop, and the link to the first hop always looks like HTTP/3 on UDP 443; there is no option to turn either off (`avpn help threat-model`).

Bundles hold no private keys. The PSK is encrypted to each device's KEM key, so a
bundle is useless on another device.

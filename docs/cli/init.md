# avpn init

Operator only. Sign a chain from the devices' public requests and produce one `.avpn`
bundle per device.

## Usage

    avpn init --out DIR --hops N --exit IP:PORT [--relay IP:PORT] [--middle IP:PORT] \
        --request ROLE=FILE ... (--vault DIR | --software-operator DIR) \
        [--rate auto|metered|standard|fast|line] [--allowance-gib N] \
        [--hours-per-day H] [--accept-cost] [--daily-limit-mib N] \
        [--dns-blocklist FILE] [--dns-allowlist FILE] [--cover-name NAME] \
        [--standby-exit NAME=IP:PORT ...] [--rotate-seconds MIN,MAX] \
        [--front i2p] [--front-hops 1|2|3]

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
- `--allowance-gib N`: the smallest hop's monthly outbound data allowance in GiB, used by `--rate auto` and the cost guard. A relay sends the stream on two links (back to the client and on to its next hop), so in a 2- or 3-hop chain the cost counts both.
- `--hours-per-day H`: expected hours connected per day for the monthly GiB cost calculation (default `8`).
- `--accept-cost`: sign a rate class even when its monthly GiB exceeds `--allowance-gib`.
- `--daily-limit-mib N`: an optional fail-closed daily cap for the client.
- `--dns-blocklist FILE`: an optional domain blocklist signed into the exit bundle; the exit's DoT forwarder answers `NXDOMAIN` for matching names. One rule per line, in the common list formats: `example.com` or `.example.com` (the domain and its subdomains), `*.example.com` (subdomains only), hosts-file `0.0.0.0 example.com`, or adblock `||example.com^`; `#` and `!` start comments (OISD and hagezi lists load as published). Answers are checked too: a name whose CNAME chain leads into a blocked domain (CNAME cloaking) is also answered `NXDOMAIN`. Filtering happens at your exit, inside the tunnel; no list, query or verdict leaves it.
- `--dns-allowlist FILE`: an optional allowlist in the same formats, signed into the exit bundle. Its names are never blocked, by name or through a CNAME.
- `--standby-exit NAME=IP:PORT`: a standby exit (2 and 3 hops; repeat for up to 7). Give its request with `--request NAME=FILE`. The server before the exit opens a session through the first live exit, fails over to the next when one stops answering (3 s of silence on the paced link), and the client trusts exactly the signed set of exits. Your entry, the guard, never changes.
- `--rotate-seconds MIN,MAX`: with standby exits, move to another live exit at a random time in this window (default `900,3600`), always at a session boundary. Between 60 and 86400 seconds.
- `--front i2p`: the client reaches the entry only through I2P. The entry (and its cloud provider) sees I2P routers, never your address; your network sees I2P, never a VPN server. Carries the `metered` and `standard` classes (`auto` picks `standard` at most). The entry's request must come from this release (it holds the entry's I2P destination). See `avpn help front`.
- `--front-hops N`: I2P hops each way between you and the entry (default `2`, so no single I2P router sees both your address and the entry's; `1` is faster, but that one router sees both, never the content; `3` is slower still).
- `--cover-name NAME`: the server name the first hop's HTTP/3 camouflage presents. Use a name that resolves to that hop's address, such as its provider-assigned DNS name; `avpn cloud chain --apply` fills this in for AWS. Without it, no server name is sent.

## What it changes

Writes `DIR/<role>.avpn` (and `DIR/<NAME>.avpn` for each standby exit) and `DIR/operator.pub`. Nothing on any host changes.

## Security notes

Every chain is padded to constant cells on every hop, runs the constant-rate stream on the carrier and on every link between two servers (paced, encrypted cells: per-hop shaping), and camouflages the link to the first hop as HTTP/3 on UDP 443 with automatic fallback to TLS 1.3 on TCP 443; there is no option to turn any of these off (`avpn help threat-model`).

Bundles hold no private keys. The PSK is encrypted to each device's KEM key, so a
bundle is useless on another device.

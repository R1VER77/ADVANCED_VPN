# avpn mix

The mix lane: requests that can wait a few seconds travel through a Katzenpost mixnet,
started from inside the protected namespace, so the mixnet's gateway sees your chain's
exit and never this device.

## Usage

    sudo avpn mix setup --config DIR
    sudo avpn mix start [--uid UID --gid GID]
    sudo avpn mix status
    sudo avpn mix fetch URL [--method GET|HEAD] [--uid UID --gid GID]
    sudo avpn mix stop

## Options

- `setup --config DIR`: install a mixnet's client configuration (`DIR/client.toml`, as its operators publish it). Refused if it turns decoy traffic off or sends through an upstream proxy. Its thin-client address is replaced with this device's fixed one.
- `start`: run the mixnet client (Katzenpost's `kpclientd`) and its HTTP proxy inside the protected namespace, as the sudo caller (or `--uid`/`--gid`). The proxy listens on `127.0.0.1:41199` there, so any program started with `avpn run` can use it.
- `status`: whether the client runs and the proxy answers.
- `fetch URL`: one request through the mix lane; prints a JSON line (status, seconds, bytes, headers) and, for `GET`, the body. `--method HEAD` fetches only the headers.
- `stop`: stop the client. While it runs it sends cover traffic; stopping it ends that too.
- `--uid`, `--gid`: the user and group the client and the fetch run as (default: the sudo caller's).

## What it protects against

A VPN, ours included, carries packets with low latency: an adversary who can watch your
link and the far end of the path at once can match the timing of what goes in with what
comes out. A mixnet holds every packet a random time at every hop, and its clients send
real-or-decoy packets and loops at a constant Poisson rate whether or not they have
anything to say. Every hop's Sphinx layer is post-quantum: X-Wing (ML-KEM-768 + X25519);
`avpn mix setup` refuses a mixnet configured with classical Sphinx. In the lab
(`docs/evidence/MIX_LANE.json`: 10 clients, 30 live public websites) an adversary watching
every link, and given the network's delay distribution, named the sender of 95.6% of
requests through a low-latency proxy and 11.6% through the mix lane (chance: 10%; the
difference is within sampling noise). Each client's link sent 2.88 packets a second busy
and 2.92 idle. Live fetches took 4.3 s at the median, 8.7 s at the 99th percentile.

The mix lane is opt-in. Everything goes through the fast lane unless you start the mix
lane yourself; its latency and its idle cover traffic are a trade you choose.

## Limits

- Latency is seconds, not milliseconds: mail, chat, small fetches and status checks, not browsing or calls.
- A reply must fit one mixnet message (8000 bytes on the lab network; the mixnet's operators choose). Larger replies are refused (`502`).
- Anonymity grows with the mixnet's traffic: the more clients send cover in the same delay window, the less any one stands out.
- A smaller post-quantum Sphinx (option E: 1,396-byte headers instead of X-Wing's 7,164) is built and under evaluation (`crates/avpn-mix-lane`, `docs/DESIGN_PACK_ASSESSMENT.md`); it replaces Katzenpost only after its cutover gates pass, including an external review.
- Cover traffic runs only while the client runs. Keep it started rather than starting it for each request: when it runs says something on its own.
- The mixnet's programs are Katzenpost's, unmodified and run as separate processes (AGPL-3.0); build them with `third_party/katzenpost/build.sh` and place `kpclientd` and `http-proxy-client` in `/usr/lib/advanced-vpn/katzenpost`. Katzenpost describes itself as pre-alpha.

## See also

`avpn help run`, `avpn help threat-model`, `avpn help front`.

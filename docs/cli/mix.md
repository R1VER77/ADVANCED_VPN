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
anything to say. Every layer is post-quantum: X-Wing (ML-KEM-768 + X25519) Sphinx and
links, and hybrid Ed25519 + SPHINCS+ directory signatures; `avpn mix setup` refuses a mixnet
configured with anything classical. The service that fetches websites for you speaks only
TLS 1.3 with X25519MLKEM768 (`tools/kp_pq_fetch.py`) and refuses sites that cannot (`525`,
`526`), so no fetch leaves the mixnet under classical key exchange. In the lab
(`docs/evidence/MIX_LANE.json`: 10 clients, 30 live public websites) an adversary watching
every link, and given the network's delay distribution, named the sender of 88.2% of
requests through a low-latency proxy and 10.7% through the mix lane (chance: 10%; the
difference is within sampling noise). Each client's link sent 2.82 packets a second busy
and 2.91 idle, about 555 kbit/s of upload. Live fetches took 4.4 s at the median, 8.3 s at
the 99th percentile.

Where the seconds go, measured on the same lab (`docs/evidence/MIX_LANE_SWEEP.json`):
about a third is a request waiting for its client's next send slot (one per second on
average), about a third is mixing on the way out (five hops), and the rest is the fetch
and the reply. The send rate is bought with bandwidth, the mixing delay with anonymity.
For operators of a mixnet: 100 ms mean delay per hop measured at chance over three runs
(10.8%, against 10.6% at 200 ms) and cut the median fetch from 2.6 s to 1.7 s at the same
bandwidth. Halving the cover rate as well halved the upload but leaked (12.8% over three
runs, above chance), and 50 ms per hop is unresolved from one run. These figures are for
ten clients. More traffic in the same delay window helps only if it is indistinguishable:
with ten extra cover clients, 50 ms per hop held at chance against an adversary who could
not tell cover from users, and leaked (15.2% against 10%) against one who could.

The mix lane is opt-in. Everything goes through the fast lane unless you start the mix
lane yourself; its latency and its idle cover traffic are a trade you choose.

## Limits

- Latency is seconds, not milliseconds: mail, chat, small fetches and status checks, not browsing or calls.
- A reply must fit one mixnet message (8000 bytes on the lab network; the mixnet's operators choose). Larger replies are refused (`502`).
- Anonymity grows with the mixnet's traffic: the more clients send cover in the same delay window, the less any one stands out.
- X-Wing's 7,164-byte Sphinx headers cost bandwidth. A smaller design (option E, 1,396 bytes) stays research: its inner hops are classical X25519, so it cannot carry the post-quantum claim (`docs/DESIGN_PACK_ASSESSMENT.md`).
- Operators: run `tools/kp_pq_fetch.py` as the service node's fetch plugin in place of Katzenpost's `http-proxy-server` (it needs Python with OpenSSL 3.5 or later and `python3-cbor2`); clients are unchanged.
- Cover traffic runs only while the client runs. Keep it started rather than starting it for each request: when it runs says something on its own.
- The mixnet's programs are Katzenpost's, unmodified and run as separate processes (AGPL-3.0); build them with `third_party/katzenpost/build.sh` and place `kpclientd` and `http-proxy-client` in `/usr/lib/advanced-vpn/katzenpost`. Katzenpost describes itself as pre-alpha.

## See also

`avpn help run`, `avpn help threat-model`, `avpn help front`.

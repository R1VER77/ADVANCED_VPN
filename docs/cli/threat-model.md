# Threat model

What this design protects against, where it sits among modern privacy architectures,
and the attacks it does not stop. This is deliberately honest: a VPN that oversells
its guarantees is more dangerous than one whose limits you know.

## The one rule that cannot be broken

At the network layer every packet carries a source and a destination address, because
the reply has to find its way back. No software makes your address invisible to the
machine you send packets to directly. The first hop always sees the address its
packets come from. Encryption does not change this, and neither do zero-knowledge
proofs (they prove statements about data; they do not rewrite IP headers). See
`avpn help privacy`.

So the goal is not to hide your address from everyone. It is to make sure that **no
single party sees both who you are and what you do.**

## Where this design sits

The modern answer to the rule above is to split knowledge across parties that do not
collude. The same idea appears in Oblivious HTTP (a blind relay plus a gateway), in
MASQUE proxies, and in Apple's iCloud Private Relay (an Apple ingress plus a
third-party egress). This design is the same shape, built for one owner:

- **Multi-party relays.** The entry relay sees your address but only ciphertext; the
  exit sees your destinations but only the relay's address. A middle hop (3 hops) sees
  neither end. `avpn cloud chain` places the entry and the exit on **different
  providers**, so no one provider holds both halves.
- **The MASQUE transport mechanism.** Inner IP packets travel as unreliable QUIC
  datagrams, never as a stream, so there is no TCP-over-TCP collapse and no
  head-of-line blocking — the property MASQUE (RFC 9298/9484) was built for.
- **Post-quantum, mutually authenticated.** Every hop is X25519MLKEM768 key exchange
  with ML-DSA-65 certificates, pinned to the exact enrolled peer. The commercial
  systems above authenticate with classical WebPKI.

### One way it goes further than the systems it resembles

Oblivious HTTP gateways, MASQUE proxies and Private Relay nodes do **no** padding, add
**no** delay and send **no** cover traffic; they forward as fast as the transport
allows. That leaves packet sizes, counts and timing correlated across the proxy, which
is what flow-correlation and website-fingerprinting attacks feed on.

This design's carrier runs a **constant-rate DAITA stream** (Maybenot `stream_grid` +
`cover` with strict blocking): every data packet is padded to one size (1380 bytes inside
WireGuard, 1420 bytes on the outer cloak), and every clock tick sends either a queued
real packet or an indistinguishable decoy packet. Whether your applications are idle or
downloading at full speed, the outer packet rate and packet size stay flat (`< 1%` wire
rate change between idle and busy). Four rate classes (`metered`, `standard`, `fast`,
`line`) trade cover bandwidth for application throughput without weakening the
constant-rate invariant (`avpn help init`). On top of that,
every chain pads **every** hop's datagrams to one size per layer (constant cells), so
inner packet sizes do not leak on the outer path at all — not just on the first link.
Padding is always on and cannot be turned off; a chain signed without it is refused.

**Per-hop shaping.** The same constant-rate stream runs on every link *between* two
servers, not only on yours to the first hop. Each relay wraps what it forwards in
fixed-size cells encrypted under a link key that the operator seals to both servers
(AES-256-GCM, a fresh key per sender session), and sends a fixed number of cells on
every tick of the chain's clock — a forwarded packet, or an empty cell that looks
exactly the same. Measured on the link into the exit: before, 0.5 packets/s of small
QUIC control packets while idle jumped to 34–3,419 packets/s during a download; now the
link runs at the class's rate with one 1270-byte packet size, idle or busy (0.0–0.1%
change; `docs/evidence/RATE_CLASSES.json`, `inner_link`). The receiving server answers
only with credit earned from authenticated cells, so a server is never a reflector for
spoofed traffic. Mullvad's DAITA shapes only your link to its entry server; nothing
shapes the exit side there.

## Roaming between networks

Switching Wi-Fi, cellular or Ethernet does not drop the chain. The WireGuard carrier
to the first hop keeps a persistent keepalive, so when your address changes the first
hop re-learns it from the next authenticated packet. The inner QUIC layers ride on the
carrier's stable overlay addresses and never see the change. Nothing falls back to an
unprotected path while this happens — the kill switch holds throughout.
Now that the carrier rides inside the HTTP/3 cloak, a changed address is also a
changed outer path: the cloak reconnects and the carrier's keepalive re-learns the address,
so a transfer survives the move (measured with `tools/daita_lab.py`, `ROBUST=roam`).

## Self-healing chains

A chain can carry standby exits (`avpn init --standby-exit`). Because every link between
servers is paced and never silent, the server before the exit notices within 3 s when
the exit stops answering, ends the session, and your client's automatic reconnect goes
through the first standby exit that answers. Your client trusts exactly the signed set
of exits, and every exit uses the same tunnel addresses, so nothing about your own
device changes: the kill switch rules stay as they are and nothing can route around the
tunnel. Measured in the lab, traffic flowed again 4.2 s after the exit went dark, and the
destination never saw your own address (`docs/evidence/FAILOVER.json`).

With standby exits, sessions also rotate among the live exits at a random time within a
signed window (default 15–60 minutes), always at a session boundary. That limits how
long any one exit sees your traffic. The entry relay is your guard: it never rotates,
because changing it often only raises the odds of eventually picking a hostile one.

## Fails closed, not open

The cloak needs the path to the first hop to carry a full-size packet (an IPv4 MTU of at
least 1448 bytes). On a smaller path the client refuses to bring the tunnel up rather than
send anything in the clear, and the kill switch stays in place: in whole-device mode every
packet is dropped; in applications mode a protected program simply has no route. There is
no automatic fallback to a direct or smaller-MTU path. If the first hop is briefly
unreachable, the carrier's strict-blocking shaper flushes and recovers on its own (a
liveness guard carried in the vendored `gotatun`), and the supervisor restarts the
carrier as a backstop if it ever stays stuck.

## Measured: which website you are on

An observer next to you (your ISP, the Wi-Fi) cannot read the traffic, but can try to
recognise a website from the shape of its traffic. The lab (`tools/daita_lab.py`,
`tools/wf_attack.py`) loads 30 synthetic sites 10 times each (300 page loads) over a
~60 ms 2-hop chain, and a 500-tree random-forest classifier (`k-FP` + `CUMUL` features,
stratified 5-fold cross-validation) guesses the site from the camouflaged carrier. A
random guess is right **3.3%** of the time (`1/30`).

| View / Rate class | Right, given 6 s from each page's start | Right, told the exact timestamp each page ended |
|---|---|---|
| Inner link before per-hop shaping (v0.7.0, same loads) | 27.0–74.7% | 42.7–81.3% |
| Inner link with per-hop shaping (v0.8.0) — `metered` / `fast` | **2.3% / 2.7%** (chance 3.3%) | — |
| Carrier — `metered` (50 pps / direction) | **3.3%** (= 1/30 random chance) | 21.3% |
| Carrier — `fast` (4,000 pps / direction) | **1.7%** (≤ 1/30 random chance) | 20.0% |

- With per-hop shaping (v0.8.0) the link into the exit is at chance too; the carrier read 3.7% / 4.3% in that run, within sampling noise of the 3.3% floor.
- In a continuous constant-rate stream, there is no on-wire start or end marker: under the fixed 6 s observation window, the classifier on both `metered` (**3.3%**) and `fast` (**1.7%**) is at or below the **3.3%** random-chance floor.
- Even when an external oracle tells the attacker the exact instant each page finished loading (`true end + 3 s`), accuracy drops from `42.7–81.3%` on the unshaped inner link to `20.0–21.3%` on the carrier.
- All four rate classes keep the outer wire rate constant between idle and full-load transfers (`tools/throughput_bench.py --shape-idle 5`):

| Rate class | Grid pacing | Wire rate / direction | 2-hop app throughput | Cover volume / direction |
|---|---|---|---|---|
| `metered` (default) | 20 ms × 1 slot (50 pps) | ~0.55 Mbit/s | ~0.27–0.34 Mbit/s | ~5.7 GiB/day (~171 GiB/mo) |
| `standard` | 2 ms × 1 slot (500 pps) | ~5.5 Mbit/s | ~3.1–4.5 Mbit/s | ~57 GiB/day |
| `fast` | 2 ms × 8 staggered slots (4,000 pps) | ~44 Mbit/s | ~24.7–32.8 Mbit/s | ~455 GiB/day |
| `line` | 2 ms × 32 staggered slots (16,000 pps) | ~177 Mbit/s | ~115.3–131.5 Mbit/s | ~1.8 TiB/day |

A relay sends the stream on two links (back to you, and on to its next hop), so in a 2-
or 3-hop chain its outbound cost is about twice the per-direction figure above;
`avpn init --rate auto` counts both.

Details are in `docs/evidence/DAITA_LAB.json` and `docs/evidence/RATE_CLASSES.json`.

## What it does show

The link to the first hop no longer looks like WireGuard. The carrier (WireGuard + DAITA)
rides inside `advanced-vpn-cloak` on port 443:

- **Primary transport (UDP 443, HTTP/3 / QUIC).** Deep packet inspection (nDPI in the lab)
  labels the outer flow `QUIC, category Web`, as it would an HTTP/3 website — not a VPN.
- **Censorship fallback (TCP 443, HTTP/1.1 over TLS 1.3).** When a network blocks UDP 443,
  the cloak automatically falls back within 2 seconds to TCP/TLS 1.3 on port 443 using the
  same post-quantum `X25519MLKEM768` + `ML-DSA-65` SPKI pin and TLS exporter proof, framing
  every packet as a constant 1420-byte cell. While on TCP, the client probes UDP 443 every
  10 seconds and upgrades back to QUIC automatically once UDP is reachable.
- **Active-probing resistance.** An unauthenticated browser or scanner hitting UDP 443
  (HTTP/3) or TCP 443 (HTTPS) receives a normal `200 OK` static HTML5 status page with
  `Alt-Svc: h3=":443"; ma=86400` and forwards nothing to the VPN carrier; only a peer that
  proves knowledge of the enrolled PSK over the TLS 1.3 exporter is admitted.

What a capable observer can still tell:

- **That it is QUIC or TLS, not which site.** The outer stream uses `h3` (or `http/1.1` on
  TCP fallback), but its handshake fingerprint (the Rustls/Quinn transport parameters and
  ClientHello) is not a mainstream browser's; an adversary that fingerprints TLS/QUIC stacks
  (JA4) can see it is not Chrome, and the certificate is self-signed.
- **The constant rate of the outer stream.** An observer can see Which rate class (`metered`,
  `standard`, `fast`, or `line`) is active from the fixed packet rate, even though that rate
  does not change when you start or stop browsing.

## With an I2P front

With `avpn init --front i2p` (`avpn help front`) the link to the entry is I2P instead:
your network sees I2P (NTCP2, obfuscated but recognisable), and the entry and its cloud
provider see I2P routers, never your address. Measured in a private I2P network
(`docs/evidence/I2P_FRONT.json`), with the client in whole-device mode:

| Gate | Result |
|---|---|
| The entry received a packet from the client's address | never (4 runs, incl. an entry offering itself as a hop) |
| The entry sent a packet to the client's address | never with the client on NTCP2 only; 3 of 3 runs with SSU2 (peer test), so the client router uses NTCP2 only |
| The client sent anything but I2P to anything but I2P routers | never (only the I2P router's user may leave) |
| The same lab without the front table | the I2P router's user reaches the entry directly: five gates fail |
| Throughput / round trip (`standard`, 2 hops each way) | 3.6 Mbit/s, 82 ms average (`metered`: 0.32 Mbit/s) |

What the front does not hide: the I2P routers on your tunnels see your address (never
the content); with `--front-hops 1` that one router also sees the entry's.

## What it does not stop

- **A global passive adversary** who can watch both ends of the chain at once can
  still try to correlate the flows by their timing and volume. Deep-learning attacks
  (DeepCorr, Var-CNN) are good at this against low-latency tunnels. Constant cells and
  the constant-rate stream on every link raise the cost, but a stream that keeps packet
  order is still a circuit: only per-packet mixing with random delays and cover traffic
  (Loopix-style mixnets) defeats it, at a latency of seconds. If that is your
  adversary, carry that traffic over the mix lane (`avpn help mix`). Measured with live
  websites (`docs/evidence/MIX_LANE.json`, 10 clients, post-quantum Sphinx): such an
  adversary named the sender of 88.2% of requests through a low-latency proxy and 10.7%
  through the mix lane (chance 10%).
- **Collusion.** The whole guarantee rests on the hops not pooling their logs. Put the
  entry and the exit on different providers and in different legal spheres, so
  collusion needs two companies and two legal orders to agree. Every free tier is a
  US company, and the US CLOUD Act reaches US providers wherever their servers stand,
  so OCI and AWS ends are one sphere: `avpn cloud chain` warns about that, and mesh
  chains refuse it unless told otherwise. A non-US middle between two US ends does not
  help — the legal attack goes to the ends. The servers keep
  nothing to hand over (`avpn help retention`), but a provider can still watch its own
  hop in real time.
- **Who calls the cloud API.** Creating or changing a server records your address in
  the provider's audit log. Run `avpn cloud` while connected through the chain so the
  exit is the caller instead (`avpn help cloud`).

## Why self-hosted, and not a big provider

These split-knowledge designs only give anonymity when many users share the same
egress, so in practice they concentrate onto a few global CDNs. The IETF has written
about the risk of that consolidation: a handful of intermediaries become the obvious
target for correlation and for legal pressure. This design takes the opposite route —
your own servers, on providers you choose — so you trade a large shared anonymity set
for never trusting someone else's infrastructure with both ends. For a single owner
who controls every hop, that is the better trade.

## Deliberately not used

- **Oblivious HTTP (RFC 9458)** secures one cookieless HTTP request at a time. The
  chain already hides your address for *all* traffic, not just discrete web requests.
- **Privacy Pass / blind tokens (RFC 9474/9578)** let a crowd of users prove they are
  allowed through a shared egress without being identified. With one owner there is no
  crowd to blend into and no shared egress to rate-limit; see `avpn help privacy`.
- **Geohashing an egress address** keeps coarse location while pooling many users onto
  a CDN. It is meaningless for a single self-hosted exit.

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

This design's carrier runs **DAITA** (Maybenot): every data packet padded to one size,
FRONT decoys around every burst of traffic (a page load, say), and in the `strong`
defense Tamaraw constant-rate shaping that rounds every trace up to a multiple of 100
packets on its own clock. On top of that,
every chain pads **every** hop's datagrams to one size per layer (constant cells), so
inner packet sizes do not leak on the outer path at all — not just on the first link.
Padding is always on and cannot be turned off; a chain signed without it is refused.
The cost is bandwidth on the links between hops: every datagram travels as a full cell
(1152 bytes on the innermost layer). A full-size 1100-byte packet costs about 5% more;
a 60-byte acknowledgement costs about 19 times as much, so the overall cost depends on
how much of your traffic is small packets. Count it against each provider's monthly
outbound allowance.

## Roaming between networks

Switching Wi-Fi, cellular or Ethernet does not drop the chain. The WireGuard carrier
to the first hop keeps a persistent keepalive, so when your address changes the first
hop re-learns it from the next authenticated packet. The inner QUIC layers ride on the
carrier's stable overlay addresses and never see the change. Nothing falls back to an
unprotected path while this happens — the kill switch holds throughout.

## Measured: which website you are on

An observer next to you (your ISP, the Wi-Fi) cannot read the traffic, but can try to
recognise a website from the shape of its traffic. The lab (`tools/daita_lab.py`,
`tools/wf_attack.py`) loads 8 synthetic sites 15 times each over a ~60 ms chain, and a
random-forest classifier of the kind used in website-fingerprinting research guesses
the site from the carrier. A random guess is right 12.5% of the time.

| Defense | Right, told where each page ended | Right, given 6 s from each page's start |
|---|---|---|
| no DAITA (the same loads between hops) | 71-75% | 49-70% |
| `balanced` | 60% | 60% |
| `strong` | 54% | 26% |

- `balanced` costs almost nothing (6-7 GB a month idle, about 12% decoys while browsing) and does **not** stop this attacker.
- `strong` sends one 1380-byte packet every ~21 ms each way for as long as the tunnel is busy, and pads every trace to a whole 2 s step. The attacker then recognised only the shortest site; the other seven were at or near chance. The cost is real: pages load about 4.7 times slower, and an idle tunnel sends about 168 GB a month each way.
- Real browsing is harder for the attacker than 8 known sites, and easier if it trains on your exact sites with more samples. Treat these as orders of magnitude.

Details are in `docs/evidence/DAITA_LAB.json`.

## What it does show

- **That you use WireGuard.** Deep packet inspection (nDPI) labels the carrier WireGuard, a VPN, from its content. DAITA hides what you send, not that a VPN is in use.
- **Between hops: QUIC that looks like HTTP/3.** The handshake offers HTTP/3's protocol name (`h3`) and names no server, so it does not identify this tool. The certificates are still checked against their pinned names; the names just never go on the wire.

## What it does not stop

- **A global passive adversary** who can watch both ends of the chain at once can
  still try to correlate the flows by their timing and volume. Deep-learning attacks
  (DeepCorr, Var-CNN) are good at this against low-latency tunnels. Constant-cell
  padding and `strong` shaping raise the cost; only a mixnet with heavy delay and
  cover traffic (Nym/Loopix, Tor to a lesser degree) defeats it outright, at a latency
  this design will not pay. If that is your adversary, use a mixnet.
- **Collusion.** The whole guarantee rests on the hops not pooling their logs. Put the
  entry and the exit on different providers, ideally different jurisdictions, so
  collusion needs two companies (or two legal orders) to agree. The servers keep
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

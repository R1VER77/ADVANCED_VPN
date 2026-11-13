# The I2P front

With `avpn init --front i2p`, the client reaches the chain's entry only through I2P.

    you -> I2P (your router, hidden) -> I2P routers -> the entry's I2P router -> the entry -> ... -> the exit

- The entry, and its cloud provider, sees I2P routers, never your address.
- Your network sees I2P, never a connection to a VPN server.
- The rest of the chain is unchanged: WireGuard with the constant-rate stream inside the
  camouflage, then the chain's post-quantum layers.

## How it works

- At `avpn request`, the entry (any first hop) also generates an I2P destination (X25519 + Ed25519); its private keys are protected with the entry's other keys. `avpn init --front i2p` signs the destination's b32 address into your profile, so your device reaches exactly that entry.
- Your device runs i2pd, unmodified, as its own user (`advanced-vpn-i2p`), configured in RAM: a client tunnel with `--front-hops` hops each way to the entry, every proxy, console and control port off, no transit, signed reseeds only. Your router is hidden: it publishes no address, and it speaks only NTCP2, because SSU2's peer test asks a third router to probe the tester's address directly and that router could be the entry.
- The entry's i2pd serves its destination with zero hops (the entry is already known to you; hiding it would cost latency and gain nothing) and hands each stream to the cloak's TLS listener, which gives streams from I2P 30 s to authenticate instead of 3.
- The cloak on your device speaks only TLS 1.3 over the I2P stream (I2P carries streams, not datagrams), never QUIC.

## Setting it up

- On your device and on the entry: i2pd **2.56 or newer** (`sudo apt install i2pd` on Debian 13; Ubuntu 24.04 ships 2.49, which never bootstrapped in the lab, so use the i2pd project's own packages there), then `sudo systemctl disable --now i2pd`. The VPN service refuses an older i2pd. The package's own service is a public, general-purpose router; the VPN service runs its own instance with the configuration above. The installer creates the `advanced-vpn-i2p` user.
- Request the entry's keys with this release, then sign with `avpn init --front i2p` and enroll as usual.

## The kill switch

- Whole-device mode lets out only the I2P router's user; everything else leaves through the tunnel or not at all. The I2P router's own packets keep the underlay route (a policy-routing rule for that user), so the tunnel never carries itself.
- A separate table drops every packet between this host and the entry's own address, in both directions. Your router therefore never exchanges a packet with the entry and is never one of its tunnel hops, even if the entry offers itself as one.
- If i2pd stops, the tunnel stops; the supervisor restarts it, and nothing leaves meanwhile.

## Cost

- Rate classes: `metered` and `standard` only (an I2P stream carries no more); `--rate auto` picks `standard` at most.
- Lab (`docs/evidence/I2P_FRONT.json`, a private I2P network in namespaces): the tunnel comes up through I2P in 10–25 s; `standard` carried a SHA-256-verified transfer at about 3.6 Mbit/s with an 82 ms average round trip; `metered` about 0.32 Mbit/s. The public I2P network is slower: expect round trips of hundreds of milliseconds to seconds.
- `--front-hops 1` is faster, but that one I2P router sees your address and the entry's (never the content). The default, `2`, leaves no single router seeing both.

## Trade-offs

- You depend on the I2P network's health, and anyone watching your link can tell you use I2P (NTCP2 is obfuscated, not invisible).
- The entry runs an I2P router reachable on its `router_port` (signed into its profile, random by default): open that TCP port to the entry in your cloud firewall.
- An I2P front and an upstream entry (`avpn preferences --upstream-interface`) are exclusive.

## See also

`avpn help init`, `avpn help threat-model`, `avpn help mix`.

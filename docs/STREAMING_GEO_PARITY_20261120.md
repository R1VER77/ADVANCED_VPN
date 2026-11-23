# Streaming geo-unblocking: how detection works and what parity requires

Triggered 20 November 2026 by the owner: *"a gap we are not looking at is
the ability of some VPNs to achieve geo unblocking for various streaming
services like BBC iPlayer, Netflix etc. Some may offer IP addresses in
that region but it does not always translate into geo unblocking as the
services still detect the VPN etc. We need to ensure this VPN can achieve
the same."*

The prior gap-doc row (§2 gap #4) said *"No equivalent and none should be
faked… A 'works with service X' claim needs live evidence per service,
per exit."* That stance is honest but passive. This document is the
active version: how detection works, what structural position this
project's BYO-exit model actually has, and what engineering closes the
gap without faking anything.

Sources inspected 20 November 2026:
[Netflix's own VPN notice](https://help.netflix.com/en/node/114701),
[devrunners: I Self-Hosted a VPN on a VPS. Streaming Blocked It](https://devrunners.com/blog/self-hosted-vpn-vs-commercial-vpn)
(Aug 2026 — "the IP resolved to AWS"),
[r/oraclecloud: Netflix via Oracle Cloud VM VPN](https://www.reddit.com/r/oraclecloud/comments/u7cx7m/)
("Netflix blocks oracle, google and aws ip ranges. Only rarely it
works, and then also get stopped soon. Best to get a small VPS from a
small [provider]"),
[r/selfhosted: Server for VPN (Netflix block?)](https://www.reddit.com/r/selfhosted/comments/14gvc12/)
("My server from Hetzner all block from Netflix"),
[r/iplayer: BBC iPlayer through VPS host](https://www.reddit.com/r/iplayer/comments/1tfosvs/)
(both VPNs' UK servers blocked from May 2026),
[cyberinsider: Best VPN for BBC iPlayer — Only 3 Still Work](https://cyberinsider.com/vpn/best/bbc-iplayer)
(Sep 2026),
[MaxMind GeoIP / IP intelligence for geo-blocking](https://www.maxmind.com)
(the licensed GeoIP database streaming services use),
[a 2026 residential-proxy study](https://www.google.com/search?q=Evading+Residential+Proxy+Networks)
("Free VPN services may enroll users' devices in a residential proxy
network, without obtaining their consent").

## 1. How streaming services actually detect VPNs

Six distinct mechanisms, in order of how hard they are to defeat:

1. **IP-range class blocking** (the primary mechanism). Netflix licenses
   [MaxMind GeoIP](https://www.maxmind.com) and similar IP-intelligence
   databases that classify every IPv4/IPv6 address as *residential*,
   *mobile*, *corporate*, or *hosting/datacenter*. Streaming services
   block or restrict the *entire hosting class* for premium catalogs.
   This is not per-IP reputation for most services — it is per-ASN or
   per-range. Oracle Cloud, Google Cloud, AWS, Hetzner's main ranges and
   OVH's main ranges are **pre-blocked as classes**, before any
   behavioral signal exists.
2. **ASN ownership flags.** If the IP's ASN belongs to a known VPN
   provider (M247, Datacamp, Tefincom, etc.), flagged instantly. This
   is the mechanism that commercial VPNs' "clean IP" teams fight by
   rotating to unlisted ranges.
3. **Concurrent-use behavioral fingerprinting.** A commercial VPN exit
   IP has hundreds of simultaneous streams from different accounts,
   device profiles and content. Services flag this pattern. A
   single-tenant exit never triggers it.
4. **GPS / timezone / language / WebRTC cross-checks** (client-side,
   mostly mobile). The IP says UK; the device's GPS says Chicago; the
   service refuses. This is not VPN-side and cannot be fixed by any
   exit choice.
5. **Session/device fingerprinting** (Widevine level, canvas, fonts).
   Not VPN-side either.
6. **Protocol / TLS fingerprinting of the tunnel transport itself**
   (added 21 November 2026; the original five-mechanism list under-counted
   this). 2026-era DPI combines TLS SNI inspection, JA3/JA4+ client-hello
   fingerprinting, ML-based packet-timing and entropy analysis, and
   hosting-class IP reputation
   ([Cloudflare JA4 signals](https://blog.cloudflare.com/ja4-signals);
   [APNIC on JA4 network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting)).
   **WireGuard traffic specifically is detectable** by its handshake
   signature and transport entropy regardless of IP class — Netflix
   detecting a WireGuard VPN behind a residential IP is a documented
   2026 report — and the AmneziaWG fork exists specifically to break
   that signature. This project's answer is already in the design: the
   HTTP/3 cloak is real QUIC (with a TLS-exporter proof and a decoy
   origin) with a TCP-443 fallback — not WireGuard-on-443 — so an exit's
   transport profile is part of its eligibility, and §4.1's probe
   records it alongside the IP class.

The practical consequence: **mechanism 1 is the one that decides
nearly everything**, and it is decided at the IP-class level before
your traffic is ever observed. If your exit IP is in a pre-blocked
hosting range, no amount of single-tenant cleanliness helps. If it is
in an unlisted small-provider range, you often pass with no further
checks. Mechanism 6 is the second VPN-side mechanism, and it is why an
eligibility claim that does not name the transport it was measured on
is incomplete.

## 2. What the market's winners actually do

Commercial VPNs that reliably unblock Netflix/BBC iPlayer (Nord,
Surfshark, ExpressVPN, Proton — the "still work in 2026" set) do it
through **continuous operational investment**, not a static feature:

- dedicated "streaming" server pools whose IP ranges are not in the
  hosting-class blocklists (often freshly acquired ranges);
- teams that monitor blocklists and rotate IPs faster than services
  block them ("stay ahead of Netflix's blocks by regularly refreshing
  the IPs they [use]" — the 2026 recommendations all describe the same
  arms race);
- **dedicated-IP add-ons** (Nord, Surfshark, ExpressVPN) sold
  specifically as the streaming-reliable tier — the honest admission
  that shared pools lose the arms race;
- a minority route: **residential-proxy VPNs** (StarVPN, Mysterium,
  Bright Data) that route through real home connections. This is the
  only approach that defeats mechanism 1 outright, because the IP class
  is genuinely residential. It is also frequently non-consensual on the
  proxy-host side (the 2026 study: "Free VPN services may enroll users'
  devices in a residential proxy network, without obtaining their
  consent"). Declined here on ethical grounds; see §6.

This project cannot and should not replicate the first three (they
require a company, staff, and a VPN-provider identity that would put
its own ASNs on the blocklists). It can do something different.

## 3. This project's actual structural position

The BYO-exit model has one genuine advantage and two genuine
disadvantages versus the commercial set:

**Advantage — the single-tenant, unlisted exit.** A self-owned exit on
a small cloud provider's IP range:

- is not in any VPN provider's ASN;
- carries a single user's behavioral pattern (mechanism 3 never
  triggers);
- if the provider's ranges are not yet in the hosting-class blocklist
  (true for many small and regional providers), passes mechanism 1
  outright.

The community evidence is consistent: the self-hosters who report
streaming success are the ones on *small* providers' fresh ranges
(Linode/DigitalOcean/Vultr historically; regional providers
currently), and the ones who report failure are on Oracle, AWS,
Google and Hetzner. The owner's current OCI exit is in Oracle's
ranges — **almost certainly Netflix-blocked today**, and this should
be tested rather than assumed either way.

**Disadvantage 1 — no arms-race team.** When an exit's range gets
listed, there is no staff to notice and rotate. The mitigation is a
probe (see §4.1), not a monitoring service.

**Disadvantage 2 — mesh fan-in reintroduces sharing.** A mesh exit
carries multiple members' traffic, which recreates the
concurrent-use pattern of mechanism 3 (though at much smaller scale
than a commercial VPN). The honest answer is per-exit
`toS_class`/eligibility labelling (already designed in
[PATH_SELECTION_DESIGN.md](PATH_SELECTION_DESIGN.md) §2, §6.1), not a
blanket claim.

## 4. The engineering that closes the gap (proposed)

Five concrete pieces, none of which fakes anything. **Status 21
November 2026: all five are implemented in-sandbox** — the probe
(`tools/stream_check.py`, transport profile included), the table
(`tools/streaming_table.py`), the recipe (§4.3 below), the rotation
tooling (`tools/ip_rotation.py`, `cypherpunk cloud rotate`) and the claim
format (§4.5, carried into the comparison doc). What remains live-only:
running the probe against real services from a real exit
(`CPVPN_STREAM_CHECK_LIVE=1`), and rotating a real provider's IP —
both need the owner's credentials.

### 4.1 A per-exit, per-service eligibility probe (`cypherpunk stream-check`)

A CLI command that tests a given exit against a given service, from
the client, through the tunnel, and prints the result with a
timestamp. Concretely:

- connect through the chain to the exit;
- fetch the service's region-eligibility endpoint (Netflix's
  `/api/.../auth` region response, BBC iPlayer's geo gate, Disney+'s
  token endpoint) or the catalog manifest that differs by region;
- parse the response for the "proxy/unblocker detected" error vs a
  real region response;
- write the result into the exit's descriptor as a dated,
  signed field: `streaming: [{service: netflix, region: UK, result:
  eligible|blocked, checked: 2026-11-20T…}]`;
- **record the transport profile of the tested path** (cloak /
  tcp443 / i2p-front / tor-front / direct) next to the result — added
  21 November 2026 per the sixth mechanism in §1: the 2026 detection
  stacks fingerprint the tunnel transport (JA3/JA4, WireGuard handshake
  entropy) as well as the IP class, so an eligibility claim without
  the transport it was measured on is incomplete. The implemented
  probe does this.

This is the `toS_class` concept from PATH_SELECTION §2 made
operational and evidence-producing. It is the difference between
"this exit is in a datacenter range" (a guess) and "this exit was
measured eligible for BBC iPlayer on 20 November 2026" (a fact).

No promise is made for the future; the timestamp is the honesty
mechanism. The streaming profile (§6.1) then filters exits by this
field, exactly as designed.

### 4.2 A cloud-provider streaming-eligibility table (evidence, version-pinned)

A maintained table in the docs, in the RATE_CLASSES evidence style,
recording which cloud providers' ranges currently pass which
services, with the check date and the exit's region:

| Provider | Region | Netflix | BBC iPlayer | Disney+ | Checked |
|---|---|---|---|---|---|
| Oracle Cloud | UK | blocked (class) | TBD | TBD | 2026-11-20 |
| Hetzner | DE/UK | blocked (class) | TBD | TBD | 2026-11-20 |
| AWS | any | blocked (class) | blocked (class) | blocked | 2026-11-20 |
| small/regional provider A | UK | TBD | TBD | TBD | — |

This is user-maintainable: anyone running `cypherpunk stream-check`
contributes a row. The table is version-pinned per release, like
every other evidence file, and dated entries expire visibly. The
`tools/providers.py` catalog already tracks provider metadata; this
is its streaming-companion.

### 4.3 A "recommended streaming exit" recipe

A specific, documented recipe for the exit that wants streaming
eligibility: small-provider VPS in the target region (not Oracle, not
AWS, not Hetzner main ranges), **one whose range is not yet publicly
listed in the IP-intelligence hosting buckets** (a provider that
advertises "streaming-friendly VPS" publicly is on its way onto the
blocklists; the eligibility window starts when the range is first
allocated, not when it is famous), single-tenant, `toS_class`-labelled,
`exit_policy` admitting the service's ports, and the streaming profile
(2-hop, line rate). The OpenTofu whole-registry search (in progress)
can mark recipes that satisfy this shape.

### 4.4 IP-rotation tooling

When a probe shows the exit's IP is newly blocked, the operator needs
a short path to a fresh IP: release and re-acquire the provider's
ephemeral IP, or reprovision in a different region, then re-run the
enrollment. Most providers allow this; the existing `cypherpunk cloud`
surface is the right place. This is the arms race on the user's own
terms — each user rotates their own exit, rather than relying on a
VPN company's team.

### 4.5 The honest claim format

The claim, wherever made (README, comparison doc, GUI), is never
"works with Netflix". It is: *"Streaming eligibility is measured per
exit, per service, dated in the exit's descriptor; run
`cypherpunk stream-check` to test yours."* This is stronger than a
commercial claim because it is falsifiable and reproducible, and it
is what the project's evidence rules already require everywhere else.

## 5. What must not be built

1. **Residential-proxy integration.** The only approach that defeats
   mechanism 1 outright. Declined — and the declination is precise
   about the two tiers that exist (sharpened 21 November 2026):

   - **The compromised-device tier** (StarVPN, Mysterium, Bright
     Data): residential IPs sourced from proxy hosts who frequently
     did not consent (the 2026 study above; the Bright Data /
     free-VPN enrollment scandals). Declined on ethical grounds: it
     contradicts the project's ethics (PRINCIPLES §6) and would import
     exactly the opaque third-party data problem the project exists to
     avoid.
   - **The ethical-lease tier** (TorGuard's residential IPs at
     $19.99/mo, Surflare's "Static ISP IPs"): dedicated static
     residential IPs leased in blocks registered to real ISPs — not
     compromised devices, but commercial carrier leases. Still
     declined, on different grounds: it requires a recurring third-
     party dependency on a residential-IP broker, a payment
     relationship this project does not have, and it imports the
     broker's own blocklist trajectory (a leased block that gets
     popular gets listed). The distinction matters because the
     ethical argument against tier one is consent; the argument
     against tier two is structural dependence — neither tier is
     compatible, but for stated, different reasons.
2. **A "works with service X" promise.** Any static promise decays as
   blocklists update; the honest form is the dated probe result.
3. **SmartDNS.** Already declined (gap #9): unencrypted DNS spoofing
   contradicts the signed-blocklist DoT design.
4. **A bundled curated-IP pool.** Would make this project a VPN
   company with its own ASN on the blocklists. Contradicts the
   no-company model and puts a target on the fleet.

## 6. What this gives the user, honestly stated

| Scenario | Commercial VPN | This project after §4 |
|---|---|---|
| Stream a service from a region where you own a small-provider exit | Works until the provider's range is listed, then waits for the VPN's rotation team | Same eligibility window, but **you** rotate (`stream-check` + IP rotation), and the descriptor records the fact |
| Stream from a major-cloud exit (OCI/AWS/GCP/Hetzner) | Works only if the provider has streaming servers there | **Blocked, honestly labelled** by `stream-check` and the table; the fix is the recipe in §4.3, not a promise |
| Stream through a mesh exit | n/a (no mesh) | Eligibility is per-exit and dated; fan-in may shorten the eligibility window; the descriptor says which |
| Streaming while mobile with GPS mismatch | Blocked by GPS cross-check | Same — client-side, not fixable at the exit |

The honest headline: **parity is achievable for the owner-operator who
follows the recipe; it is not a fleet-wide property and will not be
claimed as one.** That is the same honesty position as the throughput
row (gap #3): the defense has a cost, the cost is published, and the
user decides.

## 7. Roadmap fit

- §4.1 (`stream-check`) is a new tool + descriptor field + evidence
  file. Small, well-scoped, testable, and the foundation for
  everything else in §4.
- §4.2 (the table) is a docs artifact with a generation script,
  parallel to `tools/providers.py`.
- §4.3 (the recipe) is documentation plus possibly an OpenTofu
  recipe flag in the registry search.
- §4.4 (IP rotation) extends `cypherpunk cloud` with a provider-agnostic
  release/acquire path; provider-specific quirks live where the other
  cloud quirks do.
- §4.5 (the claim format) is a one-paragraph addition to README and
  COMPARISON.md discipline.

## 8. Decisions requested

1. **Approve the `cypherpunk stream-check` tool** (§4.1) as the next
   concrete step: probe, dated descriptor field, evidence file. This
   is the piece that converts the gap from "documented limitation" to
   "measured capability".
2. **Approve the eligibility-table format** (§4.2) and its home
   (docs, generated by a tool, version-pinned per release).
3. **Approve the streaming-exit recipe direction** (§4.3) — small
   provider, single-tenant, streaming profile — as the documented
   recommendation, without endorsing a specific commercial provider
   by name in the docs.
4. **Confirm the declinations** (§5): residential proxies, static
   promises, SmartDNS (already declined), curated IP pool.
5. **Test the owner's current OCI exit** against Netflix and BBC
   iPlayer as the first entry in the table — the Oracle ranges are
   believed blocked, but the first row should be measured, not
   assumed.

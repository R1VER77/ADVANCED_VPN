# Commercial feature-parity gap analysis

Deep-dive comparison against the full conventional commercial VPN feature
set — not only the privacy leaders already covered in
[COMPARISON.md](COMPARISON.md) (Mullvad, IVPN), but the mass-market
products (NordVPN, ExpressVPN, Surfshark, Proton, PIA, CyberGhost,
Windscribe). Sources inspected November 2026:
[Mullvad's feature matrix](https://mullvad.net/en/why-mullvad-vpn) and
[multihop modes](https://mullvad.net/en/blog/introducing-multihop-modes),
[NordVPN features](https://nordvpn.com/features/),
[ExpressVPN features](https://www.expressvpn.com/features),
[Surfshark features](https://surfshark.com/features),
[Proton VPN features](https://protonvpn.com/features),
[port forwarding](https://protonvpn.com/support/port-forwarding) and
[Tor over VPN](https://protonvpn.com/features/tor-over-vpn),
[NordVPN's specialty server categories](https://support.nordvpn.com/hc/en-us/articles/19479130821521-Different-NordVPN-server-categories-explained)
(Onion over VPN, Double VPN, obfuscated, P2P, Dedicated IP),
[NordVPN SOCKS5](https://nordvpn.com/blog/socks5-proxy/),
[ExpressVPN's post-quantum work](https://www.expressvpn.com/vpn/quantum-vpn) and
[encryption history](https://www.expressvpn.com/vpn/history-of-expressvpn-encryption),
[Windscribe features](https://windscribe.com/features) (Double Hop, static IP,
port forwarding, R.O.B.E.R.T.), [Astrill's feature list](https://www.astrill.com/features),
and the PIA/Windscribe/CyberGhost sets as summarized by
[vpnMentor's 2026 comparison](https://www.vpnmentor.com/vpn-comparison/private-internet-access-vs-windscribe-vpn).
A second per-provider sweep (Nord, Express, Surfshark, Proton, PIA,
CyberGhost, Windscribe, Mullvad, IVPN, Astrill, PureVPN, IPVanish,
hide.me, TunnelBear, Mozilla VPN, Hotspot Shield) on 20 November found the
additions in §5. A third sweep the same day deep-dived the enthusiast and
niche providers — [AirVPN](https://airvpn.org) ([specs](https://airvpn.org/specs),
[Tor modes](https://airvpn.org/tor)), Perfect Privacy (since
[shut down](https://cyberinsider.com/vpn/reviews/perfect-privacy)),
[hide.me](https://hide.me/en/features) ([port
forwarding](https://hide.me/en/vpn-port-forwarding)),
[OVPN](https://www.ovpn.com/en/features/multihop) and
[AzireVPN](https://www.azirevpn.com/service/security) — plus the majors'
late-2026 changes (Mullvad's August 2026
[multihop modes](https://mullvad.net/en/blog/introducing-multihop-modes)
and [OpenVPN removal](https://mullvad.net/en/blog/removing-openvpn-15th-january-2026),
ExpressVPN's [Aircove discontinuation](https://www.expressvpn.com/aircove),
Nord Security's [Saily](https://saily.com) eSIM); its rows are §5.3.

The aim, per the owner: **prove every feature of conventional VPNs and
more.** Per this project's evidence rules, every row states *landed*,
*planned*, *declined (with reason)* or *missing (gap)* — a plan is not a
feature, and neither is a declined row a gap.

## 1. Where this VPN already exceeds the commercial set

| Feature | Conventional best | This project | Verdict |
|---|---|---|---|
| Post-quantum crypto | **ExpressVPN shipped ML-KEM into Lightway and WireGuard (January 2025, all platforms)**; Mullvad: Rosenpass on some clients; everyone else: classical only. PQ is now *parity on key exchange* at the top end | PQ **KEX** parity-plus, but exceeds on **scope**: ML-DSA-65-only authentication on every layer, PQ OHTTP control plane, PQ (X-Wing) mix lane, hybrid PQ sealing — nobody else authenticates post-quantum | **Exceeds on scope**; KEX parity with Express |
| Traffic-analysis defense | Mullvad DAITA v2, first link only, event-driven | Constant-rate bidirectional on every hop; measured at/below chance; mix lane vs global adversary; I2P front | **Exceeds** |
| Multi-hop | 2 hops (Mullvad/IVPN/Proton Secure Core), 3–4 hops (Nord/Proton "Plus" variants) — all within one company's fleet | 1–3 hops across **distinct operators, providers, countries**; sticky guard; signed failover windows; parallel chains proposed | **Exceeds on separation**, parity on depth |
| No-logs | Policy + audit + RAM servers (trust) | Zero persistent state *by construction* (tmpfs-only, CI-verified) — nothing to log, nothing to seize | **Exceeds** |
| Anonymous signup/payment | Mullvad numbered accounts, cash/Monero | No account, no payment; hardware-anchored identity; contribution-based mesh | **Exceeds** |
| Device/connection limit | Unlimited (Surfshark) or 5–10 devices elsewhere | No limit model at all; multi-member fan-in | **Exceeds** |
| Dedicated IP | Paid add-on (Nord, others) | You *own* the exit node — a dedicated IP by construction, self-controlled | **Exceeds** |
| Censorship circumvention | Shadowsocks/udp2tcp/LWO (Mullvad), NordWhisper, Proton Stealth | QUIC/HTTP-3 cloak with TLS-exporter proof, HTML5 decoy origin, TCP-443 fallback, I2P front | **Parity or exceeds** (multi-browser fingerprint mimicry still roadmap) |
| Ad/tracker/malware blocking | DNS blocklists (all) + URL-level (Nord Threat Protection) | Signed local DNS blocklist inside the tunnel, NXDOMAIN before upstream DoT; recursive exit resolver (19 Nov) | **Parity at DNS level**; URL-level declined |
| Split tunneling | Per-app exclusion (Mullvad, Express, all) | **Inverted by design**: `avpn run` tunnels per application, fail-secure — deny-by-default rather than allow-by-default | **Parity, stronger model** |
| Kill switch | All | Fail-closed namespace guard, mutation-checked, STUN/WebRTC/resolver leak tests | **Parity** |
| Formal verification | None | Tamarin/ProVerif models in CI, Kani, fuzzing | **Exceeds** |

## 2. The real gaps — ranked by user impact

These are the rows where a conventional VPN user would find this project
missing something today. Nothing here is unfixable; each has a path.

| # | Gap | Conventional state | Path to parity |
|---|---|---|---|
| 1 | **Platforms beyond Linux x86_64** | Native apps for Windows, macOS, iOS, Android on day one | Roadmap Task 7F exists (aarch64 → Android → macOS → Windows → iOS, each with protection tests). aarch64 CI landed 19 Nov. Biggest single project on the list. |
| 2 | **Graphical one-click client** | Polished GUI apps with a map, big connect button | Native WebKit GUI is in progress (absent-controller rendering already tested); full create/join branches are the open Tasks 5–6 gate. |
| 3 | **Throughput ceiling** | Mullvad: multi-Gbit servers, 10 Gbps ports; Express "Turbo" multi-tunnel | `line` class measured ~115–123 Mbit/s. Constant-rate shaping is the cost of the defense; paths: faster line classes on faster links, multi-path streaming profile (see [PATH_SELECTION_DESIGN.md](PATH_SELECTION_DESIGN.md) §6.1). Honest speed claims only with published deltas. |
| 4 | **Streaming/geo-unblocking** | Dedicated streaming servers, curated IP reputation, dedicated-IP add-ons, continuous IP-rotation teams (the "still work in 2026" providers run an active arms race); residential-proxy VPNs defeat detection outright but unethically | **Structurally winnable for the owner-operator, not fleet-wide.** The BYO-exit model's single-tenant, unlisted-IP advantage is real (no VPN-provider ASN, no concurrent-stream fingerprint) but major-cloud ranges (Oracle/AWS/GCP/Hetzner) are class-blocked and the current OCI exit is almost certainly Netflix-blocked. The concrete path is in [STREAMING_GEO_PARITY_20261120.md](STREAMING_GEO_PARITY_20261120.md): (1) `avpn stream-check` — a per-exit, per-service probe with dated, signed descriptor results; (2) a version-pinned cloud-provider eligibility table; (3) a small-provider streaming-exit recipe; (4) IP-rotation tooling; (5) the honest claim format ("measured per exit, dated, run the probe"). Residential-proxy integration is declined on ethics. A blanket "works with X" claim will not be made; eligibility is a measured, dated fact |
| 5 | **Port forwarding** | Mullvad, Proton, PIA, Windscribe, hide.me (dynamic UPnP/NAT-PMP), AirVPN (with DDNS) offer forwarded ports | Missing. Design already drafted in [PATH_SELECTION_DESIGN.md](PATH_SELECTION_DESIGN.md) §6.2: opt-in exit port admission, never required, plan-labelled. For consumer parity the admission should speak **NAT-PMP/UPnP** (hide.me's dynamic model) and support **DDNS naming** of dynamic exits (AirVPN), not static-manual rules only. Needs the same abuse/ToS caution the mesh already records for exits. |
| 6 | **IPv6 tunneling** | Mullvad tunnels IPv6 (WireGuard, since the OpenVPN removal); AirVPN ships dual-stack entries (4×IPv4 + 4×IPv6 per server); most mass-market apps partial | IPv6 is currently *blocked*, not tunneled (SUPPORT_MATRIX). Blocking is fail-closed and safe; tunneling IPv6 is a real gap for IPv6-heavy networks. Needs cloak/link/relay IPv6 support plus dual-stack leak tests. |
| 7 | **Router / always-on-box support** | Express/Nord/Surfshark router apps, pfSense/OpenWrt guides; Express sold the Aircove appliance until discontinuing it in 2026; its successor "Fortify" is a co-branded [GL.iNet Flint 2 (GL-MT6000)](https://www.gl-inet.com/en-us/blogs/blog/glinet-and-expressvpn-launch-fortify-vpn-router) — the de-facto hardware target is now GL.iNet | Missing. The single-tenant mode is naturally router-shaped (headless, no GUI needed). Concrete target per the [Aircove post-mortem](AIRCOVE_POSTMORTEM_20261120.md): package for OpenWrt aarch64 on GL-MT6000 (home, Wi-Fi 6 AX6000, 900 Mbps WireGuard ceiling) and GL-MT3000 Beryl AX (travel, pocket-sized). Recipes: home single-tenant, travel with Wi-Fi-link upstream. Per-device VPN groups (Aircove's most useful primitive) are a planned profile extension once the router deployment is proven. No hardware product — the appliance itself is declined (Aircove's discontinuation is the case study). |
| 8 | **Auto-connect on untrusted networks** | All majors | Missing convenience feature; fits the existing preflight/guard model (trigger = new network, action = namespace up). Small, well-scoped. |
| 9 | **Smart DNS / media DNS** | Nord/Express SmartDNS (unencrypted DNS redirection for TVs) | Declined-shaped: SmartDNS is *unencrypted* DNS spoofing — it contradicts the signed-blocklist DoT design. If ever offered it must be clearly labelled as a non-private mode. Recommend declining and documenting why. |
| 10 | **Independent audit** | Mullvad/IVPN/Proton periodic external audits | Roadmap §2/§4 open item; review package prepared. The formal models + fuzzing in CI are necessary but explicitly *not* a substitute. |
| 11 | **24/7 human support, refunds, trials** | All majors | Structural: no company. The equivalent is documentation, `avpn` diagnostics, and the managed-validation evidence trail. The five non-admin usability sessions (roadmap) are the honest substitute for "is it usable without support?" |
| 12 | **Browser extensions** | Express/Nord proxy extensions | Missing; also threat-model-hostile (proxy extensions cover browser traffic only, implying the rest is unprotected). If built, must refuse to appear as "protection" (label as partial). |
| 13 | **Identity-bundle features** (Nord/Surfshark: breach monitoring, password manager, Alternative ID, antivirus) | Bundled by majors | Out of scope by design — each is a separate product with its own data problem. The mesh pseudonym (`!xxxxxxxx`) is the Alternative ID analog; decline the rest. |
| 14 | **GPS spoofing / mock location** | Surfshark, Nord (Android) | Missing; mobile-platform item only (depends on #1). |
| 15 | **Server fleet geography** | 100+ countries, thousands of servers | Different model: your nodes + mesh pool. The honest answer is the OpenTofu whole-registry rollout (in progress) plus mesh growth; "countries covered" is a mesh-size metric, not a feature to build. |

## 3. Features deliberately declined (not gaps)

1. **Allow-list split tunneling** — declined: it lowers protection by
   design; per-app tunneling is the fail-secure inversion
   ([DESIGN_PACK_ASSESSMENT.md](DESIGN_PACK_ASSESSMENT.md)).
2. **URL-level "Threat Protection"** (script/malware filtering at the
   exit) — the exit must stay a dumb pipe: URL filtering at a shared exit
   is both a censorship surface and a performance liar. DNS-level
   blocking is the privacy-preserving subset and is landed.
3. **SmartDNS** — unencrypted by construction (see gap #9 wording).
4. **A bundled catalog of anything** (magnet search, "popular sites"
   shortcuts) — curation makes the product a target and contradicts the
   dumb-pipe exit posture (PATH_SELECTION_DESIGN.md §6.2).
5. **eSIM travel-data products** (Nord Security's Saily) — a separate
   connectivity product with its own data model; bundling it would repeat
   the identity-bundle mistake (gap #13).

## 4. What "and more" already looks like (the moat)

Beyond parity, the features no conventional VPN offers at any price:

- Full-membership `1/N` indistinguishability (mesh fan-in + always-on
  cover) vs "trust our fleet".
- The mix lane (`avpn mix`) and I2P front — global-adversary and
  address-hiding options that no commercial product has.
- Hardware custody of *every* key (FIDO2 hmac-secret/TPM2 sealing,
  hardware-signed enrollment, hardware-bound sessions).
- **Operator-Nitrokey-locked server keys for hosts without a TPM2**
  (commit `cabe084`, 20 Nov 2026). The free-tier OCI Always Free Ubuntu
  22.04 exit case — no vTPM — previously kept plaintext keys (incident
  logged); now keys are PQ-hybrid-encrypted (X25519 + ML-KEM-768) to the
  operator's Nitrokey, held in RAM only, refused on boot until the
  operator unwraps, plain or host-key-only keys *replaced never
  re-wrapped*. AzireVPN's Blind Operator blocks SSH/console but does not
  protect on-disk keys from seizure; this design protects the keys
  even with disk in hand.
- Verifiable relays roadmap (TPM2/SEV-SNP attestation in descriptors)
  vs claimed "RAM-only".
- Legal-sphere diversity enforced in the chain planner vs one legal
  entity at both ends.

## 5. Second sweep: features found in the per-provider deep dive

Rows found missing from the first pass, led by the one the owner
flagged:

### 5.1 Tor integration (NordVPN "Onion over VPN", Proton "Tor over VPN"; Mullvad publishes a VPN-over-Tor guide)

Three distinct products are bundled under this label, with different
analogs here:

| Variant | What it is | Status here | Path |
|---|---|---|---|
| **Tor over VPN** (Nord, Proton) — client → VPN → Tor → internet, .onion reachable without Tor Browser | A VPN fleet exits into Tor circuits | **Missing as a named mode.** Per-app tunneling can carry Tor Browser today (`avpn run` on the Tor process), but that is untested, undocumented and unproven — not a feature yet | Document + test the "Tor Browser inside the namespace" recipe: leak suite extended with a Tor-specific case (entry must see only Tor guard traffic), then it is a *proved* mode |
| **VPN over Tor** — client reaches the VPN entry *through* Tor | Mullvad's official guide (OpenVPN over Tor SOCKS); **AirVPN runs "OpenVPN over Tor" as a standard transport on every server** — a decade of precedent that the composition works | **Structurally present as the I2P front** (`--front i2p`, same architecture with I2P instead of Tor: the entry never sees your address). A `--front tor` variant does not exist | Optional: clone the landed I2P-front pattern for Tor (SOCKS front to the entry), reusing its gate table and tests. Note the tradeoff: Tor guards are shared with other Tor users; I2P fronts are self-run |
| **.onion without Tor Browser** (Nord/Proton's selling point) | Exit-side SOCKS-to-onion translation | **No analog for interactive onion browsing.** The mix lane covers async low-volume traffic, not interactive .onion sessions | Genuine gap; the honest answer is the Tor-over-VPN recipe above (Tor Browser through the tunnel), which keeps onion crypto end-to-end instead of terminating it at a provider |

Security note worth recording in any recipe: Nord's Onion over VPN
requires OpenVPN (not WireGuard) and trusts the provider to run the Tor
side; both are weaknesses this design does not inherit — carrying Tor
Browser through the tunnel keeps Tor's own path selection intact.

### 5.2 Other newly found rows

| Feature | Conventional state | Status here |
|---|---|---|
| SOCKS5 proxy (Nord, IPVanish) | Offered for proxy-capable apps | **Declined-shaped**: per-app tunneling covers the same need with encryption — a SOCKS5 side-channel would be an unencrypted bypass. Document the declination |
| RAM-only/diskless servers (Mullvad since 2023, IVPN, Proton Secure Core) | Claimed posture | **Exceeds in mechanism** (tmpfs-only, CI-verified); verifiable attestation (TPM2/SEV-SNP in descriptors) is the roadmap row that turns claim into proof |
| Warrant canary (IVPN, others) | Company legal-transparency tool | **Not applicable — no company to receive warrants.** The analog is the hardware-signed commit history + incidents record + append-only descriptor log (roadmap). Worth a doc paragraph saying exactly that |
| Automatic WireGuard key rotation (Mullvad) | Client-side automatic | **Covered by session architecture** (hardware-bound session keys, short-lived certs, rotation inside signed windows); document the mapping |
| Server-side outbound port policies (Mullvad blocks 25/137-139/445/1900/2869) | Provider policy | **Planned via the descriptor `exit_policy` field** (PATH_SELECTION_DESIGN.md §2) — same capability, per-exit and signed instead of fleet-wide and silent |
| In-app problem reporting (Mullvad) | Built into app | Missing; diagnostics exist as files/CLI. Either a small UX item or a documented declination (telemetry-free posture) — owner's call |
| MAC spoofing (Windscribe) | Client-side L2 | Missing; minor, platform-dependent, folds into the platform ports work |
| Device-to-device networking (Nord Meshnet) | LAN-over-relay product | **Declined**: the mesh is an anonymity set, not a LAN; the DC-net private groups cover secure internal coordination |
| Site/app routing filters (Astrill) | Split tunneling by destination list | **Declined-shaped**: destination lists leak browsing intent to config and sync; per-app model already covers the legitimate need |
| Free tier (Proton, Windscribe, hide.me, TunnelBear) | Limited free service | **Different model, arguably exceeds**: contribution-based membership — an always-free cloud VM *is* the membership fee; no subsidised-user data model at all |
| Antivirus/breach/identity bundles (Nord, IPVanish, Surfshark) | Paid add-ons | Already declined (§3) |
| WireGuard-over-QUIC (Mullvad) | Transport novelty | **Already present and stronger**: the HTTP/3 cloak is real QUIC with a TLS-exporter proof and decoy origin |

### 5.3 Third sweep: enthusiast/niche providers and late-2026 changes

Rows found in the 20 November deep dive of AirVPN, Perfect Privacy,
hide.me, OVPN and AzireVPN, plus the majors' 2026 changes:

| Feature | Conventional state | Status here |
|---|---|---|
| **User-chosen 4-hop cascades** (Perfect Privacy's signature feature) | Perfect Privacy offered up to 4 manually chosen cascade servers — **but shut down in 2026**; the deepest live commercial cascade is now Nord's 3-hop Double VPN routes | **Depth parity, honestly earned by market exit.** This design's 1–3 hops across distinct operators now equals the deepest live offering; a 4th hop is a trivial chain-planner extension if a headline parity claim ever needs it. No action recommended |
| Transport-embedding breadth (AirVPN: OpenVPN over SSH and over SSL on every server; Perfect Privacy "Stealth VPN" = HTTPS masking; Mullvad offered OpenVPN until removing it January 2026) | Several embedding personalities per provider | **Parity-minus on breadth, argued.** One strong persona (QUIC/HTTP-3 cloak with TLS-exporter proof + TCP-443 fallback) beats several unproven ones; multi-persona mimicry is already the roadmap row in §1. Path: add cloak personalities only when blocking evidence demands, not for the feature list |
| Dynamic port forwarding (hide.me: UPnP/NAT-PMP so consumer apps self-configure) and DDNS for dynamic exits (AirVPN) | Both shipped | **Folds into gap #5.** The exit-admission design (PATH_SELECTION_DESIGN.md §6.2) must speak NAT-PMP/UPnP for consumer parity, and DDNS naming is the exit owner's job — static-manual forwarding alone would read as 2010s engineering |
| Blind Operator — servers with SSH *and* console access disabled (AzireVPN); OVPN's paired physical/legal security posture | Operator-access elimination claims | **Now landed and exceeds.** AzireVPN's Blind Operator blocks remote/local access to its servers but does not protect the on-disk keys if the disk is seized (snapshot, backup, physical). The landed [operator-unlock feature](HARDWARE_BOUND_SESSIONS.md) (commit `cabe084`, 20 Nov) answers the same threat model differently: servers with a TPM2 seal their keys to it (unattended restart); servers without one — the free OCI Always Free Ubuntu 22.04 case, no vTPM — now lock their keys to the operator's Nitrokey under hybrid X25519 + ML-KEM-768, held in RAM only until reboot, refusals to load while locked, and the chain's signing touch also unwraps. Plain or host-key-only keys are *replaced, never re-wrapped* (deleting a file on a cloud disk does not erase earlier copies). Disk seizure yields ciphertext only. The [plaintext-key incident](INCIDENTS.md) that this closes (14–20 Nov) is published in the incidents log. The TPM2/SEV-SNP attestation roadmap turns the *claim* into proof for mesh relays; for self-owned exits the claim is already structurally stronger than Blind Operator |
| Hardware VPN router (ExpressVPN Aircove — discontinued from sale in 2026; GL.iNet-class routers ship vendor apps; Express's successor "Fortify" is a co-branded GL.iNet Flint 2) | A purchasable appliance | **Declined-shaped**: this project sells no hardware. The path is gap #7 extended: run the headless single-tenant mode on the GL.iNet-class hardware that the market has consolidated on (GL-MT6000 home, GL-MT3000 travel). [Aircove post-mortem](AIRCOVE_POSTMORTEM_20261120.md) analyses what to import (per-device groups, double-VPN passthrough, signature-verified auto-update) and what to decline (Lightway, custom hardware, AircoveOS UI) |
| Mullvad's August 2026 multihop modes (Always / When needed / Never, plus automatic entry choice) | Convenience presets on top of multihop | **Small parity item, planned by structure**: chain-planner profiles already exist conceptually (streaming profile, PATH_SELECTION §6.1); an "always/when-needed" preset is a GUI/profile item once Tasks 5–6 land |
| Full dual-stack entries — AirVPN publishes 4 IPv4 + 4 IPv6 entry addresses per server; Perfect Privacy had full IPv6 (pre-shutdown) | Standard at the enthusiast end | **Strengthens gap #6**: IPv6 tunneling is not just Mullvad; the niche providers ship it too, and blocking-only reads as behind even that tier |
| Server-side DNS blocklists (AirVPN block lists) | Provider-side filtering | **Already exceeded**: the signed local blocklist inside the tunnel (NXDOMAIN before upstream DoT, recursive exit resolver) is stronger — no provider-side visibility |
| NeuroRouting — server-side automatic multi-hop region routing (Perfect Privacy, pre-shutdown) | Automatic path optimization | **Present and stronger client-side**: the path-selection planner (PATH_SELECTION_DESIGN.md) does this without trusting a provider to route, and publishes the anonymity-set math |
| eSIM travel-data products (Nord Security's Saily, with ad blocking and "virtual location") | Adjacent commercial product | **Declined** (see §3 item 5): separate connectivity product; the bundle problem again — and "virtual location" on an eSIM app is marketing, not a tunnel |

## 6. Proof plan (how each row above gets *proved*, not claimed)

1. Every **exceeds/parity** row already names its evidence file; keep the
   COMPARISON.md discipline of version-pinned figures.
2. Gaps #1–2 (platforms, GUI): the existing roadmap gates are the proof;
   no new plan needed, only execution.
3. Gap #3 (throughput): publish a speed delta per rate class against a
   1-hop commercial baseline on identical links, in RATE_CLASSES style.
4. Gap #4 (streaming): per-service, per-exit live checks only, with the
   exit's IP class in the record; no blanket "unblocks X" claim.
5. Gap #5 (port forwarding): plan-shown, opt-in, abuse-guidance-linked
   admission; leak and ToS tests before any docs claim.
6. Gap #6 (IPv6): dual-stack leak suite (DNS/STUN/WebRTC/IPv6) extended
   before enabling tunneling.
7. Gap #10 (audit): the prepared review package + the formal-model
   results are the inputs; the gate stays "actual independent review".
8. Gaps #9, #12, #13: decisions to *document declination* — the parity
   claim is then "declined by design, reason published", which this
   project's ethos treats as superior to shipping a weak feature.
9. §5.3 rows inherit these rules: the 4-hop depth note needs only the
   market citation (Perfect Privacy's shutdown); the multihop-mode preset
   and travel-router recipe inherit gaps #2/#7's gates; the operator-access
   mapping is a doc paragraph plus the existing attestation roadmap row.
10. The [Aircove post-mortem](AIRCOVE_POSTMORTEM_20261120.md) adds one
    new roadmap candidate: a signature-verified deployment-side
    auto-update mechanism for router targets (Aircove's 4 a.m. local
    auto-update with verified-boot signature is the commercial analog).
    This sits on top of the existing signed-commit evidence trail and is
    distinct from it.
11. Gap #7's concrete GL.iNet targeting (GL-MT6000 / GL-MT3000) is the
    Aircove's successor's exact platform; there is no commercial argument
    for picking anything else. The per-device group model is the
    software idea most worth importing, after the router deployment
    itself lands.
12. Gap #4 (streaming): the probe, table, recipe, rotation and claim
    format from [STREAMING_GEO_PARITY_20261120.md](STREAMING_GEO_PARITY_20261120.md)
    §4 each get their own evidence trail — the probe writes the dated
    descriptor result, the table is generated and version-pinned like
    RATE_CLASSES, and the claim format replaces any static promise
    wherever it appears. The first table row must be a measured test of
    the owner's current OCI exit, not an assumption about Oracle ranges.

## 7. Owner decisions requested

1. Approve port forwarding as opt-in exit admission (gap #5) or decline.
2. Approve an IPv6 tunneling project (gap #6) and its priority relative
   to platform ports.
3. Approve auto-connect-on-untrusted-network work (gap #8) as a Tasks 5–6
   subitem.
4. Confirm declination of SmartDNS, browser extensions and identity
   bundles (#9, #12, #13) so the comparison doc can state it.
5. Decide whether "streaming parity" means the honest profile
   (PATH_SELECTION §6.1 option 1) or the labelled weaker option 2.
   **Superseded in part, 20 Nov**: the speed-profile choice (1 vs 2)
   remains open, but the *eligibility* half of streaming parity now has
   a concrete engineering path in
   [STREAMING_GEO_PARITY_20261120.md](STREAMING_GEO_PARITY_20261120.md) —
   approve its §4 package (probe, table, recipe, rotation, claim
   format) and confirm its §5 declinations (residential proxies, static
   promises, SmartDNS, curated pool).
6. Tor integration (new): approve (a) the tested Tor-Browser-through-the-
   tunnel recipe as the "Tor over VPN" equivalent, and (b) optionally a
   `--front tor` variant cloned from the I2P front (AirVPN has run exactly
   this composition fleet-wide for years; Mullvad documents it), or
   decline (b).
7. Chain depth (new): with Perfect Privacy gone, no live commercial VPN
   offers a user-chosen cascade deeper than 3 hops. Confirm 3 as the
   documented ceiling (recommended — depth parity is already true in the
   live market), or fund the trivial 4-hop chain-planner extension for a
   headline claim.
8. Port-forwarding shape (new, only if #1 is approved): static-manual
   admission only, or the consumer-shaped dynamic one (NAT-PMP/UPnP
   signaling plus DDNS, the hide.me/AirVPN model)? The dynamic form is what
   users expect but enlarges the exit's attack surface — decide before the
   §6.2 design is implemented.
9. Router platform (new, gap #7): confirm the GL.iNet targeting
   (GL-MT6000 home, GL-MT3000 travel) per the
   [Aircove post-mortem](AIRCOVE_POSTMORTEM_20261120.md). The market has
   consolidated on GL.iNet; ExpressVPN's pivot to a co-branded Flint 2 is
   the case study. Confirm "no hardware product" (already the stance).
10. Per-device group model (new): a planned profile extension once the
    router deployment lands, importing Aircove's most useful primitive.
    Approve as a documented extension, not a current priority.
11. Deployment-side auto-update (new): a signature-verified auto-update
    mechanism for router targets, layered on the signed-commit evidence
    trail. Approve as a new roadmap row, or decline (manual update only).

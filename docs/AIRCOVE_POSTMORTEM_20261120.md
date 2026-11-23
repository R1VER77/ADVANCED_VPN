# Aircove post-mortem: what to learn from the discontinued hardware VPN

Triggered 20 November 2026 by the owner's suggestion that we look at "the
only hardware VPN that is no longer on the market". This is the analysis:
how ExpressVPN's Aircove worked, why it died, and what (if anything) is
worth importing into this project.

The short version: **most of Aircove's good ideas are software, not
hardware. The hardware itself is what killed the product. The path
forward is not to clone the Aircove — it is to run our existing
software on the open travel-router hardware Aircove's successor is
built on.** That reframes gap #7 in
[COMMERCIAL_FEATURE_GAP_20261119.md](COMMERCIAL_FEATURE_GAP_20261119.md)
into a concrete target instead of a vague "needs a router recipe".

Sources inspected 20 November 2026:
[ExpressVPN Aircove how-it-works](https://www.expressvpn.com/aircove/how-it-works),
[Aircove tech specs](https://www.expressvpn.com/aircove/specs),
[GL.iNet + ExpressVPN Fortify announcement](https://www.gl-inet.com/en-us/blogs/blog/glinet-and-expressvpn-launch-fortify-vpn-router)
(Fortify = the Sept 2026 successor),
[Cure53 Aircove firmware pentest report (Nov 2024)](https://cure53.de/pentest-report_expressvpn-aircove_2024.pdf)
(referenced; PDF itself not fetchable from this sandbox, findings
reproduced from public snippets),
[FlashRouters coverage of the discontinuation](https://blog.flashrouters.com/2026/02/02/expressvpn-router-support-ending),
[Reddit r/Express_VPN: ExpressVPN killed off Aircove to partner directly with GL.iNet](https://www.reddit.com/r/VPNAdvice_/comments/1wjxh4g).

## 1. What Aircove actually was

### 1.1 Hardware (verified)

- **Wi-Fi 6 router**, dual-band (2.4 GHz up to 600 Mbps, 5 GHz up to 1200 Mbps)
- **Qualcomm IPQ6000** chipset, 1.2 GHz 64-bit quad-core CPU, 512 MB RAM, 128 MB flash
- 5 gigabit Ethernet ports (Aircove), 3 gigabit ports (Aircove Go portable variant)
- ~150 sq m / ~1600 sq ft coverage
- Max VPN throughput: **330 Mbps** (the practical ceiling after Lightway encryption)
- Two SKUs: Aircove (home) and Aircove Go (travel, 250 g, Wi-Fi link feature)

This was **custom Qualcomm-based hardware** — not a GL.iNet rebrand. The
Aircove was a from-scratch design with ExpressVPN's own firmware.

### 1.2 Firmware (AircoveOS) — verified features

AircoveOS is OpenWrt-derived (the Reddit thread documenting
[installing stock GL.iNet firmware on the Aircove](https://www.reddit.com/r/Express_VPN/comments/)
is the public confirmation). The notable features, in order of interest
to this project:

1. **Per-device VPN groups** (up to 5 groups). Each connected device can
   be assigned to a group; each group has its own VPN location, or
   "No VPN" (bypass), or "No internet" (block). This is router-level
   per-device routing — fundamentally more granular than per-app split
   tunneling because it covers devices that cannot run a VPN client
   (IoT, smart TVs, game consoles).
2. **"Lightway Passthrough"** — solves the double-VPN scenario. If the
   router has a VPN up and a downstream device also runs a VPN client,
   you normally get a nested tunnel with added latency and possible
   failure. AircoveOS detects the inner Lightway session and routes
   it directly. We have no equivalent.
3. **Internet Kill Switch** — blocks all traffic when the VPN drops.
   We have a kill switch, but at namespace level, not router level.
4. **Guest Wi-Fi with full isolation** — guest devices cannot
   communicate with main-network devices, but still benefit from VPN
   protection, ad/tracker blocking, anti-malware and content filtering.
5. **Custom DNS and port forwarding** for technical users.
6. **Auto-update at 4 a.m. local time**, with **signature verification**
   (per the [Cure53 pentest report](https://cure53.de/pentest-report_expressvpn-aircove_2024.pdf)
   snippet: *"The update will only be applied after successful
   verification. Consequently, the update and auto-update processes
   are sufficiently safeguarded"*). This is verified-boot-style
   firmware updates — the closest commercial equivalent to what this
   project's signed-commit history aims at.
7. **WPA3 Wi-Fi security**, dynamic DNS, port forwarding (Lightway Pro
   features added later in the product's life).
8. **Lightway protocol** (ExpressVPN's own, open-sourced 2024) —
   WireGuard-derived with TCP/UDP modes and session resumption.

### 1.3 What it did not have

- **No post-quantum cryptography** — Lightway uses classical key
  exchange. This project's PQ-everywhere posture is ahead.
- **No multi-hop across distinct operators** — Aircove ran a single
  ExpressVPN tunnel per group; the chain was always ExpressVPN's
  fleet. This project's operator-diverse chains have no analog.
- **No hardware key custody** — the router ran ExpressVPN's keys,
  not yours. This project's hardware-bound session architecture is
  materially stronger.
- **No anonymity-set model** — the Aircove protected one household
  behind one ExpressVPN IP. There was no mesh, no fan-in, no
  indistinguishability claim.
- **No formal verification** of the protocol or implementation.
- **No zero-state-by-construction** — the router kept state (your
  group assignments, your VPN credentials, your DNS config). ExpressVPN
  could be compelled to log, even if they claimed not to.

## 2. Why it died

ExpressVPN announced the Aircove's retirement on **16 September 2026**.
The successor, Fortify, is a **co-branded GL.iNet Flint 2 (GL-MT6000)**.
Aircove is supported through end of 2027; Aircove Go through end of
2028. After that, no security updates.

The stated reasons are corporate ("pivoting", "co-branded partnership")
but the actual story is straightforward economics:

1. **Custom Qualcomm-based hardware is expensive.** Designing a
   Qualcomm-IPQ6000 board, firmware, and a Cure53 audit, for a product
   that ships at consumer volumes, has unit economics that don't work
   unless you're a router company. ExpressVPN is not.
2. **GL.iNet already does this.** GL.iNet's entire product line is
   OpenWrt-on-旅行-routers with VPN support. Co-branding one of their
   existing designs (Flint 2) costs ExpressVPN zero hardware engineering
   and gets them a better product (AX6000 vs AX1800, 2.0 GHz quad-core
   vs 1.2 GHz, 1 GB DDR4 vs 512 MB, 8 GB eMMC vs 128 MB flash, WireGuard
   at 900 Mbps vs 330 Mbps).
3. **The hardware VPN market is small.** Most users want a VPN app on
   their phone or laptop, not a $200 appliance. The Aircove served a
   niche (whole-home VPN, IoT protection, travel) that GL.iNet already
   served better at lower cost.
4. **Firmware maintenance is forever.** AircoveOS is OpenWrt-derived;
   keeping it patched against the OpenWrt CVE stream, the Qualcomm
   bootloader CVE stream, the Wi-Fi stack CVE stream, the Lightway
   protocol CVE stream — indefinitely, across two SKUs — is a permanent
   cost. ExpressVPN judged the ongoing cost higher than the revenue.

The lesson for this project: **do not build hardware.** This was already
recorded as the §5.3 verdict in the gap doc; the Aircove's fate is the
case study that proves the point.

## 3. What is worth importing

The interesting ideas are software, not hardware. Ranked by fit with
this project's threat model:

### 3.1 Per-device VPN groups (high value, natural fit)

AircoveOS's groups — each with VPN location, "No VPN", or "No internet"
— are a router-level routing primitive. This project's current model is
per-application (`cypherpunk run`), which is fine for a single user's laptop
but does not cover:

- IoT devices that cannot run a VPN client
- Smart TVs, game consoles, streaming sticks
- A household where different people want different exit locations
- A guest network that should be VPN-protected but isolated

When this project lands on a router (gap #7), the per-device group model
is the right abstraction. The descriptor fields already exist
(`exit_policy`, `toS_class` from [PATH_SELECTION_DESIGN.md](PATH_SELECTION_DESIGN.md));
mapping them to per-device groups is a profile/CLI extension, not a
protocol change.

### 3.2 "Passthrough" mode for double-VPN (medium value, niche)

Aircove's "Lightway Passthrough" detects when a downstream device is
also running a VPN and routes the inner tunnel directly, avoiding
nesting. This is a real concern: a user with this project's tunnel up
on their router who then opens Tor Browser on their laptop gets a
nested path with added latency and possible failure.

The general principle — **detect inner VPN-like traffic at the router
and bypass the outer tunnel for it** — is worth a profile option. It
fits the existing cloak design: the cloak already inspects the inner
stream to choose its mimicry persona; an "inner-VPN passthrough"
detector is a natural extension.

### 3.3 Per-device "No internet" (low-medium value, useful primitive)

Aircove's third group option — "No internet" — blocks a device from the
internet entirely while keeping it on the LAN. Useful for IoT devices
you don't trust (cameras, smart speakers) that should be local-only.
Trivial to implement as an nftables rule per-device; worth a one-line
profile option.

### 3.4 Guest network isolation (low value, already standard)

OpenWrt has had guest Wi-Fi isolation for years. No new idea here;
just confirm the recipe works when this project runs on a router.

### 3.5 Auto-update with signature verification (high value, roadmap)

The Aircove's auto-update-at-4am with signature verification is the
commercial equivalent of what this project's signed-commit history
aims at on the source side. The deployment-side equivalent does not
exist yet: a user running this on a router has no automatic path from
"a new signed commit landed on main" to "their router pulled and
applied it overnight".

This is worth a roadmap item — but it is a deployment-side concern,
not a protocol concern. The signed-commit evidence trail is the
source-side foundation; the deployment-side auto-update mechanism
sits on top of it.

### 3.6 What to deliberately not import

- **Lightway protocol.** This project's cloak (QUIC/HTTP-3 with
  TLS-exporter proof) is stronger than Lightway. No reason to adopt.
- **AircoveOS group UI.** The router GUI is gap #2; the group model
  is the interesting part, not ExpressVPN's specific implementation.
- **Custom hardware.** Already declined (§5.3 of the gap doc). The
  Aircove's death is the validation.
- **WPA3 / guest Wi-Fi.** OpenWrt provides these; nothing to add.

## 4. What this means for gap #7 (router support)

The gap doc currently says: *"The single-tenant mode is naturally
router-shaped (headless, no GUI needed); needs a documented
OpenWrt/systemd-vm target, a GL.iNet-class travel-router recipe, and
package tests. No hardware product — the appliance itself is declined."*

The Aircove post-mortem lets us sharpen this. The de-facto hardware
target for VPN routers in 2026 is **GL.iNet**, and ExpressVPN has
effectively conceded the hardware layer to them. Concretely:

- **GL.iNet Flint 2 (GL-MT6000)** — the Fortify's base, AX6000, 2.0 GHz
  quad-core, 1 GB DDR4, 8 GB eMMC, WireGuard at 900 Mbps. This is the
  reference home-router target. OpenWrt 23/24 with full source.
- **GL.iNet Beryl AX (GL-MT3000)** — pocket-sized travel router,
  Wi-Fi 6, ~USD 80. The reference travel target. Same OpenWrt base.
- **GL.iNet Slate Plus (GL-A1300)** — older but cheap; the budget
  travel target.

All three run OpenWrt; all three are documented; GL.iNet's firmware is
open enough that the project's software can be installed as packages
without forking the firmware. The path to router parity is therefore:

1. **Package this project for OpenWrt** (aarch64, since GL.iNet's
   current lineup is MediaTek MT7986/MT7988 — aarch64).
2. **Document a GL-MT6000 home recipe** (single-tenant mode, no GUI
   needed; the existing `cypherpunk` CLI is sufficient).
3. **Document a GL-MT3000 travel recipe** with the Wi-Fi-link feature
   (connect to upstream Wi-Fi, tunnel downstream).
4. **Per-device group model** as a profile extension once the router
   deployment is proven.
5. **Auto-update mechanism** as a roadmap item on top of the
   signed-commit evidence trail.

This converts gap #7 from "needs a router recipe" to "needs packaging
for OpenWrt on GL-MT6000 / GL-MT3000, with these specific recipes" —
a concrete, scoped project rather than a vague aspiration.

## 5. The validation: this project's existing design beats Aircove on every axis except one

| Axis | Aircove (max) | This project (current) |
|---|---|---|
| Crypto | Lightway (classical) | PQ KEX + ML-DSA-65 everywhere |
| Multi-hop | 1 hop (ExpressVPN fleet) | 1–3 hops across distinct operators |
| Per-device routing | Up to 5 groups, per-device | Per-application (process-level) |
| Hardware key custody | Router-held ExpressVPN keys | Hardware-bound session keys (FIDO2/TPM2) |
| Logs | Policy + audit (claim) | Zero state by construction (CI-verified) |
| Anonymity set | None (1 household, 1 IP) | Mesh fan-in, `1/N` indistinguishability |
| Formal verification | None | Tamarin/ProVerif/Kani in CI |
| Auto-update | Yes, signature-verified | Signed commits (source); deployment-side auto-update is a roadmap item |
| Hardware | Custom Qualcomm (discontinued) | Bring-your-own (open travel routers) |
| Throughput | 330 Mbps (Lightway ceiling) | ~115–123 Mbps (constant-rate cost) |
| GUI | Polished, web-based | CLI + WebKit GUI in progress |

The two rows where Aircove wins today are **throughput** (gap #3, the
constant-rate cost) and **GUI polish** (gap #2, the WebKit GUI in
progress). Every other axis is already this project's; the Aircove
post-mortem is the case study that the hardware-VPN approach is not a
competitive moat once you control the software.

## 6. Decision requested

1. **Endorse the GL.iNet targeting** (gap #7 path): GL-MT6000 home,
   GL-MT3000 travel, OpenWrt packaging. This is the Aircove's
   successor's exact platform — there is no commercial argument for
   picking anything else.
2. **Per-device group model** as a planned feature once the router
   deployment lands — not a current priority, but a documented
   extension to the path-selection profiles.
3. **Auto-update mechanism** as a new roadmap row: deployment-side
   signature-verified updates, layered on the signed-commit evidence
   trail. Not for the current Linux-desktop release; for the router
   deployment profile.
4. **No hardware product** — confirm. The Aircove's discontinuation
   is the case study. This is already the project's stance; the
   post-mortem is the evidence.

## 7. What this is not

This is not a recommendation to clone AircoveOS, to fork OpenWrt, or to
build any appliance. It is a scoped recommendation to target the
open hardware that the market has already consolidated on, and to import
the few software ideas (per-device groups, double-VPN passthrough,
auto-update) that Aircove's five-year life produced.

The Aircove died because ExpressVPN was a VPN company trying to be a
router company. This project does not need to make that mistake.

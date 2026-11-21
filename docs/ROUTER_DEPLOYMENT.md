# Router deployment design — gap #7 (GL.iNet targeting, per-device groups, deployment-side update)

Status: targeting confirmed 21 November 2026 (delegated authority,
decision D010 in [DECISIONS.md](DECISIONS.md)); per-device groups and
deployment-side auto-update approved as documented extensions that land
*with* router deployment, not before it. Basis:
[AIRCOVE_POSTMORTEM_20261120.md](AIRCOVE_POSTMORTEM_20261120.md)
(the Aircove retired 16 Sep 2026; its successor Fortify is a
co-branded GL.iNet GL-MT6000 — ExpressVPN conceded the hardware layer
to GL.iNet, and this project has no reason to fight that war either).

**No hardware product.** Custom hardware stays declined (gap doc §5.3;
the Aircove's death is the validation). This document is about running
*the existing software* on hardware a user can already buy.

## 1. The two reference targets

| | GL.iNet Flint 2 (GL-MT6000) | GL.iNet Beryl AX (GL-MT3000) |
|---|---|---|
| Role | Home router (the Fortify's base) | Travel router |
| SoC / RAM / flash | MediaTek MT7986, 2.0 GHz quad A53, 1 GB DDR4, 8 GB eMMC | MT7981, 1.3 GHz dual A53, 512 MB, 8 GB eMMC |
| Wi-Fi | AX6000 (dual-band) | AX3000 (dual-band) |
| WireGuard throughput (vendor) | ~900 Mbps | ~500 Mbps |
| Price (2026) | ~USD 160 | ~USD 80 |
| Why it is the target | The 2026 de-facto standard VPN home router; OpenWrt 23/24 with full source; eMMC (no SD-card wear) | The pocket standard; same OpenWrt base; USB-C powered |

The chain-shape constraint that matters: the constant-rate stream makes
the router's *uplink*, not its CPU, the bottleneck (a `standard`-class
3 Mbit/s stream is nothing; a `line`-class 115 Mbit/s stream is within
the MT6000's envelope and beyond the MT3000's realistic Wi-Fi
throughput — the travel target documents `fast`/27.9 Mbit/s as its
recommended ceiling).

The ARM64 (aarch64) port is the prerequisite for both — it landed in
CI on 19 November (gap #1's first slice), and these two targets are
its two named production consumers.

## 2. The deployment shape

The single-operator mode is naturally router-shaped: headless, systemd
units, no GUI. The deployment is OpenWrt-first:

1. **Stage 1 — OpenWrt package.** `avpn` as an OpenWrt package (opkg),
   built by the existing aarch64 musl cross-build, installing the same
   systemd-less unit shape the offline installer already supports
   (the pinned-runtime design from
   [OFFLINE_INSTALLATION.md](OFFLINE_INSTALLATION.md) is the point:
   no runtime downloads on the router).
2. **Stage 2 — the namespace on OpenWrt.** The protected-namespace
   machinery uses the same netns/nftables primitives OpenWrt ships;
   the whole-device kill switch becomes the router's forwarding-path
   nftables rules (drop v4/v6 forwarded traffic not from the tunnel
   — the same per-family symmetry the IPv6 design specifies).
3. **Stage 3 — Wi-Fi as the client edge.** The router's LAN Wi-Fi is
   the "device"; everything behind it rides the tunnel. This is where
   per-device groups (§3) attach.

## 3. Per-device groups (the Aircove's one genuinely good idea)

AircoveOS's groups — each device in **VPN** (with a chosen exit),
**No VPN**, or **No internet** — are a routing primitive this
project's model already half-has: `avpn run` is per-*application* on a
laptop; a router needs per-*device*. The mapping:

- A **group** is a named set of devices (by MAC or DHCP reservation)
  plus a policy: `{exit: <descriptor>, profile: <rate class/preset>}`
  or `direct` (No VPN) or `offline` (No internet — nftables drop,
  LAN-only; the IoT-camera case).
- The **descriptor fields already exist**: `exit_policy` decides what
  the group's traffic may do at the exit (§6.2's bulk admission), and
  `toS_class`/`streaming` labeling decides which exit a "streaming"
  group may pick. No protocol change; this is a profile/CLI extension.
- **Guest network = a group** with `direct`/`offline` semantics and
  LAN isolation — OpenWrt's existing guest-Wi-Fi plus a group policy.
- The **honest boundary**: a router groups *devices*, and every device
  behind one group shares that group's exit and rate class. Two
  household members on one group are one anonymous tenant to the exit
  — the same single-tenant honesty the laptop model has, now stated
  per group.

What stays refused: per-group *identities*. One router, one operator
identity, one key custodian (the router's own TPM2/`systemd-creds`
equivalent on OpenWrt — stage 2 evaluates what GL.iNet's board offers;
if no sealable TPM is present, the offline pinning path applies).

## 4. "Passthrough" for inner VPNs (double-tunnel avoidance)

A device behind the router may itself run a VPN or Tor. Nesting is the
correct default (the router cannot distinguish "inner VPN" from "any
other UDP/TCP flow" without inspecting it), but the *opt-in* detector
the post-mortem describes is approved as a profile option: the cloak
already inspects the inner stream for persona mimicry; an
`inner-vpn-passthrough` flag routes detected WireGuard/OpenVPN/Tor
handshakes direct instead of nesting them. Default off — the safe
failure is a slow nested path, not a mis-detected direct leak.

## 5. Deployment-side auto-update (the Aircove's second good idea)

Approved as a roadmap row (decision D011): the deployment-side
equivalent of the signed-commit source trail. The design inherits the
project's existing security posture rather than inventing new trust:

- **What is trusted:** a release artifact signed by the project's
  release key (the same hybrid Ed25519 + ML-DSA-65 signatures
  enrollment bundles use); the router verifies the signature before
  applying anything. No third-party updater, no vendor cloud.
- **When:** manual by default (`avpn update` on the router checks,
  verifies, applies, and *refuses removal beneath a guard* — D006's
  rule). An automatic overnight window (`--auto 04:00`) is opt-in per
  the Aircove pattern, off out of the box.
- **Failure containment:** the pinned-runtime design applies — a
  failed or interrupted update leaves the previous live environment
  bootable (the offline installer's four-distribution evidence shape);
  on a router that means the eMMC keeps the last-known-good image and
  the bootloader falls back to it.
- **What auto-update never does:** change configuration, keys, or
  chain membership. Artifacts carry code; the operator's descriptors
  and policy stay untouched by an update.

## 6. Staging and gates

| Stage | Gate |
|---|---|
| aarch64 musl preflight (done) | CI green on 19 Nov |
| OpenWrt package build | the package installs on a stock MT6000 image in QEMU (sandbox-testable) |
| Namespace + kill switch on OpenWrt | the leak suite's whole-device gates re-run against the router's forwarding path (QEMU first, hardware after) |
| Per-device groups | policy-to-nftables compilation tests; one group's leak is not another group's leak |
| Auto-update | signed-artifact verification tests; failed-update rollback test in QEMU |

Hardware-in-the-loop (a real MT6000 and MT3000 on the owner's bench)
is the last mile and is owner-side, listed in the delivery manifest.

## 7. What this does not change

No hardware product, no firmware fork, no ExpressVPN-style cloud
management. The router runs the same pinned, signed, offline-first
software a laptop runs, one `avpn` CLI at a time — the GUI (gap #2)
renders the same typed controller checks over the same bridge.

# Cost documentation — servers, hardware, accessibility, connectivity, cover traffic, energy

Status: the documentation half of the ROADMAP §2 governance row
("Hardware/server/accessibility/connectivity cost documentation …
cover-traffic bandwidth and energy costs reported"). The *tested with
non-admin users* half is the owner-side usability-session item and
stays open (see §7).

Every server figure below comes from the checked-in catalogs
(`tools/providers.py`, `tools/cloud.py` MONTHLY_USD) and the measured
rate classes (`docs/evidence/RATE_CLASSES.json`); every energy figure
is a **planning estimate with its assumption stated** — the watt-meter
measurements are owner-side (§7).

## 1. Server costs (where the chain runs)

The zero-budget path (D003) is the catalog's first answer; paid hosts
exist for when allowances run out. Monthly USD, list prices checked
2026-11, one hop each:

| Option | Terms | Cost/hop | Cap for the project |
|---|---|---|---|
| Oracle Cloud Always Free | Always Free ARM/AMD allowance, 10 TB/mo egress | $0 | 1 GB RAM micro shapes; a payment card is needed to sign up; free servers can vanish |
| AWS free plan | 6 months or $100–200 of credits | ~$12 of credits (t3.micro 7.88 + 8 GiB gp3 0.67 + public IPv4 3.65) | the credit clock runs whether or not the chain is up |
| Azure free account | 12 months, 750 h/mo B1s-class | $0 while it lasts | free outbound allowance unconfirmed |
| Google Cloud free tier | e2-micro + 1 GB/mo egress | $0 | 1 GB/mo ≈ 30 MB/day: too little for any hop (catalog says so) |
| Low-cost paid hosts | annual promotions | from ~$1.83/mo (RackNerd-class) | the "own machine / own host" path (`avpn cloud host add`) |

The honest planning number for a 3-hop chain after free tiers: **$0
while the allowances hold** (Oracle-to-Oracle across regions is
constrained by the CLOUD-Act legal-sphere rule — the catalog marks the
legal-sphere cost), then ~**$6–40/mo total** for three budget paid
hops. `avpn cloud chain --apply` computes each hop's exact allowance
fit (`--hours-per-day`, default 8) and refuses cost overruns unless
`--accept-cost` is passed — the CLI is the cost guard, not this
document.

## 2. Cover-traffic bandwidth (the real recurring cost)

The constant-rate stream is the privacy mechanism and the bandwidth
bill. Two honest framings, both from the measured rate classes
(2-hop, `RATE_CLASSES.json`):

**Planning model — what `avpn cloud chain` charges against a hop's
allowance** (`tools/rates.py`, 8 h/day connected, one link):

| Class | Wire rate | Cover volume (8 h/day, 1 link) |
|---|---|---|
| metered | ~0.30 Mbit/s | 58.3 GiB/month |
| standard | ~3.0 Mbit/s | 582.6 GiB/month |
| fast | ~27.9 Mbit/s | 4,660.6 GiB/month |
| line | ~115.3 Mbit/s | 18,642.4 GiB/month |

**Always-on reality — what the stream actually sends, 24 h/day, both
directions** (the measured `cover_gib_per_day_per_direction`):

| Class | Per day, per direction | Per month, both directions |
|---|---|---|
| metered | 5.7 GiB | ~0.3 TB |
| standard | 56.9 GiB | ~3.4 TB |
| fast | 454.8 GiB | ~27.3 TB |
| line | 1,819.3 GiB | ~109.2 TB |

**Connectivity consequences, stated plainly:**

- A typical residential cap (1–2 TB/month) fits `metered` and
  `standard` always-on comfortably; `fast` exceeds every residential
  cap; `line` assumes an uncapped line and is the reason the class is
  opt-in.
- Free-tier egress allowances are the binding constraint for
  zero-budget chains: Oracle's 10 TB/mo fits `metered`/`standard`
  always-on or `fast` at reduced hours; `line` on free tiers is a
  non-starter, and the CLI says so rather than surprising the bill.
- The client's *uplink upload* carries the same volume down to the
  entry: on an asymmetric line (e.g. 20 Mbit/s up), `line` class is
  unreachable in principle, not just in caps.

## 3. Energy costs (planning estimates — assumptions stated)

No watt-meter measurements exist yet; these are engineering estimates
to be replaced by measured figures (§7):

| Component | Estimate | Assumption |
|---|---|---|
| Client laptop, `metered`/`standard` | +0.5–1 W over idle | userspace packet pacing + ChaChaPoly at ≤3 Mbit/s is light CPU; screen dominates |
| Client laptop, `fast`/`line` | +3–8 W | crypto + pacing at 28–115 Mbit/s saturates one or two cores on a typical 15–28 W SoC |
| VPS hops | not separately billed | energy is embedded in the VPS list price (§1); no action available |
| Self-hosted hop (own hardware) | ~5–10 W always-on | a fanless ARM SBC or N100 mini-PC idling at its shaped rate; at 0.15 $/kWh ≈ **$0.5–1.3/month** |
| Hardware key | ~0 W | bus-powered when plugged in |

**At 24/7 in `standard` class on a laptop**, the client-side energy
surcharge is on the order of 4–9 kWh/year (≈ $0.6–1.4/yr at
0.15 $/kWh) — the honest statement is that cover-traffic *energy* is
negligible next to cover-traffic *bandwidth* (§2).

## 4. Hardware costs (the honest minimum and the comfortable set)

| Tier | What | Cost (2026) | Notes |
|---|---|---|---|
| Minimum | none beyond the machine | $0 | TPM2 sealing (`systemd-creds`) uses hardware the machine already has |
| Recommended | one FIDO2 hmac-secret key | ~$50–100 (Nitrokey 3, YubiKey 5 class) | the hardware-custody posture COMPARISON.md §1 describes |
| Optional second key | backup custodian | same | the enrollment flow supports a recovery path |
| Commissioned lab units | Nitrokey 3, YubiKey 5, Trezor, Ledger | already owned | the four commissioned devices; no further purchase implied |
| Router target (future) | GL.iNet GL-MT3000 / GL-MT6000 | ~$80 / ~$160 | [ROUTER_DEPLOYMENT.md](ROUTER_DEPLOYMENT.md); no hardware product is being built or bundled |

The pre-configured kits in
[REVENUE_ARCHITECTURE.md](REVENUE_ARCHITECTURE.md) ($79–119 keypack,
$199–349 travel gateway) are the *monetization model's* prices, not
this project's costs; nothing in the zero-budget path requires them.

## 5. Accessibility costs

- **Competence cost:** today the honest cost is terminal fluency: the
  `avpn` CLI, descriptors, and enrollment. The GUI (gap #2) is the
  accessibility item in flight; the five usability sessions (§7) are
  its gate.
- **Time cost:** a zero-budget 3-hop bring-up with `avpn cloud` is a
  focused afternoon the first time (cloud accounts, regions, chain
  apply) and minutes afterwards (status, allow, rotate). The offline
  installer trades that for a pinned package on the owner's hardware.
- **Language cost:** English-only today; no i18n claims are made.

## 6. Cost governance (what guards these numbers)

- `avpn cloud chain --apply` refuses a chain whose rate class exceeds a
  hop's free allowance without an explicit `--accept-cost`.
- The rate-class figures above are versioned evidence
  (`RATE_CLASSES.json` / `RATE_CLASSES_v0_10_1.json`), not marketing
  copy; a new release re-measures them.
- Zero-budget discipline (D003) stands: no cloud spend is authorized
  by this document; it prices the options that exist.

## 7. What stays owner-side

1. Watt-meter measurement of client and self-hosted-hop energy per
   rate class (replaces §3's estimates).
2. The five usability sessions with non-admin users (the ROADMAP §2
   row's testing half, and gap #11's honest substitute for support).
3. A real paid-host month to confirm the budget-host price band holds
   under sustained cover traffic (some annual-promotion hosts throttle
   sustained egress; the catalog marks this caveat per host).

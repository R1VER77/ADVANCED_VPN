# Free endpoints

Where the chain's servers can run for free, as checked on 2026-11-09. Terms change:
each entry names the page it was checked against. `avpn cloud suggest` shows the same
list, with whether you are signed in to each provider and the exact next command.

A forwarding hop sends every byte out again (downloads towards you, uploads towards
the next hop), so a chain carries about as much per month as its hop with the
smallest outbound allowance.

## Oracle Cloud Always Free (recommended exit)

- No expiry; 10 TiB/month out.
- Servers: 2 x VM.Standard.E2.1.Micro (1 GB, 50 Mbps), or Ampere A1 with 2 OCPU / 12 GB in total.
- Caveats: home region only; idle instances (CPU, network and memory all under 20% for 7 days) may be reclaimed, and Oracle does not say how network use is measured, so a VPN's steady trickle cannot be counted on to look busy; a payment card is needed to sign up; free servers can vanish (reclaimed or the account closed): keep standby exits.
- Next: `avpn cloud oci server --apply --name avpn-exit --role exit` (created by this tool).
- Source: https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm

## AWS free plan (recommended entry relay)

- 6 months, or until the $100-200 of credits run out; 100 GiB/month out.
- Servers: one t3.micro relay costs about $12/month of credits.
- Caveats: new accounts only; one Region per project; the plan closes when it ends unless upgraded.
- Next: `avpn cloud aws relay --apply --name avpn-relay --profile PROFILE` (created by this tool).
- Source: https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/

## Azure free account

- 12 months of 750 hours/month of B1s, B2ats v2 or B2pts v2; outbound allowance unconfirmed.
- Servers: one small Ubuntu VM you create in the Azure portal.
- Caveats: the free outbound allowance is not confirmed; B1s is unavailable in some regions.
- Next: `avpn cloud host add --name avpn-azure --ssh azureuser@IP --key KEY --provider azure` (recorded with `avpn cloud host add`).
- Source: https://learn.microsoft.com/azure/cost-management-billing/manage/create-free-services

## Your own server, VPS or home machine

- Free if you already have it; your own bandwidth.
- Servers: any Debian 12+/Ubuntu 22.04+ host you can SSH into as a sudo user.
- Caveats: a home connection's address is tied to you: use it as a middle hop, not an exit you want unlinked.
- Next: `avpn cloud host add --name avpn-home --ssh USER@HOST --key KEY` (recorded with `avpn cloud host add`).

## Google Cloud free tier (not usable as a hop)

- No expiry; one e2-micro in us-west1, us-central1 or us-east1; 1 GiB/month out.
- Servers: one e2-micro (shared core, 1 GB).
- Caveats: 1 GB/month out is about 30 MB a day: too little for any hop.
- Not recommended as a hop.
- Source: https://docs.cloud.google.com/free/docs/free-cloud-features

## Low-cost paid hosts

Cheapest first, as listed on 2026-11-13 (prices change: check the order page). One of these carries far more than one person uses; at 300 GB a member each month, the covered counts below halve on a 2-hop chain. Running your own VPN is fine on all of them; letting other people's traffic exit makes their abuse complaints yours, so read the host's rules first. Record one with `avpn cloud host add --provider KEY`.

- **RackNerd** (`racknerd`, US): $21.99/year (annual promotions; stock varies); 3 TB/month out, about $0.61 per TB; covers about 10 members at 300 GB each (half on a 2-hop chain); mostly US locations. Source: https://www.racknerd.com/kvm-vps
- **IONOS VPS XS** (`ionos`, DE): about $2/month (the lowest EU price needs a 24-month term); unmetered at 1000 Mbit/s; covers members until its fair-use limit; no traffic cap. Source: https://www.ionos.com/servers/vps
- **OVHcloud VPS-1** (`ovh`, FR): about $4.54 / EUR 4.49 a month (2 vCPU, 4 GB); unmetered at 500 Mbit/s; covers members until its fair-use limit; its rules forbid Tor exits. Source: https://www.ovhcloud.com/en/vps/
- **netcup VPS 500** (`netcup`, DE): about EUR 4 a month; unmetered; covers members until its fair-use limit; its fair-use rule is reported as 2 TB a day; listings disagree. Source: https://www.netcup.com/en/server/vps
- **Hetzner CX22 / CAX11 (ARM)** (`hetzner`, DE): about EUR 4.59 / EUR 5.99 a month after the June 2026 increase; 20 TB/month out, about $0.27 per TB; covers about 66 members at 300 GB each (half on a 2-hop chain); 20 TB in EU locations, but 1 TB in the US and 0.5 TB in Singapore. Source: https://www.hetzner.com/cloud

## Considered, not yet usable

- **Flux (RunOnFlux)**: its apps are unprivileged containers copied onto several operators' machines and moved between them: UDP ports, a tunnel device and a fixed address (which a signed chain pins) are all unconfirmed; operators are unknown and can read the container's memory; many rent from the same hosts, so diversity must count the real host, not Flux. Source: https://docs.runonflux.com/fluxcloud/introduction

## Choosing

- Two providers beat two servers on one provider: the entry sees your address, the exit sees your destinations, and only a provider holding both could link them.
- Put the largest allowance at the exit. `avpn cloud chain` does this automatically.
- Every provider knows who owns the account and sees its own hop's traffic volume and timing. See `avpn help privacy` for what each can still see.

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
- Caveats: home region only; idle instances (CPU, network and memory all under 20% for 7 days) may be reclaimed; a payment card is needed to sign up.
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

## Choosing

- Two providers beat two servers on one provider: the entry sees your address, the exit sees your destinations, and only a provider holding both could link them.
- Put the largest allowance at the exit. `avpn cloud chain` does this automatically.
- Every provider knows who owns the account and sees its own hop's traffic volume and timing. See `avpn help privacy` for what each can still see.

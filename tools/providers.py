"""Where an cypherpunk_vpn chain can run for free: the endpoint catalog.

One table drives `cypherpunk cloud suggest`, the "Get started" cell `cypherpunk` shows on a device
that is not enrolled yet (`src/bin/cypherpunk/get_started.txt`, checked against this table by
the test suite), and `docs/cli/endpoints.md`. Terms change; every entry names the page
it was checked against and when.

A forwarding hop sends every byte of your traffic out again (downloads towards you,
uploads towards the next hop), so a chain can carry about as much per month as its
hop with the smallest outbound allowance.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess

CHECKED = "2026-11-09"

PROVIDERS = [
    dict(
        key="oci",
        name="Oracle Cloud Always Free",
        short="Oracle Cloud: no expiry",
        terms="no expiry",
        egress_gib=10240,
        servers="2 x VM.Standard.E2.1.Micro (1 GB, 50 Mbps), or Ampere A1 with 2 OCPU / 12 GB in total",
        caveats="home region only; idle instances (CPU, network and memory all under 20% for 7 days) may be "
        "reclaimed, and Oracle does not say how network use is measured, so a VPN's steady trickle cannot be "
        "counted on to look busy; a payment card is needed to sign up; free servers can vanish (reclaimed or "
        "the account closed): keep standby exits",
        automation="create",
        cli="oci",
        next="cypherpunk cloud oci server --apply --name cpvpn-exit --role exit",
        heading="recommended exit",
        source="https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm",
    ),
    dict(
        key="aws",
        name="AWS free plan",
        short="AWS: 6 months of credits",
        terms="6 months, or until the $100-200 of credits run out",
        egress_gib=100,
        servers="one t3.micro relay costs about $12/month of credits",
        caveats="new accounts only; one Region per project; the plan closes when it ends unless upgraded",
        automation="create",
        cli="aws",
        next="cypherpunk cloud aws relay --apply --name cpvpn-relay --profile PROFILE",
        heading="recommended entry relay",
        source="https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/",
    ),
    dict(
        key="azure",
        name="Azure free account",
        short="Azure: 12 months",
        terms="12 months of 750 hours/month of B1s, B2ats v2 or B2pts v2",
        egress_gib=None,
        servers="one small Ubuntu VM you create in the Azure portal",
        caveats="the free outbound allowance is not confirmed; B1s is unavailable in some regions",
        automation="ssh",
        cli="az",
        next="cypherpunk cloud host add --name cpvpn-azure --ssh azureuser@IP --key KEY --provider azure",
        source="https://learn.microsoft.com/azure/cost-management-billing/manage/create-free-services",
    ),
    dict(
        key="gcp",
        name="Google Cloud free tier",
        short="Google Cloud",
        terms="no expiry; one e2-micro in us-west1, us-central1 or us-east1",
        egress_gib=1,
        servers="one e2-micro (shared core, 1 GB)",
        caveats="1 GB/month out is about 30 MB a day: too little for any hop",
        automation="ssh",
        cli="gcloud",
        next="not recommended as a hop",
        heading="not usable as a hop",
        source="https://docs.cloud.google.com/free/docs/free-cloud-features",
    ),
    dict(
        key="own",
        name="Your own server, VPS or home machine",
        short="Your own server",
        terms="free if you already have it",
        egress_gib=None,
        servers="any Debian 12+/Ubuntu 22.04+ host you can SSH into as a sudo user",
        caveats="a home connection's address is tied to you: use it as a middle hop, not an exit you want unlinked",
        automation="ssh",
        cli="ssh",
        next="cypherpunk cloud host add --name cpvpn-home --ssh USER@HOST --key KEY",
        source="",
    ),
]

# Hosts whose company is not American, for a chain whose ends answer to different
# legal spheres. Every free tier above belongs to a US company, and the US CLOUD Act
# reaches US providers wherever their servers stand, so a chain built only from them
# sits under one legal umbrella. These are paid; names and homes only (terms and
# prices change: check them yourself).
NON_US = [
    dict(key="hetzner", name="Hetzner", parent="DE", source="https://www.hetzner.com/cloud"),
    dict(key="netcup", name="netcup", parent="DE", source="https://www.netcup.com"),
    dict(key="ovh", name="OVHcloud", parent="FR", source="https://www.ovhcloud.com"),
    dict(key="1984", name="1984 Hosting", parent="IS", source="https://1984.hosting"),
    dict(key="infomaniak", name="Infomaniak", parent="CH", source="https://www.infomaniak.com"),
    dict(key="exoscale", name="Exoscale", parent="CH", source="https://www.exoscale.com"),
    dict(key="ionos", name="IONOS", parent="DE", source="https://www.ionos.com/servers/vps"),
]

# Low-cost paid hosts, cheapest first, for when free allowances run out or a chain needs
# more providers. Prices are as listed when checked (they changed often in 2026: check the
# order page). A server here carries far more than one person uses, which is what lets a
# member's server cover others; whose traffic may exit is each host's own rule.
LOW_COST_CHECKED = "2026-11-13"
# A planning figure, not a measurement: a member's monthly traffic, in GB.
MEMBER_GB = 300
LOW_COST = [
    dict(
        key="racknerd",
        name="RackNerd",
        parent="US",
        usd_month=1.83,
        price="$21.99/year (annual promotions; stock varies)",
        egress_tb=3,
        port_mbps=1000,
        note="mostly US locations",
        source="https://www.racknerd.com/kvm-vps",
    ),
    dict(
        key="ionos",
        name="IONOS VPS XS",
        parent="DE",
        usd_month=2.0,
        price="about $2/month (the lowest EU price needs a 24-month term)",
        egress_tb=None,
        port_mbps=1000,
        note="no traffic cap",
        source="https://www.ionos.com/servers/vps",
    ),
    dict(
        key="ovh",
        name="OVHcloud VPS-1",
        parent="FR",
        usd_month=4.54,
        price="about $4.54 / EUR 4.49 a month (2 vCPU, 4 GB)",
        egress_tb=None,
        port_mbps=500,
        note="its rules forbid Tor exits",
        source="https://www.ovhcloud.com/en/vps/",
    ),
    dict(
        key="netcup",
        name="netcup VPS 500",
        parent="DE",
        usd_month=4.6,
        price="about EUR 4 a month",
        egress_tb=None,
        port_mbps=None,
        note="its fair-use rule is reported as 2 TB a day; listings disagree",
        source="https://www.netcup.com/en/server/vps",
    ),
    dict(
        key="hetzner",
        name="Hetzner CX22 / CAX11 (ARM)",
        parent="DE",
        usd_month=5.3,
        price="about EUR 4.59 / EUR 5.99 a month after the June 2026 increase",
        egress_tb=20,
        port_mbps=None,
        note="20 TB in EU locations, but 1 TB in the US and 0.5 TB in Singapore",
        source="https://www.hetzner.com/cloud",
    ),
]

# Considered, not yet usable: what is unproven before one can carry a hop.
UNTESTED = [
    dict(
        key="flux",
        name="Flux (RunOnFlux)",
        source="https://docs.runonflux.com/fluxcloud/introduction",
        blockers="its apps are unprivileged containers copied onto several operators' machines and moved "
        "between them: UDP ports, a tunnel device and a fixed address (which a signed chain pins) are all "
        "unconfirmed; operators are unknown and can read the container's memory; many rent from the same "
        "hosts, so diversity must count the real host, not Flux",
    ),
]
# The legal sphere each provider's company answers to (tools/mesh.py and
# src/mesh/directory.rs use the same table). "own" is your own host: its country's law.
LEGAL_PARENT = {
    "oci": "US",
    "aws": "US",
    "azure": "US",
    "gcp": "US",
    "fly": "US",
    **{p["key"]: p["parent"] for p in NON_US},
}

LEGAL_PARENT.update({p["key"]: p["parent"] for p in LOW_COST})

# Fly.io: no free tier, a $5 monthly waiver (tools/fee_guard.py), one exit per organization
# over IPv6 TCP (docs/FLY_EXIT.md). Created with `cypherpunk cloud fly server`, so it is not in
# the "where to start" table above.
FLY = dict(key="fly", name="Fly.io (within the $5 waiver)", short="Fly.io", terms="pay as you go; bills under $5 waived",
           egress_gib=51, servers="one 256 MB Machine per organization", automation="create", cli="docker",
           caveats="IPv6 TCP only; one server per organization; no spending limit",
           source="https://docs.fly.io/about/pricing")  # fmt: skip
ALL_KEYS = {p["key"] for p in PROVIDERS} | {p["key"] for p in NON_US} | {p["key"] for p in LOW_COST} | {"fly"}

# The desktop app's provider list (apps/cypherpunk-vpn/src/controller/providers.json,
# generated from this table with `--generate`). Prices are what each provider or a pricing
# survey listed on APP_CHECKED, in US dollars, rounded; the app shows that date and never
# fetches a price (a recurring fetch from the device would mark it). `egress_gb` is the
# monthly outbound data included: a number, "unmetered", or None when unconfirmed.
# `over_usd_gb` is the price per GB beyond it. Privacy tiers: 1 = a privacy host (pays
# without identity, privacy-minded jurisdiction), 2 = a non-US company under GDPR-style
# law, 3 = a US company (the CLOUD Act reaches its servers wherever they stand).
# Considered and left out (2026-11-22): Koyeb. Its Master Services Agreement s.10.2 names
# "proxy anonymization services" as forbidden use, with suspension at Koyeb's discretion;
# raw TCP is a public preview; new users need the $29/month Pro plan; Mistral AI is buying it.
APP_CHECKED = "2026-11-22"
APP_PLAN_GB = MEMBER_GB
EUR = 1.16  # USD per EUR on APP_CHECKED, for the euro-priced hosts
APP_CATALOG = [
    dict(key="njalla", service="Njalla VPS", company="Njalla", parent="KN", tier=1,
         server_usd=round(15 * EUR, 2), egress_gb=None, over_usd_gb=None, how="ssh",
         why="crypto payment, no identity required, registered in Nevis",
         note="traffic allowance not published", source="https://njal.la/vps/"),
    dict(key="flokinet", service="FlokiNET VPS", company="FlokiNET", parent="IS", tier=1,
         server_usd=round(7.99 * EUR, 2), egress_gb=3000, over_usd_gb=None, how="ssh",
         why="crypto payment, no identity required, Icelandic company",
         note="servers in Iceland, Romania, Finland and the Netherlands", source="https://flokinet.is/vps.php"),
    dict(key="1984", service="1984 Hosting VPS", company="1984 ehf.", parent="IS", tier=1,
         server_usd=round(7.6 * EUR, 2), egress_gb=1000, over_usd_gb=None, how="ssh",
         why="crypto payment, Icelandic free-speech host", note="reviews disagree on the traffic cap",
         source="https://1984.hosting/product/vps/"),
    dict(key="netcup", service="netcup VPS", company="netcup GmbH", parent="DE", tier=2,
         server_usd=round(4 * EUR, 2), egress_gb="unmetered", over_usd_gb=None, how="ssh",
         why="German company, GDPR", note="fair-use limit reported as 2 TB a day",
         source="https://www.netcup.com/en/server/vps"),
    dict(key="ovh", service="OVHcloud VPS", company="OVHcloud", parent="FR", tier=2,
         server_usd=4.54, egress_gb="unmetered", over_usd_gb=None, how="ssh",
         why="French company, GDPR", note="500 Mbit/s; its rules forbid Tor exits",
         source="https://www.ovhcloud.com/en/vps/"),
    dict(key="ionos", service="IONOS VPS", company="IONOS SE", parent="DE", tier=2,
         server_usd=2.0, egress_gb="unmetered", over_usd_gb=None, how="ssh",
         why="German company, GDPR", note="lowest price needs a 24-month term",
         source="https://www.ionos.com/servers/vps"),
    dict(key="scaleway", service="Scaleway Instances", company="Scaleway SAS", parent="FR", tier=2,
         server_usd=round(7.75 * EUR, 2), egress_gb="unmetered", over_usd_gb=None, how="ssh",
         why="French company, GDPR", note="DEV1-S with a public IPv4; 200 Mbit/s",
         source="https://www.scaleway.com/en/pricing/virtual-instances/"),
    dict(key="hetzner", service="Hetzner Cloud", company="Hetzner Online GmbH", parent="DE", tier=2,
         server_usd=round(5.99 * EUR, 2), egress_gb=20000, over_usd_gb=None, how="ssh",
         why="German company, GDPR", note="20 TB in EU locations, 1 TB in the US; new servers sometimes restricted",
         source="https://www.hetzner.com/cloud"),
    dict(key="infomaniak", service="Infomaniak Public Cloud", company="Infomaniak", parent="CH", tier=2,
         server_usd=None, egress_gb=None, over_usd_gb=None, how="ssh",
         why="Swiss company, Swiss data protection law", note="price not checked",
         source="https://www.infomaniak.com/en/hosting/public-cloud"),
    dict(key="exoscale", service="Exoscale Compute", company="Exoscale (A1 Digital)", parent="CH", tier=2,
         server_usd=None, egress_gb=None, over_usd_gb=None, how="ssh",
         why="Swiss company, Swiss data protection law", note="price not checked",
         source="https://www.exoscale.com/pricing/"),
    dict(key="oci", service="Oracle Cloud Infrastructure (OCI) Always Free", company="Oracle", parent="US", tier=3,
         server_usd=0.0, egress_gb=10240, over_usd_gb=0.0085, how="create",
         why="US company", note="free with no expiry; idle servers can be reclaimed",
         source="https://www.oracle.com/cloud/networking/pricing/"),
    dict(key="racknerd", service="RackNerd KVM VPS", company="RackNerd", parent="US", tier=3,
         server_usd=1.83, egress_gb=3000, over_usd_gb=None, how="ssh",
         why="US company", note="yearly promotions; stock varies", source="https://www.racknerd.com/kvm-vps"),
    dict(key="akamai", service="Akamai Cloud (Linode)", company="Akamai", parent="US", tier=3,
         server_usd=5.0, egress_gb=1000, over_usd_gb=0.005, how="ssh",
         why="US company", note="Nanode 1 GB", source="https://www.linode.com/pricing/"),
    dict(key="vultr", service="Vultr Cloud Compute", company="Vultr", parent="US", tier=3,
         server_usd=5.0, egress_gb=1000, over_usd_gb=0.01, how="ssh",
         why="US company", note="", source="https://www.vultr.com/pricing/"),
    dict(key="digitalocean", service="DigitalOcean Droplets", company="DigitalOcean", parent="US", tier=3,
         server_usd=4.0, egress_gb=500, over_usd_gb=0.01, how="ssh",
         why="US company", note="included transfer is pooled across an account's Droplets",
         source="https://www.digitalocean.com/pricing/droplets"),
    dict(key="fly", service="Fly.io Machines", company="Fly.io", parent="US", tier=3,
         server_usd=2.19, egress_gb=0, over_usd_gb=0.02, how="create",
         why="US company", note="bills under $5 a month are waived; IPv6 exit only; no spending limit",
         source="https://fly.io/docs/about/pricing/"),
    dict(key="azure", service="Microsoft Azure Virtual Machines", company="Microsoft", parent="US", tier=3,
         server_usd=7.59, egress_gb=100, over_usd_gb=0.087, how="ssh",
         why="US company", note="B1s; free for 12 months on a new account",
         source="https://azure.microsoft.com/pricing/details/bandwidth/"),
    dict(key="aws", service="Amazon Web Services (AWS) EC2", company="Amazon", parent="US", tier=3,
         server_usd=12.0, egress_gb=100, over_usd_gb=0.09, how="create",
         why="US company", note="t3.micro with disk and IPv4; new accounts get credits for 6 months",
         source="https://aws.amazon.com/ec2/pricing/on-demand/"),
    dict(key="gcp", service="Google Cloud Compute Engine", company="Google", parent="US", tier=3,
         server_usd=0.0, egress_gb=1, over_usd_gb=0.12, how="ssh",
         why="US company", note="one free e2-micro in three US regions",
         source="https://cloud.google.com/vpc/network-pricing"),
]  # fmt: skip


def month_usd(p, gb=APP_PLAN_GB):
    """About what a month of `gb` out costs on one server, or None when a price is unknown."""
    if p["server_usd"] is None:
        return None
    egress = p["egress_gb"]
    if egress == "unmetered" or (isinstance(egress, int) and egress >= gb):
        return round(p["server_usd"], 2)
    if egress is None or p["over_usd_gb"] is None:
        return None
    return round(p["server_usd"] + (gb - egress) * p["over_usd_gb"], 2)


def app_catalog():
    """The app's list: privacy tier first, then the most included data, then the cheapest."""

    def data(p):
        e = p["egress_gb"]
        return float("inf") if e == "unmetered" else -1 if e is None else e

    rows = [dict(p, month_usd=month_usd(p), sphere=p["parent"]) for p in APP_CATALOG]
    rows.sort(key=lambda p: (p["tier"], -data(p), p["month_usd"] if p["month_usd"] is not None else 1e9, p["key"]))
    return dict(schema=1, checked=APP_CHECKED, plan_gb=APP_PLAN_GB, providers=rows)


def sphere(key):
    """A provider's legal sphere, or None for your own host (whose country decides)."""
    return LEGAL_PARENT.get(key)


# A hop sending under this much a month is useless for a VPN.
USABLE_GIB = 20


def outbound(p):
    """The monthly outbound allowance, in words."""
    gib = p["egress_gib"]
    if gib is None:
        return "your own bandwidth" if p["key"] == "own" else "outbound allowance unconfirmed"
    return ("%d TiB" % (gib // 1024) if gib >= 1024 else "%d GiB" % gib) + "/month out"


def usable(p):
    """Whether a provider can carry a hop at all."""
    return p["egress_gib"] is None or p["egress_gib"] >= USABLE_GIB


def ranked():
    """Providers by usable monthly outbound allowance (unknown after known, unusable last)."""
    return sorted(PROVIDERS, key=lambda p: (not usable(p), p["egress_gib"] is None, -(p["egress_gib"] or 0)))


def by_key(key):
    """One catalog entry (a non-US host has no free allowance on record)."""
    for p in PROVIDERS:
        if p["key"] == key:
            return p
    if key == "fly":
        return FLY
    q = next((p for p in NON_US if p["key"] == key), None) or next(p for p in LOW_COST if p["key"] == key)
    return dict(q, egress_gib=None, terms="paid", servers="a VPS you create", automation="ssh")


def low_cost_rows():
    """The low-cost hosts, cheapest first: price, traffic, and members one server covers."""
    rows = []
    for p in sorted(LOW_COST, key=lambda p: p["usd_month"]):
        if p["egress_tb"]:
            traffic = "%d TB/month out, about $%.2f per TB" % (p["egress_tb"], p["usd_month"] / p["egress_tb"])
            members = p["egress_tb"] * 1000 // MEMBER_GB
            covers = "covers about %d members at %d GB each (half on a 2-hop chain)" % (members, MEMBER_GB)
        else:
            traffic = "unmetered" + (" at %d Mbit/s" % p["port_mbps"] if p["port_mbps"] else "")
            covers = "covers members until its fair-use limit"
        rows.append(dict(p, traffic=traffic, covers=covers))
    return rows


def quick(argv, timeout=20):
    """Run a provider CLI check; True when it succeeds."""
    try:
        return subprocess.run(argv, capture_output=True, timeout=timeout, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def cli_path(name):
    """The provider CLI, honouring the `CPVPN_<NAME>` override the cloud tool uses."""
    return os.environ.get("CPVPN_" + name.upper()) or shutil.which(name)


def readiness(p, profile=None):
    """(ready, why) for creating or joining a server with this provider from here."""
    exe = cli_path(p["cli"])
    if not exe:
        return False, "%s CLI not installed" % p["cli"]
    if p["key"] == "aws":
        args = ["--profile", profile] if profile else []
        if quick([exe, "sts", "get-caller-identity", *args, "--output", "json"]):
            return True, "signed in" + (" (profile %s)" % profile if profile else "")
        return False, "not signed in: aws login" + (" --profile %s" % profile if profile else "")
    if p["key"] == "oci":
        config = Path(os.environ.get("OCI_CLI_CONFIG_FILE", Path.home() / ".oci" / "config"))
        if not config.exists():
            return False, "not configured: oci setup config"
        return True, "configured (%s)" % config
    if p["key"] == "azure":
        return (True, "signed in") if quick([exe, "account", "show", "--output", "json"]) else (False, "az login")
    return True, "%s found" % p["cli"]


def capacity_gib(servers):
    """About how much a chain of these providers can carry per month (None if unknown)."""
    known = [by_key(k)["egress_gib"] for k in servers if by_key(k)["egress_gib"] is not None]
    return min(known) if known else None


def recommendation(recorded):
    """What to do next, given the servers already recorded (name -> provider key)."""
    n = len(recorded)
    if n == 0:
        return (
            "start with an OCI Always Free exit (10 TB/month), then add an AWS relay "
            "for 2 hops on two providers, so no single provider sees both ends"
        )
    if n == 1:
        return "one server recorded (%s): add one more on another provider for 2 hops" % ", ".join(sorted(recorded))
    hops = min(n, 3)
    cap = capacity_gib(recorded.values())
    return "%d servers recorded: cypherpunk cloud chain --apply joins them into %d hops%s" % (
        n,
        hops,
        " (about %d GiB/month)" % cap if cap else "",
    )


def get_started_text():
    """The "Get started" cell `cypherpunk` shows on a device that is not enrolled yet.

    Line 1 is the title, line 2 the summary, then `label<TAB>value` rows.
    """
    rows = ["Get started", "this device is not enrolled yet"]
    for p in ranked():
        if not usable(p):
            continue
        rows.append("%s\t%s" % (p["short"], outbound(p)))
    rows.append("details\tcypherpunk help endpoints")
    rows.append("next\tcypherpunk cloud suggest  (checks your sign-ins)")
    rows.append("then\tcypherpunk cloud chain --apply  (one multi-hop chain)")
    return "\n".join(rows) + "\n"


PAGE_HEAD = """# Free endpoints

Where the chain's servers can run for free, as checked on %s. Terms change:
each entry names the page it was checked against. `cypherpunk cloud suggest` shows the same
list, with whether you are signed in to each provider and the exact next command.

A forwarding hop sends every byte out again (downloads towards you, uploads towards
the next hop), so a chain carries about as much per month as its hop with the
smallest outbound allowance.
"""

PAGE_TAIL = """
## Choosing

- Two providers beat two servers on one provider: the entry sees your address, the exit sees your destinations, and only a provider holding both could link them.
- Put the largest allowance at the exit. `cypherpunk cloud chain` does this automatically.
- Every provider knows who owns the account and sees its own hop's traffic volume and timing. See `cypherpunk help privacy` for what each can still see.
"""


def endpoints_page():
    """`docs/cli/endpoints.md`, generated from the catalog (the docs gate checks it)."""
    out = [PAGE_HEAD % CHECKED]
    for p in ranked():
        out.append("\n## %s%s\n\n" % (p["name"], " (%s)" % p["heading"] if p.get("heading") else ""))
        out.append("- %s; %s.\n" % (p["terms"][0].upper() + p["terms"][1:], outbound(p)))
        out.append("- Servers: %s.\n" % p["servers"])
        out.append("- Caveats: %s.\n" % p["caveats"])
        how = "created by this tool" if p["automation"] == "create" else "recorded with `cypherpunk cloud host add`"
        out.append("- Next: `%s` (%s).\n" % (p["next"], how) if usable(p) else "- Not recommended as a hop.\n")
        if p["source"]:
            out.append("- Source: %s\n" % p["source"])
    out.append(
        "\n## Low-cost paid hosts\n\nCheapest first, as listed on %s (prices change: check the order page). "
        "One of these carries far more than one person uses; at %d GB a member each month, the covered "
        "counts below halve on a 2-hop chain. Running your own VPN is fine on all of them; letting other "
        "people's traffic exit makes their abuse complaints yours, so read the host's rules first. Record "
        "one with `cypherpunk cloud host add --provider KEY`.\n\n" % (LOW_COST_CHECKED, MEMBER_GB)
    )
    for p in low_cost_rows():
        out.append(
            "- **%s** (`%s`, %s): %s; %s; %s; %s. Source: %s\n"
            % (p["name"], p["key"], p["parent"], p["price"], p["traffic"], p["covers"], p["note"], p["source"])
        )
    out.append("\n## Considered, not yet usable\n\n")
    for p in UNTESTED:
        out.append("- **%s**: %s. Source: %s\n" % (p["name"], p["blockers"], p["source"]))
    out.append(PAGE_TAIL)
    return "".join(out)


APP_CATALOG_PATH = "apps/cypherpunk-vpn/src/controller/providers.json"


def app_catalog_text():
    """The generated app list, as written (the test suite compares it)."""
    return json.dumps(app_catalog(), indent=1) + "\n"


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["--generate"]:
        root = Path(__file__).resolve().parents[1]
        (root / "src/bin/cypherpunk/get_started.txt").write_text(get_started_text())
        (root / "docs/cli/endpoints.md").write_text(endpoints_page())
        (root / APP_CATALOG_PATH).write_text(app_catalog_text())
        print("wrote src/bin/cypherpunk/get_started.txt, docs/cli/endpoints.md and " + APP_CATALOG_PATH)
    else:
        print(json.dumps(ranked(), indent=2))

"""Where an ADVANCED_VPN chain can run for free: the endpoint catalog.

One table drives `avpn cloud suggest`, the "Get started" cell `avpn` shows on a device
that is not enrolled yet (`src/bin/avpn/get_started.txt`, checked against this table by
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
        next="avpn cloud oci server --apply --name avpn-exit --role exit",
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
        next="avpn cloud aws relay --apply --name avpn-relay --profile PROFILE",
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
        next="avpn cloud host add --name avpn-azure --ssh azureuser@IP --key KEY --provider azure",
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
        next="avpn cloud host add --name avpn-home --ssh USER@HOST --key KEY",
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
LEGAL_PARENT = {"oci": "US", "aws": "US", "azure": "US", "gcp": "US", **{p["key"]: p["parent"] for p in NON_US}}

LEGAL_PARENT.update({p["key"]: p["parent"] for p in LOW_COST})

ALL_KEYS = {p["key"] for p in PROVIDERS} | {p["key"] for p in NON_US} | {p["key"] for p in LOW_COST}


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
    """The provider CLI, honouring the `AVPN_<NAME>` override the cloud tool uses."""
    return os.environ.get("AVPN_" + name.upper()) or shutil.which(name)


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
    return "%d servers recorded: avpn cloud chain --apply joins them into %d hops%s" % (
        n,
        hops,
        " (about %d GiB/month)" % cap if cap else "",
    )


def get_started_text():
    """The "Get started" cell `avpn` shows on a device that is not enrolled yet.

    Line 1 is the title, line 2 the summary, then `label<TAB>value` rows.
    """
    rows = ["Get started", "this device is not enrolled yet"]
    for p in ranked():
        if not usable(p):
            continue
        rows.append("%s\t%s" % (p["short"], outbound(p)))
    rows.append("details\tavpn help endpoints")
    rows.append("next\tavpn cloud suggest  (checks your sign-ins)")
    rows.append("then\tavpn cloud chain --apply  (one multi-hop chain)")
    return "\n".join(rows) + "\n"


PAGE_HEAD = """# Free endpoints

Where the chain's servers can run for free, as checked on %s. Terms change:
each entry names the page it was checked against. `avpn cloud suggest` shows the same
list, with whether you are signed in to each provider and the exact next command.

A forwarding hop sends every byte out again (downloads towards you, uploads towards
the next hop), so a chain carries about as much per month as its hop with the
smallest outbound allowance.
"""

PAGE_TAIL = """
## Choosing

- Two providers beat two servers on one provider: the entry sees your address, the exit sees your destinations, and only a provider holding both could link them.
- Put the largest allowance at the exit. `avpn cloud chain` does this automatically.
- Every provider knows who owns the account and sees its own hop's traffic volume and timing. See `avpn help privacy` for what each can still see.
"""


def endpoints_page():
    """`docs/cli/endpoints.md`, generated from the catalog (the docs gate checks it)."""
    out = [PAGE_HEAD % CHECKED]
    for p in ranked():
        out.append("\n## %s%s\n\n" % (p["name"], " (%s)" % p["heading"] if p.get("heading") else ""))
        out.append("- %s; %s.\n" % (p["terms"][0].upper() + p["terms"][1:], outbound(p)))
        out.append("- Servers: %s.\n" % p["servers"])
        out.append("- Caveats: %s.\n" % p["caveats"])
        how = "created by this tool" if p["automation"] == "create" else "recorded with `avpn cloud host add`"
        out.append("- Next: `%s` (%s).\n" % (p["next"], how) if usable(p) else "- Not recommended as a hop.\n")
        if p["source"]:
            out.append("- Source: %s\n" % p["source"])
    out.append(
        "\n## Low-cost paid hosts\n\nCheapest first, as listed on %s (prices change: check the order page). "
        "One of these carries far more than one person uses; at %d GB a member each month, the covered "
        "counts below halve on a 2-hop chain. Running your own VPN is fine on all of them; letting other "
        "people's traffic exit makes their abuse complaints yours, so read the host's rules first. Record "
        "one with `avpn cloud host add --provider KEY`.\n\n" % (LOW_COST_CHECKED, MEMBER_GB)
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


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["--generate"]:
        root = Path(__file__).resolve().parents[1]
        (root / "src/bin/avpn/get_started.txt").write_text(get_started_text())
        (root / "docs/cli/endpoints.md").write_text(endpoints_page())
        print("wrote src/bin/avpn/get_started.txt and docs/cli/endpoints.md")
    else:
        print(json.dumps(ranked(), indent=2))

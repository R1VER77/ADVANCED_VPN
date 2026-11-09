#!/usr/bin/env python3
"""Built-in cloud setup for ADVANCED_VPN chains (`avpn cloud`).

Runs as you, never as root, because it uses your own signed-in provider CLIs (`aws`,
`oci`). It only ever touches resources it tagged itself (`avpn:managed=true` plus
`avpn:name=<name>`), so a teardown cannot reach anything else in the account.

Commands:
- `status`: the local inventory, plus the tagged resources that still exist.
- `aws relay --apply|--teardown`: one NitroTPM-capable relay (or middle/exit) instance.
- `aws allow --apply`: replace the addresses that may reach that instance (for example
  after your public address changed).
- `oci allow --apply|--teardown`: one ingress rule on an OCI security list, from the
  previous hop only.

Every apply and teardown prints its plan first. `--dry-run` stops after the plan, and
`--yes` confirms without a prompt. `--json` prints one object for the `avpn` CLI.
"""

import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from install import pack  # the installer's own package format
import providers
import retention

MANAGED = "avpn:managed"
NAME = "avpn:name"
DEBIAN_OWNER = "136693071363"  # Debian's official AWS account
INVENTORY = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "advanced-vpn" / "cloud.json"
# On-demand list prices in eu-north-1 (USD, checked 2026-11). These are estimates only:
# the free plan's credits pay for them, and AWS Billing shows the real cost.
MONTHLY_USD = {"t3.micro": 7.88, "t3.small": 15.77, "gp3_gib": 0.0836, "public_ipv4": 3.65}
ROLES = {"relay": 41194, "middle": 4445, "exit": 4444}
PROTO = {"relay": "udp", "middle": "udp", "exit": "udp"}


class CloudError(RuntimeError):
    """A provider call or a safety check failed; the message says which."""


def tool(name):
    """The provider CLI: `AVPN_AWS` / `AVPN_OCI` override it (tests), else PATH."""
    override = os.environ.get("AVPN_" + name.upper())
    found = override or shutil.which(name)
    if not found:
        raise CloudError("the %s CLI is not installed or not on PATH" % name)
    return found


def call(argv, parse=True, stdin=None):
    """Run a provider CLI command; return its parsed JSON output (or text)."""
    r = subprocess.run(argv, capture_output=True, text=True, timeout=900, check=False, input=stdin)
    if r.returncode != 0:
        detail = (r.stderr.strip().splitlines() or ["exit %d" % r.returncode])[-1]
        if "ExpiredToken" in r.stderr or "Token has expired" in r.stderr or "aws login" in r.stderr:
            detail += " (sign in again: aws login --profile <profile>)"
        raise CloudError("%s %s: %s" % (Path(argv[0]).name, " ".join(argv[1:3]), detail))
    out = r.stdout.strip()
    if not parse:
        return out
    return json.loads(out) if out else {}


def valid_name(name):
    """Resource names: lowercase letters, digits and dashes, starting `avpn-`."""
    if not (
        name.startswith("avpn-") and 6 <= len(name) <= 40 and all(c.islower() or c.isdigit() or c == "-" for c in name)
    ):
        raise CloudError("name must start with avpn- and use only a-z, 0-9 and -")
    return name


ANY = "0.0.0.0/0"
# What each provider keeps about whoever calls its API, whatever you configure.
CALLER_LOG = {
    "aws": "AWS CloudTrail keeps every caller's address for 90 days",
    "oci": "OCI Audit keeps every caller's address for 365 days",
}


def egress():
    """This machine's public address as the internet sees it."""
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as r:  # noqa: S310 (fixed https URL)
        return r.read().decode().strip()


def single_ip(value):
    """One IPv4 address (as a /32 CIDR); `auto` uses this machine's public address."""
    if value == "auto":
        value = egress()
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_global:
        raise CloudError("%s is not a public IPv4 address" % value)
    return str(ip) + "/32"


def tunnel_sources(values, first_hop):
    """`--allow-from` values as CIDRs: single public IPv4s, or `any` for a first hop.

    A first hop is a WireGuard endpoint, which never answers a peer it was not enrolled
    with (the lab and live probes prove it), so it can be open to every address. Then
    the provider's firewall configuration, and its audit log of that configuration,
    never name your address. Later hops admit only the previous server.
    """
    out = []
    for v in values:
        if v == "any":
            if not first_hop:
                raise CloudError("only the first hop may be open to any address; later hops admit the previous server")
            out.append(ANY)
        else:
            out.append(single_ip(v))
    if ANY in out and len(out) > 1:
        raise CloudError("any already admits every address; give it alone")
    return out


def caller_note(provider):
    """A plan row saying which address the provider will record as the API caller."""
    try:
        me = egress()
    except (OSError, ValueError):
        return dict(label="caller", value="address unknown; " + CALLER_LOG[provider])
    servers = {r.get("public_ip"): n for n, r in load_inventory()["resources"].items() if r.get("public_ip")}
    if me in servers:
        return dict(label="caller", value="%s (%s, through your chain); %s" % (me, servers[me], CALLER_LOG[provider]))
    return dict(
        label="caller",
        value="%s, this machine's address; %s. Connect through a chain first to record the exit instead"
        % (me, CALLER_LOG[provider]),
    )


def load_inventory(path=None):
    """The local record of what was created (no secrets)."""
    path = path or INVENTORY
    return json.loads(path.read_text()) if path.exists() else dict(schema=1, resources={})


def save_inventory(inv, path=None):
    """Write the inventory atomically, readable by you only."""
    path = path or INVENTORY
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cloud.")
    with os.fdopen(fd, "w") as f:
        json.dump(inv, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


class Aws:
    """The AWS CLI for one profile, in the profile's own (single) Region."""

    def __init__(self, profile, region=None):
        self.exe = tool("aws")
        self.profile = profile
        configured = call([self.exe, "configure", "get", "region", "--profile", profile], parse=False)
        if region and configured and region != configured:
            raise CloudError("this project's Region is %s; resources cannot be created in %s" % (configured, region))
        self.region = region or configured
        if not self.region:
            raise CloudError("no Region configured for profile %s" % profile)

    def __call__(self, *args, parse=True):
        """Run `aws ARGS` for this profile and Region, returning parsed JSON."""
        return call(
            [self.exe, *args, "--profile", self.profile, "--region", self.region, "--output", "json"], parse=parse
        )

    def ec2(self, *args, parse=True):
        """`aws ec2 ...`"""
        return self("ec2", *args, parse=parse)

    def tags(self, kind, name, extra=None):
        """A TagSpecification for one resource type."""
        tags = [dict(Key=MANAGED, Value="true"), dict(Key=NAME, Value=name), dict(Key="Name", Value=name)]
        tags += [dict(Key=k, Value=v) for k, v in (extra or {}).items()]
        return json.dumps([dict(ResourceType=kind, Tags=tags)])

    def owned(self, name):
        """Every resource this tool tagged with `name`, by type."""
        f = ["Name=tag:%s,Values=true" % MANAGED, "Name=tag:%s,Values=%s" % (NAME, name)]
        live = "Name=instance-state-name,Values=pending,running,stopping,stopped"
        res = self.ec2("describe-instances", "--filters", *f, live)
        instances = [i for r in res.get("Reservations", []) for i in r["Instances"]]
        groups = self.ec2("describe-security-groups", "--filters", *f).get("SecurityGroups", [])
        images = self.ec2("describe-images", "--owners", "self", "--filters", *f).get("Images", [])
        snaps = self.ec2("describe-snapshots", "--owner-ids", "self", "--filters", *f).get("Snapshots", [])
        keys = self.ec2("describe-key-pairs", "--filters", *f).get("KeyPairs", [])
        return dict(instances=instances, security_groups=groups, images=images, snapshots=snaps, key_pairs=keys)


def plan_state(aws):
    """The account plan (FREE or PAID) from `aws freetier`, or None if unavailable."""
    try:
        return aws("freetier", "get-account-plan-state").get("accountPlanType")
    except CloudError:
        return None


def monthly_estimate(instance_type, disk_gib):
    """Rough monthly list price of one relay, in USD."""
    return round(MONTHLY_USD.get(instance_type, 0) + disk_gib * MONTHLY_USD["gp3_gib"] + MONTHLY_USD["public_ipv4"], 2)


def aws_relay_plan(a, aws):
    """What `aws relay --apply` will create (and check first)."""
    who = aws("sts", "get-caller-identity")
    owned = aws.owned(a.name)
    port = a.port or ROLES[a.role]
    sources = a.allow_from
    rows = [
        dict(label="account", value="%s (%s)" % (who["Account"], plan_state(aws) or "plan unknown")),
        dict(label="region", value=aws.region),
        dict(
            label="instance", value="%s %s, NitroTPM 2.0, IMDSv2 only, standard CPU credits" % (a.instance_type, a.name)
        ),
        dict(label="disk", value="%d GiB gp3, encrypted, deleted with the instance" % a.disk_gib),
        dict(
            label="firewall",
            value="%s %d from %s; SSH 22 from %s" % (PROTO[a.role], port, ", ".join(sources), a.admin_ip),
        ),
        dict(label="image", value="newest Debian 13 amd64, re-registered UEFI + NitroTPM"),
        dict(
            label="estimate",
            value="about $%.2f/month (list price; see AWS Billing)" % monthly_estimate(a.instance_type, a.disk_gib),
        ),
    ]
    if owned["instances"]:
        rows.append(
            dict(label="exists", value=", ".join(i["InstanceId"] for i in owned["instances"]) + " (apply refuses)")
        )
    rows.append(caller_note("aws"))
    return dict(account=who["Account"], rows=rows, owned=owned, port=port)


def first_boot_file():
    """The first-boot hardening as a cloud-init user-data file (tools/retention.py)."""
    INVENTORY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(dir=INVENTORY.parent, prefix=".first-boot.", suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(retention.cloud_init())
    return Path(path)


def ssh_key_dir(name):
    """Where the throwaway admin SSH key for `name` lives (your config dir, 0700)."""
    d = INVENTORY.parent / "ssh"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d / name


def wait(what, check, timeout=1800, every=15):
    """Poll `check` until it returns a truthy value or `timeout` seconds pass."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(every)
    raise CloudError("timed out waiting for " + what)


def aws_relay_apply(a, aws, plan):
    """Create the image, key, firewall and instance; record them in the inventory."""
    if plan["owned"]["instances"]:
        raise CloudError("%s already exists; tear it down first" % a.name)
    created = dict(provider="aws", profile=a.profile, region=aws.region, role=a.role, port=plan["port"])
    inv = load_inventory()
    inv["resources"][a.name] = created
    created["created"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    def record():
        save_inventory(inv)

    base = aws.ec2(
        "describe-images",
        "--owners",
        DEBIAN_OWNER,
        "--filters",
        "Name=name,Values=debian-13-amd64-*",
        "Name=architecture,Values=x86_64",
        "Name=state,Values=available",
    )["Images"]
    if not base:
        raise CloudError("no Debian 13 amd64 image found in " + aws.region)
    base = max(base, key=lambda i: i["CreationDate"])
    stamp = datetime.date.today().strftime("%Y%m%d")
    copy = aws.ec2(
        "copy-image",
        "--source-region",
        aws.region,
        "--source-image-id",
        base["ImageId"],
        "--name",
        "%s-copy-%s" % (a.name, stamp),
        "--encrypted",
        "--tag-specifications",
        aws.tags("image", a.name),
    )["ImageId"]
    created["copy_image"] = copy
    record()

    def copied():
        img = aws.ec2("describe-images", "--image-ids", copy)["Images"][0]
        if img["State"] == "failed":
            raise CloudError("image copy failed")
        return img if img["State"] == "available" else None

    img = wait("the image copy", copied)
    snap = img["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"]
    aws.ec2(
        "create-tags", "--resources", snap, "--tags", json.dumps(json.loads(aws.tags("snapshot", a.name))[0]["Tags"])
    )
    root = img.get("RootDeviceName", "/dev/xvda")
    tpm = aws.ec2(
        "register-image",
        "--name",
        "%s-nitrotpm-%s" % (a.name, stamp),
        "--description",
        "ADVANCED_VPN: Debian 13 amd64, UEFI, NitroTPM 2.0",
        "--architecture",
        "x86_64",
        "--virtualization-type",
        "hvm",
        "--ena-support",
        "--boot-mode",
        "uefi",
        "--tpm-support",
        "v2.0",
        "--imds-support",
        "v2.0",
        "--root-device-name",
        root,
        "--block-device-mappings",
        json.dumps([dict(DeviceName=root, Ebs=dict(SnapshotId=snap, VolumeType="gp3", DeleteOnTermination=True))]),
        "--tag-specifications",
        aws.tags("image", a.name),
    )["ImageId"]
    created.update(image=tpm, snapshot=snap)
    aws.ec2("deregister-image", "--image-id", copy)
    created.pop("copy_image")
    record()
    key = ssh_key_dir(a.name)
    if not key.exists():
        subprocess.run(
            [
                shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                a.name,
                "-f",
                str(key),
            ],
            check=True,
        )
    aws.ec2(
        "import-key-pair",
        "--key-name",
        a.name,
        "--public-key-material",
        "fileb://" + str(key) + ".pub",
        "--tag-specifications",
        aws.tags("key-pair", a.name),
    )
    created.update(key_pair=a.name, ssh_key=str(key))
    record()
    vpc = aws.ec2("describe-vpcs", "--filters", "Name=is-default,Values=true")["Vpcs"]
    if not vpc:
        raise CloudError("no default VPC in " + aws.region)
    sg = aws.ec2(
        "create-security-group",
        "--group-name",
        a.name,
        "--description",
        "ADVANCED_VPN %s: tunnel from the previous hop, SSH from the admin address" % a.role,
        "--vpc-id",
        vpc[0]["VpcId"],
        "--tag-specifications",
        aws.tags("security-group", a.name),
    )["GroupId"]
    created["security_group"] = sg
    record()
    perms = [
        dict(
            IpProtocol=PROTO[a.role],
            FromPort=plan["port"],
            ToPort=plan["port"],
            IpRanges=[dict(CidrIp=c, Description="ADVANCED_VPN previous hop") for c in a.allow_from],
        ),
        dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[dict(CidrIp=a.admin_ip, Description="admin SSH")]),
    ]
    aws.ec2("authorize-security-group-ingress", "--group-id", sg, "--ip-permissions", json.dumps(perms))
    # First-boot hardening: every log in RAM before sshd accepts its first login.
    user_data = first_boot_file()
    disks = [
        dict(
            DeviceName=root, Ebs=dict(VolumeSize=a.disk_gib, VolumeType="gp3", Encrypted=True, DeleteOnTermination=True)
        )
    ]
    instance_tags = json.loads(aws.tags("instance", a.name, {"avpn:role": a.role})) + json.loads(
        aws.tags("volume", a.name)
    )
    try:
        run = aws.ec2(
            "run-instances",
            "--user-data",
            "file://" + str(user_data),
            "--image-id",
            tpm,
            "--instance-type",
            a.instance_type,
            "--key-name",
            a.name,
            "--security-group-ids",
            sg,
            "--credit-specification",
            "CpuCredits=standard",
            "--metadata-options",
            "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled",
            "--block-device-mappings",
            json.dumps(disks),
            "--tag-specifications",
            json.dumps(instance_tags),
        )
    finally:
        user_data.unlink(missing_ok=True)
    iid = run["Instances"][0]["InstanceId"]
    created["instance"] = iid
    record()

    def running():
        i = aws.ec2("describe-instances", "--instance-ids", iid)["Reservations"][0]["Instances"][0]
        return i if i["State"]["Name"] == "running" and i.get("PublicIpAddress") else None

    inst = wait("the instance to run", running, timeout=600, every=10)
    created["public_ip"] = inst["PublicIpAddress"]
    record()
    return [
        dict(label="instance", value=iid),
        dict(label="public address", value="%s (%s %d)" % (inst["PublicIpAddress"], PROTO[a.role], plan["port"])),
        dict(label="image", value=tpm + " (NitroTPM 2.0)"),
        dict(label="ssh", value="ssh -i %s admin@%s" % (key, inst["PublicIpAddress"])),
        dict(
            label="next",
            value="install the package on it, then avpn request --role %s --protect systemd-creds" % a.role,
        ),
    ]


def aws_teardown_plan(a, aws):
    """The tagged resources a teardown will delete."""
    owned = aws.owned(a.name)
    rows = []
    for i in owned["instances"]:
        name = {t["Key"]: t["Value"] for t in i.get("Tags", [])}.get("Name", "")
        if not name.startswith("avpn-"):
            raise CloudError("refusing: %s is tagged but not named avpn-*" % i["InstanceId"])
        rows.append(dict(label="instance", value="%s %s %s" % (i["InstanceId"], name, i.get("PublicIpAddress", ""))))
    for g in owned["security_groups"]:
        rows.append(dict(label="firewall", value=g["GroupId"] + " " + g["GroupName"]))
    for k in owned["key_pairs"]:
        rows.append(dict(label="key pair", value=k["KeyName"]))
    for img in owned["images"]:
        rows.append(dict(label="image", value=img["ImageId"] + " " + img.get("Name", "")))
    for s in owned["snapshots"]:
        rows.append(dict(label="snapshot", value=s["SnapshotId"]))
    if not rows:
        rows.append(dict(label="nothing", value="no resources tagged %s=%s in %s" % (NAME, a.name, aws.region)))
    else:
        rows.append(caller_note("aws"))
    return dict(rows=rows, owned=owned)


def aws_teardown_apply(a, aws, plan):
    """Delete exactly the tagged resources in the plan, instances first."""
    owned = plan["owned"]
    ids = [i["InstanceId"] for i in owned["instances"]]
    if ids:
        aws.ec2("terminate-instances", "--instance-ids", *ids)

        def gone():
            res = aws.ec2("describe-instances", "--instance-ids", *ids)
            states = {i["State"]["Name"] for r in res["Reservations"] for i in r["Instances"]}
            return states <= {"terminated"}

        wait("the instances to terminate", gone, timeout=900, every=10)
    for g in owned["security_groups"]:
        aws.ec2("delete-security-group", "--group-id", g["GroupId"])
    for k in owned["key_pairs"]:
        aws.ec2("delete-key-pair", "--key-pair-id", k["KeyPairId"])
    for img in owned["images"]:
        aws.ec2("deregister-image", "--image-id", img["ImageId"])
    for s in owned["snapshots"]:
        aws.ec2("delete-snapshot", "--snapshot-id", s["SnapshotId"])
    inv = load_inventory()
    inv["resources"].pop(a.name, None)
    save_inventory(inv)
    return [dict(label="deleted", value=r["value"]) for r in plan["rows"] if r["label"] not in ("nothing", "caller")]


def ranges_of(perm):
    """The IPv4 sources of one security-group permission, as CIDR strings."""
    return {r["CidrIp"] for r in perm.get("IpRanges", [])}


def aws_allow_plan(a, aws):
    """Which sources `aws allow` adds to and removes from the tagged security group.

    The group's tunnel rule is its one single-port UDP permission and its admin rule is
    TCP 22; any other permission is left alone. A source list is replaced, never merged:
    afterwards the rule admits exactly the addresses given. IPv6 ranges, prefix lists
    and group references on a managed rule are removed, because this tool never opens
    them.
    """
    owned = aws.owned(a.name)
    groups = owned["security_groups"]
    roles = {t["Value"] for i in owned["instances"] for t in i.get("Tags", []) if t["Key"] == "avpn:role"}
    record = load_inventory()["resources"].get(a.name, {})
    a.allow_from = tunnel_sources(a.allow_from, first_hop=record.get("first_hop", roles == {"relay"}))
    if len(groups) != 1:
        raise CloudError("expected one security group tagged %s=%s, found %d" % (NAME, a.name, len(groups)))
    g = groups[0]
    perms = g.get("IpPermissions", [])
    tunnel = [p for p in perms if p.get("IpProtocol") == "udp" and p.get("FromPort") == p.get("ToPort")]
    ssh = [p for p in perms if p.get("IpProtocol") == "tcp" and p.get("FromPort") == 22 and p.get("ToPort") == 22]
    if len(tunnel) != 1:
        raise CloudError(
            "%s has %d single-port UDP rules; cannot tell which is the tunnel" % (g["GroupId"], len(tunnel))
        )
    wanted = []
    if a.allow_from:
        wanted.append(("tunnel", tunnel[0], "udp", tunnel[0]["FromPort"], a.allow_from, "ADVANCED_VPN previous hop"))
    if a.admin_ip:
        wanted.append(("ssh", ssh[0] if ssh else {}, "tcp", 22, [a.admin_ip], "admin SSH"))
    add, remove, rows = [], [], [dict(label="firewall", value="%s %s" % (g["GroupId"], g.get("GroupName", "")))]
    for label, perm, proto, port, sources, why in wanted:
        now, new = ranges_of(perm), set(sources)
        extra = {k: perm[k] for k in ("Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs") if perm.get(k)}
        if new - now:
            add.append(
                dict(
                    IpProtocol=proto,
                    FromPort=port,
                    ToPort=port,
                    IpRanges=[dict(CidrIp=c, Description=why) for c in sorted(new - now)],
                )
            )
        if now - new or extra:
            gone = dict(IpProtocol=proto, FromPort=port, ToPort=port, **extra)
            if now - new:
                gone["IpRanges"] = [dict(CidrIp=c) for c in sorted(now - new)]
            remove.append(gone)
        was = sorted(now) + (["%d non-IPv4 source(s)" % sum(map(len, extra.values()))] if extra else [])
        state = "unchanged" if now == new and not extra else "was " + (", ".join(was) or "closed")
        rows.append(dict(label=label, value="%s %d from %s (%s)" % (proto, port, ", ".join(sorted(new)), state)))
    kept = [p for p in perms if not any(p is w[1] for w in wanted)]
    rows.append(dict(label="unchanged", value="%d other ingress rule(s)" % len(kept)))
    if not add and not remove:
        rows = [dict(label="nothing", value="%s already admits exactly these addresses" % g["GroupId"])]
    else:
        rows.append(caller_note("aws"))
    return dict(group=g["GroupId"], add=add, remove=remove, rows=rows)


def aws_allow_apply(a, aws, plan):
    """Open the new sources, then close the old ones, and record them."""
    if plan["add"]:
        aws.ec2(
            "authorize-security-group-ingress", "--group-id", plan["group"], "--ip-permissions", json.dumps(plan["add"])
        )
    if plan["remove"]:
        aws.ec2(
            "revoke-security-group-ingress", "--group-id", plan["group"], "--ip-permissions", json.dumps(plan["remove"])
        )
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    if record is not None:
        if a.allow_from:
            record["allow_from"] = a.allow_from
        if a.admin_ip:
            record["admin_ip"] = a.admin_ip
        save_inventory(inv)
    return plan["rows"]


def oci(*args):
    """`oci ...` with JSON output."""
    return call([tool("oci"), *args])


def oci_rule(a):
    """The single ingress rule `oci allow` manages for `name`."""
    opts = dict(destinationPortRange=dict(min=a.port, max=a.port))
    rule = dict(
        protocol="17" if a.protocol == "udp" else "6",
        source=a.allow_from[0],
        sourceType="CIDR_BLOCK",
        isStateless=False,
        description="advanced-vpn:" + a.name,
    )
    rule["udpOptions" if a.protocol == "udp" else "tcpOptions"] = opts
    return rule


def oci_allow(a, apply):
    """Plan or apply one tagged ingress rule on a security list (add, or remove with --teardown)."""
    if len(a.allow_from) != 1:
        raise CloudError("oci allow takes exactly one --allow-from address")
    sl = oci("network", "security-list", "get", "--security-list-id", a.security_list)["data"]
    tag = "advanced-vpn:" + a.name
    ingress = [r for r in sl["ingress-security-rules"] if r.get("description") != tag]
    mine = [r for r in sl["ingress-security-rules"] if r.get("description") == tag]
    rows = [dict(label="security list", value="%s (%s)" % (sl["display-name"], a.security_list))]
    if a.teardown:
        rows += [dict(label="remove", value="%s from %s" % (tag, r["source"])) for r in mine] or [
            dict(label="nothing", value="no rule described " + tag)
        ]
        new = ingress
    else:
        rule = oci_rule(a)
        rows.append(dict(label="add", value="%s %d from %s (%s)" % (a.protocol, a.port, a.allow_from[0], tag)))
        if mine:
            rows.append(dict(label="replace", value="%d existing %s rule(s)" % (len(mine), tag)))
        new = ingress + [rule]
    rows.append(
        dict(
            label="unchanged",
            value="%d other ingress and %d egress rules" % (len(ingress), len(sl["egress-security-rules"])),
        )
    )
    rows.append(caller_note("oci"))
    if not apply:
        return rows
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "ingress.json").write_text(json.dumps(new))
        (Path(d) / "egress.json").write_text(json.dumps(sl["egress-security-rules"]))
        oci(
            "network",
            "security-list",
            "update",
            "--security-list-id",
            a.security_list,
            "--ingress-security-rules",
            "file://" + str(Path(d) / "ingress.json"),
            "--egress-security-rules",
            "file://" + str(Path(d) / "egress.json"),
            "--force",
        )
    inv = load_inventory()
    if a.teardown:
        inv["resources"].pop(a.name, None)
    else:
        inv["resources"][a.name] = dict(
            provider="oci", security_list=a.security_list, rule=tag, source=a.allow_from[0], port=a.port
        )
    save_inventory(inv)
    return rows


OCI_SHAPES = {"micro": "VM.Standard.E2.1.Micro", "arm": "VM.Standard.A1.Flex"}
OCI_CIDR = "10.77.100.0/24"


class Oci:
    """The OCI CLI for one config profile, always in the tenancy's home region (Always
    Free resources exist only there)."""

    def __init__(self, profile="DEFAULT", compartment=None):
        import configparser

        self.exe = tool("oci")
        self.profile = profile
        path = Path(os.environ.get("OCI_CLI_CONFIG_FILE", Path.home() / ".oci" / "config"))
        cfg = configparser.ConfigParser()
        if not cfg.read(path):
            raise CloudError("no OCI CLI configuration at %s (run: oci setup config)" % path)
        section = cfg.defaults() if profile == "DEFAULT" else (cfg[profile] if cfg.has_section(profile) else None)
        if not section or "tenancy" not in section or "region" not in section:
            raise CloudError("OCI profile %s has no tenancy or region in %s" % (profile, path))
        self.tenancy, self.region = section["tenancy"], section["region"]
        self.compartment = compartment or self.tenancy

    def __call__(self, *args):
        """Run `oci ARGS` for this profile and region; return the parsed JSON."""
        return call([self.exe, *args, "--profile", self.profile, "--region", self.region])

    def home_region(self):
        """The tenancy's home region name."""
        regions = self("iam", "region-subscription", "list", "--tenancy-id", self.tenancy)["data"]
        return next(r["region-name"] for r in regions if r.get("is-home-region"))

    def tags(self, name):
        """Freeform tags marking a resource as this tool's."""
        return json.dumps({"avpn-managed": "true", "avpn-name": name})


def oci_ingress(port, sources, admin):
    """Security-list ingress: the tunnel port from `sources`, SSH from `admin`."""
    rules = [
        dict(
            protocol="17",
            source=c,
            sourceType="CIDR_BLOCK",
            isStateless=False,
            description="ADVANCED_VPN previous hop",
            udpOptions=dict(destinationPortRange=dict(min=port, max=port)),
        )
        for c in sources
    ]
    rules += [
        dict(
            protocol="6",
            source=c,
            sourceType="CIDR_BLOCK",
            isStateless=False,
            description="admin SSH",
            tcpOptions=dict(destinationPortRange=dict(min=22, max=22)),
        )
        for c in admin
    ]
    return rules


def oci_server_plan(a, oc):
    """What `oci server --apply` will create, after checking the home region and shape."""
    home = oc.home_region()
    if oc.region != home:
        raise CloudError(
            "Always Free servers exist only in the home region %s; this profile uses %s" % (home, oc.region)
        )
    shape = OCI_SHAPES[a.shape]
    ads = [d["name"] for d in oc("iam", "availability-domain", "list", "--compartment-id", oc.tenancy)["data"]]
    ad = next(
        (
            d
            for d in ads
            if shape
            in {
                x["shape"]
                for x in oc(
                    "compute", "shape", "list", "--compartment-id", oc.compartment, "--availability-domain", d, "--all"
                )["data"]
            }
        ),
        None,
    )
    if not ad:
        raise CloudError("%s is not offered to this tenancy in %s" % (shape, home))
    images = oc(
        "compute", "image", "list", "--compartment-id", oc.compartment, "--operating-system", "Canonical Ubuntu",
        "--operating-system-version", "24.04", "--shape", shape, "--sort-by", "TIMECREATED", "--sort-order", "DESC",
        "--all",
    )["data"]  # fmt: skip
    if not images:
        raise CloudError("no Ubuntu 24.04 image for %s in %s" % (shape, home))
    image = next((i for i in images if "Minimal" not in i["display-name"]), images[0])
    port = a.port or ROLES[a.role]
    size = "1 OCPU / 1 GB" if a.shape == "micro" else "%d OCPU / %d GB" % (a.ocpus, a.memory_gib)
    rows = [
        dict(label="tenancy", value="home region %s, compartment %s" % (home, oc.compartment[-12:])),
        dict(label="instance", value="%s %s (%s), %s" % (a.name, shape, size, ad)),
        dict(label="image", value=image["display-name"]),
        dict(label="network", value="own VCN %s with an internet gateway, all tagged %s" % (OCI_CIDR, a.name)),
        dict(label="firewall", value="udp %d from %s; SSH 22 from %s" % (port, ", ".join(a.allow_from), a.admin_ip)),
        dict(label="cost", value="Always Free: $0 within 2 micro instances or 2 OCPU / 12 GB of A1 per tenancy"),
    ]
    if load_inventory()["resources"].get(a.name):
        rows.append(dict(label="exists", value="%s is already recorded (apply refuses)" % a.name))
    rows.append(caller_note("oci"))
    return dict(rows=rows, ad=ad, image=image["id"], shape=shape, port=port)


def oci_server_apply(a, oc, plan):
    """Create the network, firewall and instance; record each id as it is created."""
    inv = load_inventory()
    if a.name in inv["resources"]:
        raise CloudError("%s is already recorded; tear it down first" % a.name)
    rec = dict(provider="oci", catalog="oci", profile=a.oci_profile, region=oc.region, compartment=oc.compartment)
    rec.update(role=a.role, port=plan["port"], ssh_user="ubuntu", first_hop=a.role == "relay")
    rec["created"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    inv["resources"][a.name] = rec
    tags = oc.tags(a.name)
    c = ["--compartment-id", oc.compartment]
    wait_ok = ["--wait-for-state", "AVAILABLE"]

    def record(**ids):
        rec.update(ids)
        save_inventory(inv)

    vcn = oc("network", "vcn", "create", *c, "--cidr-blocks", json.dumps([OCI_CIDR]), "--display-name", a.name,
             "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
    record(vcn=vcn["id"], route_table=vcn["default-route-table-id"])
    igw = oc("network", "internet-gateway", "create", *c, "--vcn-id", vcn["id"], "--is-enabled", "true",
             "--display-name", a.name, "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
    record(internet_gateway=igw["id"])
    route = [dict(destination="0.0.0.0/0", destinationType="CIDR_BLOCK", networkEntityId=igw["id"])]
    oc("network", "route-table", "update", "--rt-id", vcn["default-route-table-id"], "--route-rules", json.dumps(route),
       "--force", *wait_ok)  # fmt: skip
    egress = [dict(destination="0.0.0.0/0", protocol="all", isStateless=False)]
    ingress = oci_ingress(plan["port"], a.allow_from, [a.admin_ip])
    sl = oc("network", "security-list", "create", *c, "--vcn-id", vcn["id"], "--display-name", a.name,
            "--egress-security-rules", json.dumps(egress), "--ingress-security-rules", json.dumps(ingress),
            "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
    record(security_list=sl["id"], managed_list=True)
    subnet = oc("network", "subnet", "create", *c, "--vcn-id", vcn["id"], "--cidr-block", OCI_CIDR,
                "--display-name", a.name, "--route-table-id", vcn["default-route-table-id"],
                "--security-list-ids", json.dumps([sl["id"]]), "--prohibit-public-ip-on-vnic", "false",
                "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
    record(subnet=subnet["id"])
    key = ssh_key_dir(a.name)
    if not key.exists():
        subprocess.run(
            [
                shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                a.name,
                "-f",
                str(key),
            ],
            check=True,
        )
    # First-boot hardening: every log in RAM before sshd accepts its first login.
    user_data = first_boot_file()
    launch = ["compute", "instance", "launch", *c, "--availability-domain", plan["ad"], "--shape", plan["shape"],
              "--image-id", plan["image"], "--subnet-id", subnet["id"], "--assign-public-ip", "true",
              "--ssh-authorized-keys-file", str(key) + ".pub", "--display-name", a.name, "--freeform-tags", tags,
              "--instance-options", json.dumps(dict(areLegacyImdsEndpointsDisabled=True)),
              "--user-data-file", str(user_data),
              "--wait-for-state", "RUNNING"]  # fmt: skip
    if a.shape == "arm":
        launch += ["--shape-config", json.dumps(dict(ocpus=a.ocpus, memoryInGBs=a.memory_gib))]
    try:
        inst = oc(*launch)["data"]
    finally:
        user_data.unlink(missing_ok=True)
    record(instance=inst["id"], ssh_key=str(key))
    vnics = oc("compute", "instance", "list-vnics", "--instance-id", inst["id"])["data"]
    ip = vnics[0].get("public-ip")
    if not ip:
        raise CloudError("%s has no public address" % inst["id"])
    record(public_ip=ip)
    return [
        dict(label="instance", value="%s %s" % (inst["id"][-16:], plan["shape"])),
        dict(label="public address", value="%s (udp %d)" % (ip, plan["port"])),
        dict(label="ssh", value="ssh -i %s ubuntu@%s" % (key, ip)),
        dict(label="next", value="avpn cloud chain --apply (or: avpn cloud host setup --name %s --out FILE)" % a.name),
    ]


# Teardown order, and how to check and delete each recorded OCI resource.
OCI_PARTS = [
    ("instance", ("compute", "instance"), "--instance-id", ["--preserve-boot-volume", "false"], "TERMINATED"),
    ("subnet", ("network", "subnet"), "--subnet-id", [], "TERMINATED"),
    ("security_list", ("network", "security-list"), "--security-list-id", [], "TERMINATED"),
    ("internet_gateway", ("network", "internet-gateway"), "--ig-id", [], "TERMINATED"),
    ("vcn", ("network", "vcn"), "--vcn-id", [], "TERMINATED"),
]


def oci_teardown_plan(a, oc):
    """The recorded OCI resources a teardown deletes; each must carry this tool's tags."""
    rec = load_inventory()["resources"].get(a.name)
    if not rec or rec.get("provider") != "oci":
        return dict(rows=[dict(label="nothing", value="%s is not an OCI server this tool created" % a.name)], parts=[])
    rows, parts = [], []
    for field, noun, flag, _, _ in OCI_PARTS:
        if not rec.get(field):
            continue
        got = oc(*noun, "get", flag, rec[field])["data"]
        tags = got.get("freeform-tags", {})
        if tags.get("avpn-managed") != "true" or tags.get("avpn-name") != a.name:
            raise CloudError("refusing: %s %s is not tagged avpn-name=%s" % (field, rec[field][-16:], a.name))
        if got.get("lifecycle-state") in ("TERMINATED", "TERMINATING"):
            continue
        rows.append(dict(label=field.replace("_", " "), value=rec[field][-24:]))
        parts.append(field)
    rows = rows or [dict(label="nothing", value="every recorded resource of %s is already gone" % a.name)]
    if parts:
        rows.append(caller_note("oci"))
    return dict(rows=rows, parts=parts, record=rec)


def oci_teardown_apply(a, oc, plan):
    """Delete exactly the planned resources, instance first."""
    rec = plan["record"]
    for field, noun, flag, extra, state in OCI_PARTS:
        if field not in plan["parts"]:
            continue
        if field == "internet_gateway" and rec.get("route_table"):
            # The VCN's default route table points at the gateway; empty it first.
            oc("network", "route-table", "update", "--rt-id", rec["route_table"], "--route-rules", "[]", "--force")
        verb = "terminate" if field == "instance" else "delete"
        oc(*noun, verb, flag, rec[field], *extra, "--force", "--wait-for-state", state)
    inv = load_inventory()
    inv["resources"].pop(a.name, None)
    save_inventory(inv)
    return [dict(label="deleted", value=r["value"]) for r in plan["rows"] if r["label"] not in ("nothing", "caller")]


# What a server needs, as a script run over SSH: bash -s -- ROLE PORT REPLACE SHARED.
# The TSS2 runtime libraries let systemd-creds actually use the TPM; without them it
# silently falls back to the host key. Keys are kept when the role is unchanged.
HOST_SETUP = r"""set -e
ROLE=$1 PORT=$2 REPLACE=$3 SHARED=$4
E=/etc/advanced-vpn/enrolled
# No retained data, first: a dedicated server keeps every log in RAM before anything
# else runs (tools/retention.py). A shared host's logging belongs to its other
# workloads, so it is only marked, and doctor reports it.
if [ "$SHARED" != yes ]; then
  sudo -n sh -s <<'AVPN_HARDEN'
@@HARDEN@@
AVPN_HARDEN
  sudo -n rm -f /etc/advanced-vpn/shared-host
else
  sudo -n mkdir -p /etc/advanced-vpn
  sudo -n touch /etc/advanced-vpn/shared-host
fi
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update -qq
TSS=$(apt-cache search --names-only '^libtss2-(esys|mu|rc|tcti-device)' | awk '{print $1}' | grep -v -- -dev | tr '\n' ' ')
sudo -n apt-get install -y -qq nftables python3-venv $TSS >/dev/null
# Images that reject by default (OCI's Ubuntu) need the tunnel port accepted on the host.
if sudo -n iptables -S INPUT 2>/dev/null | grep -q -- '-j REJECT'; then
  sudo -n iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || sudo -n iptables -I INPUT 1 -p udp --dport "$PORT" -j ACCEPT
  # Persisting would also save a shared host's other runtime rules, so only a dedicated one does.
  if [ "$SHARED" != yes ] && command -v netfilter-persistent >/dev/null; then sudo -n netfilter-persistent save >/dev/null 2>&1 || true; fi
fi
sudo -n rm -rf /tmp/avpn-src && mkdir -p /tmp/avpn-src && tar -C /tmp/avpn-src -xzf /tmp/avpn-src.tgz
sudo -n python3 -B /tmp/avpn-src/tools/install.py --apply >/dev/null
HAVE=$(sudo -n python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["role"])' $E/request.json 2>/dev/null || true)
if [ -n "$HAVE" ] && [ "$HAVE" = "$ROLE" ]; then
  echo "keys=kept"
elif [ -n "$HAVE" ] && [ "$REPLACE" != yes ]; then
  echo "this server has keys for role $HAVE; replace them to make it a $ROLE" >&2; exit 3
else
  sudo -n systemctl stop advanced-vpn.service 2>/dev/null || true
  sudo -n rm -rf $E
  sudo -n /opt/advanced-vpn/bin/avpnctl request --role "$ROLE" --protect systemd-creds --out /root/request.json >/dev/null
  echo "keys=new"
fi
sudo -n cat $E/request.json > /tmp/avpn-request.json
echo "tpm2=$(systemd-analyze has-tpm2 >/dev/null 2>&1 && echo yes || echo no) creds_key=$(sudo -n python3 -c 'import json;print(json.load(open("/etc/advanced-vpn/enrolled/protection.json")).get("creds_key"))')"
sudo -n rm -rf /tmp/avpn-src /tmp/avpn-src.tgz
""".replace("@@HARDEN@@", retention.HARDEN.rstrip("\n"))

# Install a signed bundle on a server and (re)start it: bash -s -- (bundle on stdin is not used).
HOST_ENROLL = r"""set -e
sudo -n systemctl stop advanced-vpn.service 2>/dev/null || true
sudo -n /opt/advanced-vpn/bin/avpnctl enroll /tmp/avpn-bundle.avpn --operator-key /tmp/avpn-operator.pub --replace >/dev/null
rm -f /tmp/avpn-bundle.avpn /tmp/avpn-operator.pub
sudo -n systemctl restart advanced-vpn.service
sleep 3
systemctl is-active advanced-vpn.service
"""


def ssh_base(name, record):
    """ssh/scp options for a recorded host: its key (or SSH config), its own known_hosts."""
    known = INVENTORY.parent / "ssh" / (name + ".known_hosts")
    known.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    opts = ["-F", record["ssh_config"]] if record.get("ssh_config") else []
    if record.get("ssh_key"):
        opts += ["-i", record["ssh_key"], "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"]
    return opts + [
        "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + str(known),
        "-o", "ConnectTimeout=20", "-o", "BatchMode=yes",
    ]  # fmt: skip


def ssh_target(record):
    """`user@host` (or an SSH config alias) for a recorded server."""
    if record.get("ssh"):
        return record["ssh"]
    return "%s@%s" % (record.get("ssh_user", "admin"), record["public_ip"])


def source_tarball(root, out):
    """The release package for a built checkout (the installer's own `pack`)."""
    try:
        return pack(root, out)
    except FileNotFoundError as e:
        raise CloudError(str(e)) from None


def glibc_needed(root):
    """The newest glibc symbol version any packaged binary needs, as (major, minor)."""
    import install
    import re

    found = (0, 0)
    for b in install.BINARIES:
        data = (Path(root) / "target/release" / b).read_bytes()
        for m in re.finditer(rb"GLIBC_(\d+)\.(\d+)", data):
            found = max(found, (int(m.group(1)), int(m.group(2))))
    return found


def check_glibc(name, have, need):
    """Refuse to install binaries a server's C library cannot run."""
    import re

    m = re.search(r"(\d+)\.(\d+)", have or "")
    if not m:
        raise CloudError("cannot tell %s's C library version (%r)" % (name, have))
    got = (int(m.group(1)), int(m.group(2)))
    if got < need:
        raise CloudError(
            "%s has glibc %d.%d but this package needs %d.%d: install from a release build "
            "(built on Ubuntu 22.04) with --source" % ((name, *got, *need))
        )


def remote(name, record):
    """(ssh, scp, base options, target) for one recorded server."""
    return tool("ssh"), tool("scp"), ssh_base(name, record), ssh_target(record)


def setup_server(name, record, role, port, out, source, replace=False):
    """Install or upgrade the package on a recorded server and fetch its public request
    for `role`, with the tunnel `port` accepted by the host firewall. Returns
    (kept|new, TPM report)."""
    ssh, scp, base, host = remote(name, record)

    def reachable():
        try:
            call([ssh, *base, host, "true"], parse=False)
            return True
        except CloudError:
            return False

    wait("SSH on " + name, reachable, timeout=300, every=10)
    try:
        need = glibc_needed(source)
    except FileNotFoundError as e:
        raise CloudError("%s is missing: build first (cargo build --release)" % e.filename) from None
    check_glibc(name, call([ssh, *base, host, "getconf GNU_LIBC_VERSION"], parse=False), need)
    with tempfile.TemporaryDirectory() as d:
        tgz = source_tarball(Path(source).resolve(), Path(d) / "avpn-src.tgz")
        call([scp, "-q", *base, str(tgz), host + ":/tmp/avpn-src.tgz"], parse=False)
    args = [role, str(port), "yes" if replace else "no"]
    args.append("yes" if record.get("shared") else "no")
    report = call([ssh, *base, host, "bash", "-s", "--", *args], parse=False, stdin=HOST_SETUP)
    out.parent.mkdir(parents=True, exist_ok=True)
    call([scp, "-q", *base, host + ":/tmp/avpn-request.json", str(out)], parse=False)
    if json.loads(out.read_text()).get("role") != role:
        raise CloudError("the request from %s is not for role %s" % (name, role))
    lines = report.strip().splitlines()
    keys = next((x.split("=", 1)[1] for x in lines if x.startswith("keys=")), "new")
    return keys, (lines[-1] if lines else "")


def host_setup(a):
    """`host setup`: install on a recorded server and fetch its public request."""
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    if not record or not record.get("public_ip") or not (record.get("ssh_key") or record.get("ssh_config")):
        raise CloudError("%s is not a recorded host with an address and SSH access" % a.name)
    role = a.role or record.get("role")
    if role not in ROLES:
        raise CloudError("give --role relay|middle|exit for %s" % a.name)
    port = record["port"] if record.get("role") == role and record.get("port") else ROLES[role]
    keys, tpm = setup_server(a.name, record, role, port, a.out, a.source, replace=a.replace)
    record.update(role=role, port=port, request=str(a.out))
    save_inventory(inv)
    return [
        dict(label="host", value="%s %s (%s)" % (a.name, record["public_ip"], role)),
        dict(label="installed", value="/opt/advanced-vpn (service not enabled)"),
        dict(label="keys", value="%s; %s" % ("kept" if keys == "kept" else "generated", tpm)),
        dict(label="request", value="%s (public; give it to avpn init)" % a.out),
    ]


def host_add(a):
    """`host add`: record a server you already have (any provider, or your own machine)."""
    inv = load_inventory()
    if a.name in inv["resources"]:
        raise CloudError("%s is already recorded" % a.name)
    if not a.key and not a.ssh_config:
        raise CloudError("give --key FILE (or --ssh-config FILE) so SSH never asks for a password")
    if a.key:
        key = Path(a.key).expanduser().resolve()
        if not key.is_file():
            raise CloudError("no SSH key at %s" % key)
        if key.stat().st_mode & 0o077:
            raise CloudError("%s is readable by others; chmod 600 it first" % key)
    if a.catalog not in providers.ALL_KEYS:
        raise CloudError("--provider must be one of " + ", ".join(p["key"] for p in providers.PROVIDERS))
    host = a.ssh.rsplit("@", 1)[-1]
    address = a.address or host
    try:
        address = socket.gethostbyname(address)
    except OSError:
        raise CloudError("cannot resolve %s; give --address IP" % address) from None
    address = single_ip(address)[:-3]
    record = dict(
        provider="ssh",
        catalog=a.catalog,
        ssh=a.ssh,
        public_ip=address,
        shared=a.shared,
        added=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    )
    if a.key:
        record["ssh_key"] = str(Path(a.key).expanduser().resolve())
    if a.ssh_config:
        record["ssh_config"] = str(Path(a.ssh_config).expanduser().resolve())
    ssh, _, base, target = remote(a.name, record)
    call([ssh, *base, target, "sudo -n true"], parse=False)
    inv["resources"][a.name] = record
    save_inventory(inv)
    return [
        dict(label="server", value="%s %s (%s)" % (a.name, address, providers.by_key(a.catalog)["name"])),
        dict(label="ssh", value="%s works, with passwordless sudo" % a.ssh),
        dict(label="firewall", value="not managed by this tool: the chain plan lists what to open"),
        dict(label="journal", value="left as it is (shared host)" if a.shared else "set to RAM only during setup"),
    ]


def host_forget(a):
    """`host forget`: drop a server from the inventory (nothing on it changes)."""
    inv = load_inventory()
    if inv["resources"].pop(a.name, None) is None:
        raise CloudError("%s is not recorded" % a.name)
    save_inventory(inv)
    return [dict(label="forgotten", value="%s (the server itself is unchanged)" % a.name)]


def servers():
    """Recorded servers that can be chain hops: name -> provider key (catalog)."""
    out = {}
    for name, r in load_inventory()["resources"].items():
        if r.get("public_ip") and (r.get("ssh_key") or r.get("ssh_config")):
            out[name] = r.get("catalog", r["provider"])
    return out


FIRST_HOP_PORT = ROLES["relay"]  # the WireGuard carrier, whatever the first hop's role
# The exit's own address inside the tunnel. Its public address does not work from
# inside: cloud servers do not hold it locally (the provider translates it at its edge).
EXIT_TUNNEL_IP = "10.77.0.1"


def chain_order(recorded, order=None):
    """Hop order for up to three servers, client side first.

    The exit is the server with the largest monthly outbound allowance (it carries
    everything). The entry relay prefers a different provider from the exit, so no
    single provider sees both your address and your destinations.
    """
    if order:
        names = [n.strip() for n in order.split(",") if n.strip()]
        unknown = [n for n in names if n not in recorded]
        if unknown:
            raise CloudError("not recorded as servers: " + ", ".join(unknown))
        if len(set(names)) != len(names) or not 1 <= len(names) <= 3:
            raise CloudError("--order takes one to three different servers")
        return names
    if not recorded:
        raise CloudError("no servers recorded yet: see avpn cloud suggest")

    def allowance(n):
        if recorded[n] not in providers.ALL_KEYS:
            return 0
        return providers.by_key(recorded[n])["egress_gib"] or 0

    pool = sorted(recorded, key=lambda n: (-allowance(n), n))
    exit_ = pool.pop(0)
    pool.sort(key=lambda n: (recorded[n] == recorded[exit_], -allowance(n), n))
    return pool[:2] + [exit_]


def chain_layout(names, inv):
    """Role, port, tunnel sources and final SSH sources for each hop."""
    roles = {1: ["exit"], 2: ["relay", "exit"], 3: ["relay", "middle", "exit"]}[len(names)]
    exit_ip = inv[names[-1]]["public_ip"] + "/32"
    hops = []
    for k, (name, role) in enumerate(zip(names, roles, strict=True)):
        port = FIRST_HOP_PORT if k == 0 else ROLES[role]
        sources = [ANY] if k == 0 else [inv[names[k - 1]]["public_ip"] + "/32"]
        # Connected through the chain, your SSH reaches every other hop from the exit's
        # address, and the exit itself at its tunnel address (EXIT_TUNNEL_IP), which
        # needs no firewall rule at all; so no rule names you.
        ssh = [] if name == names[-1] else [exit_ip]
        hops.append(dict(name=name, role=role, port=port, sources=sources, ssh=ssh, record=inv[name]))
    return hops


def sg_diff(perms, wanted):
    """Authorize/revoke lists that make a group's managed rules exactly `wanted`.

    Managed rules are every single-port UDP permission and TCP 22; `wanted` maps
    (protocol, port) to the set of IPv4 CIDRs it should admit.
    """
    have = {}
    extra = {}
    for q in perms:
        key = (q.get("IpProtocol"), q.get("FromPort"))
        managed = (key[0] == "udp" and q.get("FromPort") == q.get("ToPort")) or (
            key[0] == "tcp" and q.get("FromPort") == q.get("ToPort") == 22
        )
        if managed:
            have[key] = ranges_of(q)
            extra[key] = {k: q[k] for k in ("Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs") if q.get(k)}
    add, remove = [], []
    for (proto, port), cidrs in wanted.items():
        new = sorted(set(cidrs) - have.get((proto, port), set()))
        if new:
            add.append(dict(IpProtocol=proto, FromPort=port, ToPort=port, IpRanges=[dict(CidrIp=c) for c in new]))
    for (proto, port), cidrs in have.items():
        gone = sorted(cidrs - set(wanted.get((proto, port), ())))
        if gone or extra[(proto, port)]:
            perm = dict(IpProtocol=proto, FromPort=port, ToPort=port, **extra[(proto, port)])
            if gone:
                perm["IpRanges"] = [dict(CidrIp=c) for c in gone]
            remove.append(perm)
    return add, remove


def set_firewall(name, record, port, sources, ssh):
    """Make a managed server's firewall admit exactly the tunnel `sources` on `port`
    and SSH from `ssh`. Returns a description, or None for a firewall this tool does
    not manage."""
    if record["provider"] == "aws":
        aws = Aws(record["profile"], record["region"])
        groups = aws.owned(name)["security_groups"]
        if len(groups) != 1:
            raise CloudError("expected one security group tagged %s=%s" % (NAME, name))
        wanted = {("udp", port): set(sources), ("tcp", 22): set(ssh)}
        add, remove = sg_diff(groups[0].get("IpPermissions", []), wanted)
        gid = groups[0]["GroupId"]
        if add:
            aws.ec2("authorize-security-group-ingress", "--group-id", gid, "--ip-permissions", json.dumps(add))
        if remove:
            aws.ec2("revoke-security-group-ingress", "--group-id", gid, "--ip-permissions", json.dumps(remove))
        return "%s: udp %d from %s; SSH from %s" % (gid, port, ", ".join(sources), ", ".join(ssh) or "nobody")
    if record["provider"] == "oci" and record.get("managed_list"):
        oc = Oci(record.get("profile", "DEFAULT"), record.get("compartment"))
        oc("network", "security-list", "update", "--security-list-id", record["security_list"],
           "--ingress-security-rules", json.dumps(oci_ingress(port, sources, ssh)), "--force")  # fmt: skip
        return "security list: udp %d from %s; SSH from %s" % (port, ", ".join(sources), ", ".join(ssh) or "nobody")
    return None


def controller():
    """The controller used to sign the chain (`AVPN_CTL` overrides it in tests)."""
    override = os.environ.get("AVPN_CTL")
    return [override] if override else [sys.executable, str(Path(__file__).with_name("avpnctl.py"))]


def chain_plan(a):
    """The hops `chain --apply` will build, and every change it will make."""
    inv = load_inventory()["resources"]
    names = chain_order(servers(), a.order)
    hops = chain_layout(names, inv)
    rows = []
    for k, h in enumerate(hops, 1):
        r = h["record"]
        managed = r["provider"] == "aws" or (r["provider"] == "oci" and r.get("managed_list"))
        how = "managed" if managed else "NOT managed: open it yourself"
        rows.append(
            dict(
                label="hop %d" % k,
                value="%s %s %s (%s)" % (h["role"], h["name"], r["public_ip"], r.get("catalog", r["provider"])),
            )
        )
        rows.append(dict(label="", value="udp %d from %s; firewall %s" % (h["port"], ", ".join(h["sources"]), how)))
        if r.get("role") and r["role"] != h["role"]:
            rows.append(dict(label="", value="new keys: it was a %s" % r["role"]))
    extra = sorted(set(servers()) - set(names))
    if extra:
        rows.append(dict(label="unused", value=", ".join(extra) + " (a chain has at most 3 hops)"))
    cap = providers.capacity_gib(r["record"].get("catalog", r["record"]["provider"]) for r in hops)
    if cap:
        rows.append(dict(label="capacity", value="about %d GiB/month, the smallest hop allowance" % cap))
    rows.append(dict(label="sign", value="one Nitrokey PIN + touch (vault %s)" % a.vault))
    rows.append(
        dict(
            label="ssh",
            value="afterwards only while connected: other hops admit the exit's address, the exit answers at %s"
            % EXIT_TUNNEL_IP,
        )
    )
    for provider in sorted({h["record"]["provider"] for h in hops} & set(CALLER_LOG)):
        rows.append(caller_note(provider))
    return dict(rows=rows, hops=hops)


def chain_apply(a, plan):
    """Build the chain: firewalls, packages and requests, one signature, enrollment."""
    hops = plan["hops"]
    me = single_ip("auto")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    work = INVENTORY.parent / "chains" / stamp
    work.mkdir(mode=0o700, parents=True)
    done = []
    # 1. Open each managed firewall in its final form, plus SSH from here for setup.
    for h in hops:
        set_firewall(h["name"], h["record"], h["port"], h["sources"], sorted(set(h["ssh"]) | {me}))
    # 2. Install or upgrade each server and collect its request for its role.
    requests = {}
    for h in hops:
        out = work / "requests" / (h["role"] + ".req")
        keys, tpm = setup_server(h["name"], h["record"], h["role"], h["port"], out, a.source, replace=True)
        requests[h["role"]] = out
        done.append(dict(label=h["name"], value="%s, keys %s, %s" % (h["role"], keys, tpm)))
    # 3. One signature over the whole chain.
    endpoint = {h["role"]: "%s:%d" % (h["record"]["public_ip"], h["port"]) for h in hops}
    argv = [*controller(), "--json", "init", "--out", str(work / "bundles"), "--hops", str(len(hops))]
    argv += ["--exit", endpoint["exit"], "--vault", str(a.vault)]
    for role in ("relay", "middle"):
        if role in endpoint:
            argv += ["--" + role, endpoint[role]]
    argv += ["--request", "client=%s" % Path(a.client_request).resolve()]
    argv += [x for role, f in requests.items() for x in ("--request", "%s=%s" % (role, f))]
    call(argv, parse=False)
    bundles = work / "bundles"
    # 4. Enroll and start, exit first, so each hop's next hop is already up.
    for h in reversed(hops):
        ssh, scp, base, host = remote(h["name"], h["record"])
        call([scp, "-q", *base, str(bundles / (h["role"] + ".avpn")), host + ":/tmp/avpn-bundle.avpn"], parse=False)
        call([scp, "-q", *base, str(bundles / "operator.pub"), host + ":/tmp/avpn-operator.pub"], parse=False)
        state = call([ssh, *base, host, "bash", "-s"], parse=False, stdin=HOST_ENROLL).strip().splitlines()
        if not state or state[-1] != "active":
            raise CloudError("%s did not start after enrolling" % h["name"])
    # 5. SSH only through the chain from now on.
    for h in hops:
        set_firewall(h["name"], h["record"], h["port"], h["sources"], h["ssh"])
    inv = load_inventory()
    for h in hops:
        inv["resources"][h["name"]].update(role=h["role"], port=h["port"], first_hop=h is hops[0])
    inv["chain"] = dict(hops=[h["name"] for h in hops], created=stamp, bundles=str(bundles))
    save_inventory(inv)
    client = bundles / "client.avpn"
    return (
        done
        + [
            dict(label="chain", value=" -> ".join(["client"] + ["%s(%s)" % (h["role"], h["name"]) for h in hops])),
            dict(label="client", value="%s and %s" % (client, bundles / "operator.pub")),
            dict(
                label="next",
                value="sudo avpn enroll %s --operator-key %s --replace" % (client, bundles / "operator.pub"),
            ),
            dict(label="", value="then: sudo avpn connect"),
        ]
        + [
            dict(label="admin" if k == 0 else "", value="ssh %s (while connected)" % admin_target(h, h is hops[-1]))
            for k, h in enumerate(hops)
        ]
    )


def admin_target(hop, is_exit):
    """How to SSH to a hop once the chain is up: the exit by its tunnel address."""
    target = ssh_target(hop["record"])
    if not is_exit:
        return target
    user = target.rsplit("@", 1)[0] if "@" in target else "USER"
    return "%s@%s" % (user, EXIT_TUNNEL_IP)


def suggest(a):
    """The endpoint catalog, ranked, with whether each is ready to use from here."""
    rows = []
    for p in providers.ranked():
        out = providers.outbound(p)
        ready, why = providers.readiness(p, a.profile if p["key"] == "aws" else None)
        if not providers.usable(p):
            ready, why = False, "too little outbound transfer for a hop"
        rows.append(dict(label=p["key"], value="%s: %s; %s; %s" % (p["name"], p["terms"], out, p["servers"])))
        rows.append(dict(label="", value="note: " + p["caveats"]))
        rows.append(dict(label="", value=("ready: " if ready else "not ready: ") + why))
        if providers.usable(p):
            rows.append(dict(label="", value="$ " + p["next"]))
    rows.append(dict(label="next", value=providers.recommendation(servers())))
    return rows


def _server_addresses():
    """The public addresses of every recorded server (the only sources a rule may name)."""
    return {r["public_ip"] for r in load_inventory()["resources"].values() if r.get("public_ip")}


def _foreign(cidrs, servers):
    """Sources in `cidrs` that are neither "any" nor one of your servers."""
    return sorted(c for c in cidrs if c != ANY and c.split("/")[0] not in servers)


def audit_aws(profile, servers):
    """Rows and finding count for one AWS profile, in its Region (logs also in us-east-1)."""
    aws = Aws(profile)
    rows, findings = [], 0

    def row(label, found, detail):
        nonlocal findings
        findings += bool(found)
        rows.append(dict(label=label, value=("FOUND: " if found else "") + detail))

    def ask(*args):
        """Run a read; None when the account may not read it (a managed-account policy)."""
        try:
            return aws(*args)
        except CloudError as e:
            if "AccessDenied" in str(e) or "not authorized" in str(e):
                return None
            raise

    trails = ask("cloudtrail", "describe-trails", "--include-shadow-trails")
    names = [t["Name"] for t in (trails or {}).get("trailList", [])]
    row("aws trails", bool(names), ", ".join(names) or "none (API calls kept only in the 90-day history)")
    stores = ask("cloudtrail", "list-event-data-stores")
    names = [d.get("Name") for d in (stores or {}).get("EventDataStores", [])]
    row("aws cloudtrail lake", bool(names), ", ".join(names) or "none")
    flows = ask("ec2", "describe-flow-logs")
    names = ["%s on %s" % (f["FlowLogId"], f["ResourceId"]) for f in (flows or {}).get("FlowLogs", [])]
    row("aws vpc flow logs", bool(names), ", ".join(names) or "none")
    mirrors = ask("ec2", "describe-traffic-mirror-sessions")
    names = [m["TrafficMirrorSessionId"] for m in (mirrors or {}).get("TrafficMirrorSessions", [])]
    row("aws traffic mirroring", bool(names), ", ".join(names) or "none")
    config = ask("configservice", "describe-configuration-recorder-status")
    names = [c["name"] for c in (config or {}).get("ConfigurationRecordersStatus", []) if c.get("recording")]
    row("aws config recording", bool(names), ", ".join(names) or "none (firewall history not recorded)")
    dns = ask("route53resolver", "list-resolver-query-log-configs")
    names = [c.get("Name") for c in (dns or {}).get("ResolverQueryLogConfigs", [])]
    row("aws dns query logs", bool(names), ", ".join(names) or "none")
    groups = []
    for region in sorted({aws.region, "us-east-1"}):
        out = call(
            [aws.exe, "logs", "describe-log-groups", "--profile", profile, "--region", region, "--output", "json"]
        )
        groups += ["%s (%s)" % (g["logGroupName"], region) for g in out.get("logGroups", [])]
    row("aws log groups", bool(groups), ", ".join(groups) or "none in %s or us-east-1" % aws.region)
    for name, r in sorted(load_inventory()["resources"].items()):
        if r.get("provider") != "aws" or r.get("profile") != profile:
            continue
        for g in aws.owned(name)["security_groups"]:
            cidrs = [x["CidrIp"] for q in g.get("IpPermissions", []) for x in q.get("IpRanges", [])]
            bad = _foreign(cidrs, servers)
            row("aws firewall " + name, bool(bad), ("names %s, which is not one of your servers" % ", ".join(bad))
                if bad else "only any-address and your servers")  # fmt: skip
    detectors = ask("guardduty", "list-detectors")
    if detectors is None:
        rows.append(dict(label="aws guardduty", value="cannot check: the account may not read it (a managing policy)"))
    else:
        ids = detectors.get("DetectorIds", [])
        row("aws guardduty", bool(ids), ("detectors %s analyse flow and DNS data" % ", ".join(ids)) if ids else "off")
    history = ask("cloudtrail", "lookup-events", "--max-items", "1000") or {}
    callers = set()
    for e in history.get("Events", []):
        ip = json.loads(e.get("CloudTrailEvent", "{}")).get("sourceIPAddress", "")
        if ip and not ip.endswith("amazonaws.com") and ip != "AWS Internal":
            callers.add(ip)
    rows.append(
        dict(
            label="aws always on",
            value="CloudTrail keeps every API caller's address for 90 days and cannot be turned off; "
            "%d caller addresses are in it now" % len(callers),
        )
    )
    return rows, findings


def audit_oci(profile, servers):
    """Rows and finding count for one OCI CLI profile, across the whole tenancy."""
    oc = Oci(profile)
    rows, findings = [], 0

    def row(label, found, detail):
        nonlocal findings
        findings += bool(found)
        rows.append(dict(label=label, value=("FOUND: " if found else "") + detail))

    subs = oc(
        "iam", "compartment", "list", "--compartment-id", oc.tenancy, "--compartment-id-in-subtree", "true", "--all"
    )
    compartments = [oc.tenancy] + [c["id"] for c in subs.get("data", [])]
    logs, flows, vtaps, allow = [], [], [], []
    for c in compartments:
        for g in oc("logging", "log-group", "list", "--compartment-id", c, "--all").get("data", []):
            members = oc("logging", "log", "list", "--log-group-id", g["id"], "--all").get("data", [])
            for log in members:
                source = (((log.get("configuration") or {}).get("source")) or {}).get("service", "")
                (flows if source == "flowlogs" else logs).append(log.get("display-name", "?"))
            if not members:
                logs.append(g.get("display-name", "?") + " (empty group)")
        vtaps += [
            v.get("display-name", "?")
            for v in oc("network", "vtap", "list", "--compartment-id", c, "--all").get("data", [])
        ]
        for b in oc("bastion", "bastion", "list", "--compartment-id", c, "--all").get("data", []):
            got = oc("bastion", "bastion", "get", "--bastion-id", b["id"]).get("data", {})
            bad = _foreign(got.get("client-cidr-block-allow-list", []), servers)
            if bad:
                allow.append("%s admits %s" % (got.get("name", "?"), ", ".join(bad)))
    row("oci flow logs", bool(flows), ", ".join(flows) or "none")
    row("oci other logs", bool(logs), ", ".join(logs) or "none")
    row("oci traffic mirroring", bool(vtaps), ", ".join(vtaps) or "none")
    row("oci bastions", bool(allow), "; ".join(allow) or "admit only your servers (or none exist)")
    for name, r in sorted(load_inventory()["resources"].items()):
        if r.get("provider") != "oci" or not r.get("security_list"):
            continue
        rules = oc("network", "security-list", "get", "--security-list-id", r["security_list"]).get("data", {})
        ingress = rules.get("ingress-security-rules", [])
        if not r.get("managed_list"):
            # A list this tool does not own (oci allow): only its own tagged rule is ours to judge.
            ingress = [x for x in ingress if x.get("description") == r.get("rule", "advanced-vpn:" + name)]
        bad = _foreign([x.get("source", "") for x in ingress], servers)
        row("oci firewall " + name, bool(bad), ("names %s, which is not one of your servers" % ", ".join(bad))
            if bad else "only any-address and your servers")  # fmt: skip
    rows.append(
        dict(
            label="oci always on",
            value="OCI Audit keeps every API caller's address for 365 days and cannot be turned off",
        )
    )
    return rows, findings


def audit(a):
    """`cloud audit`: what the providers log about you, and what this tool cannot turn off."""
    servers = _server_addresses()
    inv = load_inventory()["resources"].values()
    rows, findings = [], 0
    profiles = sorted(
        {r["profile"] for r in inv if r.get("provider") == "aws" and r.get("profile")}
        | ({a.profile} if a.profile else set())
    )
    for profile in profiles:
        r, f = audit_aws(profile, servers)
        rows += r
        findings += f
    oci_used = any(r.get("provider") == "oci" or r.get("catalog") == "oci" for r in inv) or a.oci_profile
    if oci_used:
        r, f = audit_oci(a.oci_profile or "DEFAULT", servers)
        rows += r
        findings += f
    if not rows:
        rows.append(dict(label="nothing", value="no AWS or OCI resources recorded; give --profile or --oci-profile"))
    rows.append(
        dict(
            label="on the servers",
            value="avpn doctor on each server checks that no log reaches its disk (avpn help retention)",
        )
    )
    return rows, findings


def status(a):
    """The inventory, and for AWS entries whether the instance still exists."""
    inv = load_inventory()
    rows = []
    for name, r in sorted(inv["resources"].items()):
        detail = "%s %s" % (r["provider"], r.get("role") or r.get("rule", ""))
        if r["provider"] == "aws" and r.get("instance"):
            detail += " %s %s:%s" % (r["instance"], r.get("public_ip", "?"), r.get("port", "?"))
            if a.live:
                try:
                    found = Aws(r["profile"], r["region"]).owned(name)["instances"]
                    detail += " (running)" if found else " (gone)"
                except CloudError as e:
                    detail += " (unknown: %s)" % e
        if r["provider"] == "oci":
            detail += " %s:%s" % (r["source"], r["port"])
        rows.append(dict(label=name, value=detail))
    return rows or [dict(label="nothing", value="no cloud resources recorded in " + str(INVENTORY))]


def build_parser():
    """The `avpn cloud` command line; also walked by the documentation gate."""
    p = argparse.ArgumentParser(prog="avpn cloud", description=__doc__)
    p.add_argument("--json", action="store_true", help="print one JSON object (used by the avpn CLI)")
    s = p.add_subparsers(dest="provider", required=True)
    sg = s.add_parser("suggest", help="free places to run servers, ranked, and which you can use from here")
    sg.add_argument(
        "--profile", default=os.environ.get("AWS_PROFILE"), help="AWS CLI profile to check (default: $AWS_PROFILE)"
    )
    au = s.add_parser("audit", help="what the cloud providers log about you, and what cannot be turned off")
    au.add_argument("--profile", default=os.environ.get("AWS_PROFILE"), help="AWS CLI profile to audit too")
    au.add_argument("--oci-profile", help="OCI CLI profile to audit too (default: DEFAULT, if OCI is used)")
    st = s.add_parser("status", help="recorded resources and whether they still exist")
    st.add_argument("--live", action="store_true", help="ask the provider whether each instance still exists")
    aws = s.add_parser("aws", help="Amazon Web Services")
    aws_s = aws.add_subparsers(dest="kind", required=True)
    relay = aws_s.add_parser("relay", help="one chain server on EC2 (relay, middle or exit)")
    mode = relay.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="create the server")
    mode.add_argument("--teardown", action="store_true", help="delete everything tagged with --name")
    relay.add_argument("--name", default="avpn-relay", help="resource name and tag (avpn-*)")
    relay.add_argument("--role", choices=sorted(ROLES), default="relay", help="what the server is in the chain")
    relay.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "default"), help="AWS CLI profile")
    relay.add_argument("--region", help="must equal the profile's Region (the project has one Region)")
    relay.add_argument("--instance-type", default="t3.micro", help="EC2 type with NitroTPM support")
    relay.add_argument("--disk-gib", type=int, default=8, help="root disk size")
    relay.add_argument("--port", type=int, help="tunnel port (default: 41194 relay, 4445 middle, 4444 exit)")
    relay.add_argument(
        "--allow-from",
        action="append",
        default=[],
        help="previous hop's public IPv4, auto, or any (first hop only; the default for a relay)",
    )
    relay.add_argument("--admin-ip", default="auto", help="address allowed to SSH in (default: this machine)")
    relay.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    relay.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    allow = aws_s.add_parser("allow", help="replace who may reach a server this tool created")
    allow.add_argument("--apply", action="store_true", required=True, help="change the security group")
    allow.add_argument("--name", default="avpn-relay", help="the server's name and tag (avpn-*)")
    allow.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "default"), help="AWS CLI profile")
    allow.add_argument("--region", help="must equal the profile's Region (the project has one Region)")
    allow.add_argument(
        "--allow-from",
        action="append",
        default=[],
        help="new previous-hop public IPv4, auto, or any (first hop only); repeatable",
    )
    allow.add_argument("--admin-ip", help="new address allowed to SSH in, or auto")
    allow.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    allow.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    h = s.add_parser("host", help="servers this tool created")
    h_s = h.add_subparsers(dest="kind", required=True)
    setup = h_s.add_parser("setup", help="install the package over SSH and fetch the public request")
    setup.add_argument("--name", required=True, help="the recorded server (avpn-*)")
    setup.add_argument(
        "--source", default=str(Path(__file__).resolve().parents[1]), help="built checkout to install from"
    )
    setup.add_argument("--out", type=Path, required=True, help="where to save the server's public request")
    setup.add_argument("--role", choices=sorted(ROLES), help="the server's role (default: its recorded role)")
    setup.add_argument("--replace", action="store_true", help="replace keys made for another role")
    add = h_s.add_parser("add", help="record a server you already have (any provider, or your own machine)")
    add.add_argument("--name", required=True, help="a name for it (avpn-*)")
    add.add_argument("--ssh", required=True, help="USER@HOST (a sudo user), or a host alias with --ssh-config")
    add.add_argument("--key", help="SSH private key for it (mode 600)")
    add.add_argument("--ssh-config", help="SSH config file, for bastions, jump hosts or other ports")
    add.add_argument("--address", help="its public IPv4 if HOST is not it (for example behind a bastion)")
    add.add_argument(
        "--provider",
        dest="catalog",
        default="own",
        help="where it runs: oci, aws, azure, gcp or own (sets its allowance)",
    )
    add.add_argument("--shared", action="store_true", help="it also runs other things: leave its journal alone")
    forget = h_s.add_parser("forget", help="drop a recorded server from the inventory (it is not changed)")
    forget.add_argument("--name", required=True, help="the recorded server")
    ch = s.add_parser("chain", help="join the recorded servers into one multi-hop chain")
    ch.add_argument("--apply", action="store_true", required=True, help="build (or rebuild) the chain")
    ch.add_argument("--client-request", type=Path, required=True, help="the client device's public request")
    ch.add_argument("--vault", type=Path, required=True, help="the operator's Nitrokey vault directory")
    ch.add_argument("--order", help="hop order, client side first: NAME,NAME[,NAME] (default: automatic)")
    ch.add_argument(
        "--source", default=str(Path(__file__).resolve().parents[1]), help="built package or checkout to install"
    )
    ch.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    ch.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    o = s.add_parser("oci", help="Oracle Cloud Infrastructure")
    o_s = o.add_subparsers(dest="kind", required=True)
    srv = o_s.add_parser("server", help="one Always Free chain server, with its own network")
    mode = srv.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="create the server")
    mode.add_argument("--teardown", action="store_true", help="delete everything recorded for --name")
    srv.add_argument("--name", default="avpn-exit", help="resource name and tag (avpn-*)")
    srv.add_argument("--role", choices=sorted(ROLES), default="exit", help="what the server is in the chain")
    srv.add_argument("--shape", choices=sorted(OCI_SHAPES), default="micro", help="micro (AMD, 1 GB) or arm (A1)")
    srv.add_argument("--ocpus", type=int, default=1, help="A1 only: OCPUs (Always Free: 2 in total)")
    srv.add_argument("--memory-gib", type=int, default=6, help="A1 only: memory (Always Free: 12 GB in total)")
    srv.add_argument("--compartment", help="compartment OCID (default: the tenancy's root)")
    srv.add_argument("--oci-profile", default="DEFAULT", help="profile in ~/.oci/config")
    srv.add_argument("--port", type=int, help="tunnel port (default: 41194 relay, 4445 middle, 4444 exit)")
    srv.add_argument(
        "--allow-from",
        action="append",
        default=[],
        help="previous hop's public IPv4, auto, or any (first hop only; the default for a relay)",
    )
    srv.add_argument("--admin-ip", default="auto", help="address allowed to SSH in (default: this machine)")
    srv.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    srv.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    allow = o_s.add_parser("allow", help="one ingress rule on a security list, from the previous hop only")
    mode = allow.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="add (or replace) the rule")
    mode.add_argument("--teardown", action="store_true", help="remove the rule")
    allow.add_argument("--name", required=True, help="rule name (avpn-*), stored in its description")
    allow.add_argument("--security-list", required=True, help="security list OCID")
    allow.add_argument("--allow-from", action="append", default=[], help="previous hop's public IPv4, or auto")
    allow.add_argument("--port", type=int, default=4444, help="destination port")
    allow.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="transport")
    allow.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    allow.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    return p


def confirm(a, title):
    """Ask on the terminal unless --yes; JSON mode never prompts."""
    if a.yes:
        return True
    if a.json or not sys.stdin.isatty():
        raise CloudError("add --yes to confirm (no terminal to ask on)")
    return input("%s? Type yes to continue: " % title).strip() == "yes"


def run(a):
    """Execute one parsed command; return the result object."""
    if a.provider == "suggest":
        return dict(title="Where to run your servers", summary="checked %s" % providers.CHECKED, rows=suggest(a))
    if a.provider == "audit":
        rows, findings = audit(a)
        summary = "%d finding(s)" % findings if findings else "no opt-in logging found"
        return dict(title="Provider logging audit", summary=summary, rows=rows, findings=findings)
    if a.provider == "status":
        return dict(title="Cloud", summary="inventory " + str(INVENTORY), rows=status(a))
    if a.provider == "host":
        valid_name(a.name)
        if a.kind == "add":
            return dict(title="Add server %s" % a.name, summary="recorded", rows=host_add(a))
        if a.kind == "forget":
            return dict(title="Forget server %s" % a.name, summary="forgotten", rows=host_forget(a))
        return dict(title="Set up %s" % a.name, summary="installed", rows=host_setup(a))
    if a.provider == "chain":
        plan = chain_plan(a)
        title = "Build a %d-hop chain" % len(plan["hops"])
        if a.dry_run:
            return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
        if not confirm(a, title):
            return dict(title=title, summary="cancelled", rows=plan["rows"])
        return dict(title=title, summary="built", rows=chain_apply(a, plan))
    if a.provider == "oci" and a.kind == "server":
        valid_name(a.name)
        oc = Oci(a.oci_profile, a.compartment)
        if a.apply:
            if not a.allow_from and a.role != "relay":
                raise CloudError("--allow-from is required: the previous server's address")
            a.allow_from = tunnel_sources(a.allow_from or ["any"], first_hop=a.role == "relay")
            a.admin_ip = single_ip(a.admin_ip)
            plan = oci_server_plan(a, oc)
            title = "Create OCI %s %s" % (a.role, a.name)
            if a.dry_run:
                return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
            if not confirm(a, title):
                return dict(title=title, summary="cancelled", rows=plan["rows"])
            return dict(title=title, summary="created", rows=oci_server_apply(a, oc, plan))
        plan = oci_teardown_plan(a, oc)
        title = "Remove OCI %s" % a.name
        if a.dry_run or plan["rows"][0]["label"] == "nothing":
            return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
        if not confirm(a, title):
            return dict(title=title, summary="cancelled", rows=plan["rows"])
        return dict(title=title, summary="deleted", rows=oci_teardown_apply(a, oc, plan))
    if a.provider == "aws":
        valid_name(a.name)
        aws = Aws(a.profile, a.region)
        if a.kind == "allow":
            if not a.allow_from and not a.admin_ip:
                raise CloudError("nothing to change: give --allow-from and/or --admin-ip (auto = this machine)")
            a.admin_ip = a.admin_ip and single_ip(a.admin_ip)
            plan = aws_allow_plan(a, aws)
            title = "Update AWS firewall %s" % a.name
            if a.dry_run or plan["rows"][0]["label"] == "nothing":
                return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
            if not confirm(a, title):
                return dict(title=title, summary="cancelled", rows=plan["rows"])
            return dict(title=title, summary="applied", rows=aws_allow_apply(a, aws, plan))
        if a.apply:
            if not a.allow_from and a.role != "relay":
                raise CloudError("--allow-from is required: the previous server's address")
            a.allow_from = tunnel_sources(a.allow_from or ["any"], first_hop=a.role == "relay")
            a.admin_ip = single_ip(a.admin_ip)
            plan = aws_relay_plan(a, aws)
            title = "Create AWS %s %s" % (a.role, a.name)
            if a.dry_run:
                return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
            if not confirm(a, title):
                return dict(title=title, summary="cancelled", rows=plan["rows"])
            return dict(title=title, summary="created", rows=aws_relay_apply(a, aws, plan))
        plan = aws_teardown_plan(a, aws)
        title = "Remove AWS %s" % a.name
        if a.dry_run or plan["rows"][0]["label"] == "nothing":
            return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
        if not confirm(a, title):
            return dict(title=title, summary="cancelled", rows=plan["rows"])
        return dict(title=title, summary="deleted", rows=aws_teardown_apply(a, aws, plan))
    valid_name(a.name)
    a.allow_from = [single_ip(x) for x in a.allow_from] or (["0.0.0.0/0"] if a.teardown else [])
    if not a.allow_from:
        raise CloudError("--allow-from is required: the previous hop's address")
    title = "%s OCI rule %s" % ("Remove" if a.teardown else "Add", a.name)
    rows = oci_allow(a, apply=False)
    if a.dry_run:
        return dict(title=title, summary="plan", rows=rows, dry_run=True)
    if not confirm(a, title):
        return dict(title=title, summary="cancelled", rows=rows)
    return dict(title=title, summary="applied", rows=oci_allow(a, apply=True))


def main(argv=None):
    """Entry point: refuses root, prints JSON or text, returns the exit status."""
    a = build_parser().parse_args(argv)
    if os.geteuid() == 0:
        print(json.dumps(dict(ok=False, error="RunAsYourself")) if a.json else "run avpn cloud as yourself, not root")
        return 1
    try:
        result = run(a)
    except (CloudError, OSError, ValueError, KeyError) as e:
        msg = str(e) if isinstance(e, CloudError) else "%s: %s" % (type(e).__name__, e)
        if a.json:
            print(json.dumps(dict(ok=False, action="cloud", error=type(e).__name__, message=msg)))
        print("avpn cloud: " + msg, file=sys.stderr)
        return 1
    result.update(ok=True, action="cloud")
    if a.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("%s  %s" % (result["title"], result.get("summary", "")))
        for r in result["rows"]:
            print("  %-15s %s" % (r["label"], r["value"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

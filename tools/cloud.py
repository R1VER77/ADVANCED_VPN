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
import base64
import datetime
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from install import pack  # the installer's own package format
import fee_guard
import providers
import retention

MANAGED = "avpn:managed"
NAME = "avpn:name"
DEBIAN_OWNER = "136693071363"  # Debian's official AWS account
INVENTORY = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "advanced-vpn" / "cloud.json"
# On-demand list prices in eu-north-1 (USD, checked 2026-11). These are estimates only:
# the free plan's credits pay for them, and AWS Billing shows the real cost.
MONTHLY_USD = {"t3.micro": 7.88, "t3.small": 15.77, "gp3_gib": 0.0836, "public_ipv4": 3.65}
# The first hop serves the HTTP/3 camouflage on UDP 443, as a web server would.
ROLES = {"relay": 443, "middle": 4445, "exit": 4444}
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


# ssh/scp failing before the remote side ran anything: exit 255 with one of these. The
# Instance Connect tunnel drops a session now and then right after authentication (live,
# 22 Nov 2026: "Connection closed by UNKNOWN port 65535" one second into the setup
# script); every host script this tool runs is safe to run again.
SSH_TRANSIENT = ("Connection closed by UNKNOWN port 65535", "kex_exchange_identification", "Connection reset by peer")
SSH_TRIES = 3


def call(argv, parse=True, stdin=None, sleep=time.sleep):
    """Run a provider CLI command; return its parsed JSON output (or text). An ssh or scp
    whose connection dropped before the remote command ran is tried again (SSH_TRANSIENT)."""
    for attempt in range(SSH_TRIES):
        r = subprocess.run(argv, capture_output=True, text=True, timeout=900, check=False, input=stdin)
        transient = (
            r.returncode == 255 and Path(argv[0]).name in ("ssh", "scp") and any(t in r.stderr for t in SSH_TRANSIENT)
        )
        if not transient or attempt == SSH_TRIES - 1:
            break
        sleep(5 * (attempt + 1))
    if r.returncode != 0:
        detail = (r.stderr.strip().splitlines() or ["exit %d" % r.returncode])[-1]
        if "{" in r.stderr:  # OCI prints a JSON service error; its last line is just "}"
            try:
                err = json.loads(r.stderr[r.stderr.index("{") :])
                detail = "%s: %s" % (err.get("code", "error"), err.get("message", detail))
            except ValueError:
                pass
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
    "azure": "the Azure Activity Log keeps each management call, with its caller, for 90 days",
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
    if plan["port"] == FIRST_HOP_PORT:
        # A first hop also takes the camouflage's TLS/TCP fallback on the same port.
        perms.append(
            dict(
                IpProtocol="tcp",
                FromPort=plan["port"],
                ToPort=plan["port"],
                IpRanges=[dict(CidrIp=c, Description="ADVANCED_VPN camouflage TLS fallback") for c in a.allow_from],
            )
        )
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
    # The provider's own name for this address: the cloak sends it as its server name,
    # so name and address agree, as for any site hosted there.
    if inst.get("PublicDnsName"):
        created["public_dns"] = inst["PublicDnsName"]
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
    admin = dict(endpoints=admin_endpoints(aws, a.name), groups=aws.owned(a.name + ADMIN_SUFFIX)["security_groups"])
    for e in admin["endpoints"]:
        rows.append(dict(label="admin endpoint", value=e["InstanceConnectEndpointId"]))
    for g in admin["groups"]:
        rows.append(dict(label="firewall", value=g["GroupId"] + " " + g["GroupName"]))
    if not rows:
        rows.append(dict(label="nothing", value="no resources tagged %s=%s in %s" % (NAME, a.name, aws.region)))
    else:
        rows.append(caller_note("aws"))
    return dict(rows=rows, owned=owned, admin=admin)


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
    admin = plan.get("admin", dict(endpoints=[], groups=[]))
    for e in admin["endpoints"]:
        aws.ec2("delete-instance-connect-endpoint", "--instance-connect-endpoint-id", e["InstanceConnectEndpointId"])
    for g in admin["groups"]:
        # Its outbound rule names the server's group, which could not be deleted while named.
        for p in g.get("IpPermissionsEgress", []):
            aws.ec2("revoke-security-group-egress", "--group-id", g["GroupId"], "--ip-permissions", json.dumps([p]))
    if admin["endpoints"]:
        ids = [e["InstanceConnectEndpointId"] for e in admin["endpoints"]]
        wait("the Instance Connect Endpoint to go", lambda: not [
            e for e in aws.ec2("describe-instance-connect-endpoints", "--instance-connect-endpoint-ids", *ids)
            .get("InstanceConnectEndpoints", []) if e.get("State") != "delete-complete"], timeout=900, every=15)  # fmt: skip
    for g in owned["security_groups"] + admin["groups"]:
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
    if a.admin_ip and eice_admin(record):
        raise CloudError(
            "%s is administered through its Instance Connect Endpoint (`aws admin-endpoint`): "
            "SSH admits no address, so there is no --admin-ip to change" % a.name
        )
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


ADMIN_SUFFIX = "-admin"


def admin_endpoints(aws, name):
    """The Instance Connect Endpoints this tool made for `name`'s administration."""
    f = ["Name=tag:%s,Values=true" % MANAGED, "Name=tag:%s,Values=%s" % (NAME, name + ADMIN_SUFFIX)]
    found = aws.ec2("describe-instance-connect-endpoints", "--filters", *f).get("InstanceConnectEndpoints", [])
    return [e for e in found if e.get("State") not in ("delete-complete", "delete-in-progress")]


def aws_admin_endpoint_plan(a, aws):
    """What `aws admin-endpoint` creates: an EC2 Instance Connect Endpoint in the server's
    subnet, its own security group (no inbound; outbound SSH to the server only), and the
    server's SSH rule replaced by that group, so admin SSH depends on an AWS login, never
    on the address it comes from."""
    owned = aws.owned(a.name)
    if len(owned["instances"]) != 1 or len(owned["security_groups"]) != 1:
        raise CloudError("expected one instance and one security group tagged %s=%s" % (NAME, a.name))
    instance, group = owned["instances"][0], owned["security_groups"][0]
    ssh = [p for p in group.get("IpPermissions", []) if p.get("IpProtocol") == "tcp" and p.get("FromPort") == 22]
    endpoints = admin_endpoints(aws, a.name)
    admin_groups = aws.owned(a.name + ADMIN_SUFFIX)["security_groups"]
    rows = [
        dict(label="server", value="%s %s" % (instance["InstanceId"], instance.get("PublicIpAddress", ""))),
        dict(
            label="endpoint",
            value=endpoints[0]["InstanceConnectEndpointId"]
            if endpoints
            else "new, in %s (free; reached through AWS, authorised by your AWS login)" % instance["SubnetId"],
        ),  # fmt: skip
        dict(
            label="group",
            value=admin_groups[0]["GroupId"]
            if admin_groups
            else "new %s: no inbound, outbound SSH to %s only" % (a.name + ADMIN_SUFFIX, group["GroupId"]),
        ),  # fmt: skip
        dict(
            label="ssh",
            value="tcp 22 from that group only (was %s)"
            % (", ".join(sorted(ranges_of(ssh[0]))) if ssh and ranges_of(ssh[0]) else "no address"),
        ),  # fmt: skip
    ]
    return dict(instance=instance, group=group, endpoints=endpoints, admin_groups=admin_groups, rows=rows)


def aws_admin_endpoint_apply(a, aws, plan):
    """Create (or reuse) the endpoint and its group, admit SSH from that group only, then
    close every address on the server's SSH rule, and record it."""
    instance, group = plan["instance"], plan["group"]
    gid = group["GroupId"]
    if plan["admin_groups"]:
        admin_gid = plan["admin_groups"][0]["GroupId"]
    else:
        admin_gid = aws.ec2(
            "create-security-group", "--group-name", a.name + ADMIN_SUFFIX, "--vpc-id", instance["VpcId"],
            "--description", "Instance Connect Endpoint for %s admin SSH (no inbound)" % a.name,
            "--tag-specifications", aws.tags("security-group", a.name + ADMIN_SUFFIX),
        )["GroupId"]  # fmt: skip
        aws.ec2("revoke-security-group-egress", "--group-id", admin_gid, "--ip-permissions",
                json.dumps([dict(IpProtocol="-1", IpRanges=[dict(CidrIp="0.0.0.0/0")])]))  # fmt: skip
        aws.ec2("authorize-security-group-egress", "--group-id", admin_gid, "--ip-permissions", json.dumps(
            [dict(IpProtocol="tcp", FromPort=22, ToPort=22, UserIdGroupPairs=[dict(GroupId=gid)])]))  # fmt: skip
    if plan["endpoints"]:
        endpoint = plan["endpoints"][0]["InstanceConnectEndpointId"]
    else:
        endpoint = aws.ec2(
            "create-instance-connect-endpoint", "--subnet-id", instance["SubnetId"],
            "--security-group-ids", admin_gid, "--no-preserve-client-ip",
            "--tag-specifications", aws.tags("instance-connect-endpoint", a.name + ADMIN_SUFFIX),
        )["InstanceConnectEndpoint"]["InstanceConnectEndpointId"]  # fmt: skip

    def ready():
        got = aws.ec2("describe-instance-connect-endpoints", "--instance-connect-endpoint-ids", endpoint)
        state = got["InstanceConnectEndpoints"][0]["State"]
        if state == "create-failed":
            raise CloudError("the Instance Connect Endpoint could not be created")
        return state == "create-complete"

    wait("the Instance Connect Endpoint", ready, timeout=900, every=15)
    ssh = [p for p in group.get("IpPermissions", []) if p.get("IpProtocol") == "tcp" and p.get("FromPort") == 22]
    if not any(pair.get("GroupId") == admin_gid for p in ssh for pair in p.get("UserIdGroupPairs", [])):
        aws.ec2("authorize-security-group-ingress", "--group-id", gid, "--ip-permissions", json.dumps([dict(
            IpProtocol="tcp", FromPort=22, ToPort=22, UserIdGroupPairs=[dict(
                GroupId=admin_gid, Description="admin SSH via its Instance Connect Endpoint")])]))  # fmt: skip
    for p in ssh:  # the endpoint is open first; only then is any address closed
        drop = {k: p[k] for k in ("IpRanges", "Ipv6Ranges", "PrefixListIds") if p.get(k)}
        others = [q for q in p.get("UserIdGroupPairs", []) if q.get("GroupId") != admin_gid]
        if others:
            drop["UserIdGroupPairs"] = others
        if drop:
            aws.ec2("revoke-security-group-ingress", "--group-id", gid, "--ip-permissions",
                    json.dumps([dict(IpProtocol="tcp", FromPort=22, ToPort=22, **drop)]))  # fmt: skip
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    if record is not None:
        record["admin"] = dict(via="eice", endpoint=endpoint, group=admin_gid, instance=instance["InstanceId"])
        record.pop("admin_ip", None)
        save_inventory(inv)
    return plan["rows"] + [dict(label="admin", value="ssh now goes through %s; no address is admitted" % endpoint)]


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


def oci_ingress(port, sources, admin, tcp=False):
    """Security-list ingress: the tunnel port from `sources`, SSH from `admin`. With
    `tcp` (a first hop), the same port on TCP too, for the camouflage's TLS fallback."""
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
    if tcp:
        rules += [
            dict(
                protocol="6",
                source=c,
                sourceType="CIDR_BLOCK",
                isStateless=False,
                description="ADVANCED_VPN camouflage TLS fallback",
                tcpOptions=dict(destinationPortRange=dict(min=port, max=port)),
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
    # Always Free covers 2 OCPU / 12 GB of A1 in total; anything larger is billed, or
    # removed when a trial's credits run out. Refuse rather than create it.
    if a.shape == "arm" and not (1 <= a.ocpus <= 2 and 1 <= a.memory_gib <= 12):
        raise CloudError(
            "Always Free A1 is at most 2 OCPU and 12 GB in total; asked for %d OCPU / %d GB" % (a.ocpus, a.memory_gib)
        )
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
    network = "own VCN %s with an internet gateway, all tagged %s" % (OCI_CIDR, a.name)
    shared = None
    bastion = None
    if getattr(a, "bastion", None):
        # No SSH address rule (it breaks whenever your address changes, e.g. behind a VPN):
        # SSH only from the bastion's private endpoint, through IAM-authorised sessions.
        b = oc("bastion", "bastion", "get", "--bastion-id", a.bastion)["data"]
        if a.vcn and a.vcn != b["target-vcn-id"]:
            raise CloudError("--vcn must be the bastion's VCN; omit it to use that one")
        a.vcn = b["target-vcn-id"]
        bastion = dict(id=a.bastion, endpoint=b["private-endpoint-ip-address"], region=oc.region)
    if a.vcn:
        # A free tenancy has two VCNs. Inside an existing one, this server gets its own subnet,
        # route table and security list (tagged, and all a teardown removes); the VCN and its
        # internet gateway are used, never changed.
        import ipaddress

        vcn = oc("network", "vcn", "get", "--vcn-id", a.vcn)["data"]
        taken = [ipaddress.ip_network(x["cidr-block"]) for x in oc("network", "subnet", "list", "--compartment-id",
                                                                    oc.compartment, "--vcn-id", a.vcn, "--all")["data"]]  # fmt: skip
        gateways = [g for g in oc("network", "internet-gateway", "list", "--compartment-id", oc.compartment, "--vcn-id",
                                  a.vcn)["data"] if g.get("is-enabled")]  # fmt: skip
        if not gateways:
            raise CloudError("VCN %s has no enabled internet gateway" % vcn.get("display-name", a.vcn[-12:]))
        free = [n for block in vcn.get("cidr-blocks") or [vcn["cidr-block"]]
                for n in reversed(list(ipaddress.ip_network(block).subnets(new_prefix=24)))
                if not any(n.overlaps(t) for t in taken)]  # fmt: skip
        if not free:
            raise CloudError("no free /24 left in VCN %s" % vcn.get("display-name", a.vcn[-12:]))
        shared = dict(vcn=a.vcn, cidr=str(free[0]), gateway=gateways[0]["id"])
        network = "subnet %s in the existing VCN %s, with its own route table and security list, all tagged %s; " \
                  "the VCN and its internet gateway are not changed" % (free[0], vcn.get("display-name", ""), a.name)  # fmt: skip
    rows = [
        dict(label="tenancy", value="home region %s, compartment %s" % (home, oc.compartment[-12:])),
        dict(label="instance", value="%s %s (%s), %s" % (a.name, shape, size, ad)),
        dict(label="image", value=image["display-name"]),
        dict(label="network", value=network),
        dict(
            label="firewall",
            value="%s %d from %s; SSH 22 %s"
            % (
                transports(port),
                port,
                ", ".join(a.allow_from),
                "only from the OCI bastion's private endpoint %s (no address rule)" % bastion["endpoint"]
                if bastion
                else "from " + str(a.admin_ip),
            ),
        ),
        dict(label="cost", value="Always Free: $0 within 2 micro instances or 2 OCPU / 12 GB of A1 per tenancy"),
    ]
    known = load_inventory()["resources"].get(a.name)
    if known and known.get("subnet") and not known.get("instance"):
        rows.append(dict(label="resume", value="%s's network exists without an instance: apply launches it" % a.name))
    elif known:
        rows.append(dict(label="exists", value="%s is already recorded (apply refuses)" % a.name))
    rows.append(caller_note("oci"))
    return dict(rows=rows, ad=ad, image=image["id"], shape=shape, port=port, shared=shared, bastion=bastion)


def oci_server_apply(a, oc, plan):
    """Create the network, firewall and instance; record each id as it is created."""
    inv = load_inventory()
    rec = inv["resources"].get(a.name)
    # A launch that failed (Always Free A1 is often "Out of host capacity") leaves its network
    # recorded and no instance: apply again resumes with that network instead of refusing.
    resume = bool(rec) and rec.get("provider") == "oci" and rec.get("subnet") and not rec.get("instance")
    if rec and not resume:
        raise CloudError("%s is already recorded; tear it down first" % a.name)
    if not resume:
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

    bastion = plan.get("bastion")
    if resume:
        subnet = {"id": rec["subnet"]}
    else:
        shared = plan.get("shared")
        if shared:
            # Not recorded as `vcn`/`internet_gateway`: a teardown never reaches them.
            record(vcn_shared=shared["vcn"])
            route = [dict(destination="0.0.0.0/0", destinationType="CIDR_BLOCK", networkEntityId=shared["gateway"])]
            rt = oc("network", "route-table", "create", *c, "--vcn-id", shared["vcn"], "--display-name", a.name,
                    "--route-rules", json.dumps(route), "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
            record(own_route_table=rt["id"])
            vcn, route_table, cidr = {"id": shared["vcn"]}, rt["id"], shared["cidr"]
        else:
            vcn = oc("network", "vcn", "create", *c, "--cidr-blocks", json.dumps([OCI_CIDR]), "--display-name", a.name,
                     "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
            record(vcn=vcn["id"], route_table=vcn["default-route-table-id"])
            igw = oc("network", "internet-gateway", "create", *c, "--vcn-id", vcn["id"], "--is-enabled", "true",
                     "--display-name", a.name, "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
            record(internet_gateway=igw["id"])
            route = [dict(destination="0.0.0.0/0", destinationType="CIDR_BLOCK", networkEntityId=igw["id"])]
            oc("network", "route-table", "update", "--rt-id", vcn["default-route-table-id"], "--route-rules",
               json.dumps(route), "--force", *wait_ok)  # fmt: skip
            route_table, cidr = vcn["default-route-table-id"], OCI_CIDR
        egress = [dict(destination="0.0.0.0/0", protocol="all", isStateless=False)]
        admin = [bastion["endpoint"] + "/32"] if bastion else [a.admin_ip]
        ingress = oci_ingress(plan["port"], a.allow_from, admin, tcp=plan["port"] == FIRST_HOP_PORT)
        sl = oc("network", "security-list", "create", *c, "--vcn-id", vcn["id"], "--display-name", a.name,
                "--egress-security-rules", json.dumps(egress), "--ingress-security-rules", json.dumps(ingress),
                "--freeform-tags", tags, *wait_ok)["data"]  # fmt: skip
        record(security_list=sl["id"], managed_list=True)
        subnet = oc("network", "subnet", "create", *c, "--vcn-id", vcn["id"], "--cidr-block", cidr,
                    "--display-name", a.name, "--route-table-id", route_table,
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
    if bastion:
        # Managed SSH sessions need the Oracle Cloud Agent's Bastion plugin on the instance.
        launch += ["--agent-config", json.dumps(dict(pluginsConfig=[dict(name="Bastion", desiredState="ENABLED")]))]
    deadline = time.monotonic() + 60 * getattr(a, "wait_capacity", 0)
    domains = ["FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]
    attempt = 0
    try:
        while True:
            try:
                extra = ["--fault-domain", domains[attempt % 3]] if attempt else []
                inst = oc(*launch, *extra)["data"]
                break
            except CloudError as e:
                # Both are transient: no free host now, or the tenancy's API rate limit (live,
                # 20 Nov 2026: a long capacity wait ended on "TooManyRequests").
                busy = "TooManyRequests" in str(e) or "Too many requests" in str(e)
                if "Out of host capacity" not in str(e) and not busy:
                    raise
                if time.monotonic() >= deadline:
                    raise CloudError(
                        "%s: no free capacity for %s right now (its network is kept); run the same --apply "
                        "again later, or with --wait-capacity MINUTES" % (a.name, plan["shape"])
                    ) from None
                attempt += 1
                time.sleep(300 if busy else 120)
    finally:
        user_data.unlink(missing_ok=True)
    record(instance=inst["id"], ssh_key=str(key))
    vnics = oc("compute", "instance", "list-vnics", "--instance-id", inst["id"])["data"]
    ip = vnics[0].get("public-ip")
    if not ip:
        raise CloudError("%s has no public address" % inst["id"])
    record(public_ip=ip)
    if bastion:
        private_ip = vnics[0].get("private-ip")
        if not private_ip:
            raise CloudError("%s has no private address for the bastion to reach" % inst["id"])
        config = bastion_ssh_config(a.name, key, private_ip, bastion["region"])
        record(
            ssh="ubuntu@" + a.name,
            ssh_config=str(config),
            bastion=dict(id=bastion["id"], instance=inst["id"], user="ubuntu", host=a.name + "-bastion",
                         public_key=str(key) + ".pub", oci_profile=a.oci_profile),
        )  # fmt: skip
        how = "through the OCI bastion: avpn cloud renews its session (ssh -F %s %s)" % (config, a.name)
    else:
        how = "ssh -i %s ubuntu@%s" % (key, ip)
    return [
        dict(label="instance", value="%s %s" % (inst["id"][-16:], plan["shape"])),
        dict(label="public address", value="%s (udp %d)" % (ip, plan["port"])),
        dict(label="ssh", value=how),
        dict(label="next", value="avpn cloud chain --apply (or: avpn cloud host setup --name %s --out FILE)" % a.name),
    ]


# Teardown order, and how to check and delete each recorded OCI resource.
OCI_PARTS = [
    ("instance", ("compute", "instance"), "--instance-id", ["--preserve-boot-volume", "false"], "TERMINATED"),
    ("subnet", ("network", "subnet"), "--subnet-id", [], "TERMINATED"),
    ("own_route_table", ("network", "route-table"), "--rt-id", [], "TERMINATED"),
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
ROLE=$1 PORT=$2 REPLACE=$3 SHARED=$4 UNLOCK=${5:-no}
E=/etc/advanced-vpn/enrolled
# Updates and installs need the network the egress lock closes (tools/server_egress.py):
# open a counted maintenance window first. A running supervisor reopens its egress table
# with root allowed; with none running, the retained lock is removed and the next start
# rebuilds it. Traffic still counts against the monthly cap; a capped server stays shut.
M=/etc/advanced-vpn/metering/enrolled
sudo -n install -d -m 0700 /etc/advanced-vpn/metering $M
echo $(( $(date +%s) + 1800 )) | sudo -n tee $M/maintenance-until >/dev/null
trap 'sudo -n rm -f /etc/advanced-vpn/metering/enrolled/maintenance-until' EXIT
if systemctl is-active -q advanced-vpn.service 2>/dev/null; then sleep 7
else sudo -n nft delete table inet advanced_vpn_egress 2>/dev/null || true; fi
# An image host (a Fly.io Machine) was built with the package, its logs in RAM and no
# timers: only its keys are made here.
IMAGE=no; [ -f /opt/advanced-vpn/IMAGE ] && IMAGE=yes
# No retained data, first: a dedicated server keeps every log in RAM before anything
# else runs (tools/retention.py). A shared host's logging belongs to its other
# workloads, so it is only marked, and doctor reports it.
if [ "$IMAGE" = yes ]; then
  :
elif [ "$SHARED" != yes ]; then
  sudo -n sh -s <<'AVPN_HARDEN'
@@HARDEN@@
AVPN_HARDEN
  sudo -n rm -f /etc/advanced-vpn/shared-host
  # Nothing sends on its own (the egress lock would drop it anyway, and every byte counts
  # against the cap): no update timers, snaps, news or telemetry. Updates run in a counted
  # window instead: avpn cloud host update NAME.
  # Their own timers are off; security updates still come daily, from the supervisor.
  for u in apt-daily.timer apt-daily-upgrade.timer snapd.service snapd.socket \
           motd-news.timer ua-timer.timer esm-cache.service update-notifier-download.timer fwupd-refresh.timer; do
    sudo -n systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
else
  sudo -n mkdir -p /etc/advanced-vpn
  sudo -n touch /etc/advanced-vpn/shared-host
fi
if [ "$IMAGE" = no ]; then
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update -qq
TSS=$(apt-cache search --names-only '^libtss2-(esys|mu|rc|tcti-device)' | awk '{print $1}' | grep -v -- -dev | tr '\n' ' ')
# unattended-upgrades: the supervisor runs it daily (security only) in a counted window.
sudo -n apt-get install -y -qq nftables python3-venv unattended-upgrades $TSS >/dev/null
# Images that reject by default (OCI's Ubuntu) need the tunnel port accepted on the host.
if sudo -n iptables -S INPUT 2>/dev/null | grep -q -- '-j REJECT'; then
  sudo -n iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || sudo -n iptables -I INPUT 1 -p udp --dport "$PORT" -j ACCEPT
  sudo -n iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || sudo -n iptables -I INPUT 1 -p tcp --dport "$PORT" -j ACCEPT
  # A first hop redirects its public port to the cloak's unprivileged listener first.
  if [ "$ROLE" != middle ] && [ "$PORT" = 443 ]; then
    sudo -n iptables -C INPUT -p udp --dport 8443 -j ACCEPT 2>/dev/null || sudo -n iptables -I INPUT 1 -p udp --dport 8443 -j ACCEPT
    sudo -n iptables -C INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || sudo -n iptables -I INPUT 1 -p tcp --dport 8443 -j ACCEPT
  fi
  # Persisting would also save a shared host's other runtime rules, so only a dedicated one does.
  if [ "$SHARED" != yes ] && command -v netfilter-persistent >/dev/null; then sudo -n netfilter-persistent save >/dev/null 2>&1 || true; fi
fi
sudo -n rm -rf /tmp/avpn-src && mkdir -p /tmp/avpn-src && tar -C /tmp/avpn-src -xzf /tmp/avpn-src.tgz
# A flat installation from before release slots cannot be moved while it runs: stop what
# runs from it and adopt it, kept as the previous slot for a rollback. `chain` enrolls and
# restarts the service afterwards, and the guard comes back with it (Requires=).
ADOPT=
if [ -d /opt/advanced-vpn/bin ] && [ ! -L /opt/advanced-vpn/bin ]; then
  for unit in advanced-vpn.service advanced-vpn-guard.service; do sudo -n systemctl stop "$unit" 2>/dev/null || true; done
  ADOPT=--adopt-legacy
fi
sudo -n python3 -B /tmp/avpn-src/tools/install.py --apply $ADOPT >/dev/null
fi
HAVE=$(sudo -n python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["role"])' $E/request.json 2>/dev/null || true)
# Same-role keys are kept only if they carry every key this release makes for the role
# (managed_profile.request): keys from before the HTTP/3 camouflage would be refused
# when the chain is signed.
CURRENT=$(sudo -n python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))
need = ["kem_public"]
if r["role"] in ("client", "relay", "exit"):
    need.append("wireguard_public_hex")
if r["role"] in ("relay", "exit"):
    need += ["cloak_spki_sha256", "i2p_destination"]
print("yes" if all(k in r for k in need) else "no")' $E/request.json 2>/dev/null || echo no)
# Keys are kept only if they are protected the way this release requires: sealed to a
# TPM2, or locked to this operator's unlock key. Plain or host-key-only keys are
# replaced, not re-wrapped: copies of them may survive on the disk or in its backups.
STRONG=$(sudo -n python3 -c '
import hashlib, json, sys
p = json.load(open(sys.argv[1]))
ok = p.get("mode") == "systemd-creds" and p.get("creds_key") == "host+tpm2"
if p.get("mode") == "operator" and sys.argv[2] == "yes":
    ok = p["unlock"]["operator_unlock_sha256"] == hashlib.sha256(open("/tmp/avpn-unlock.pub", "rb").read()).hexdigest()
print("yes" if ok else "no")' $E/protection.json "$UNLOCK" 2>/dev/null || echo no)
if [ -n "$HAVE" ] && [ "$HAVE" = "$ROLE" ] && [ "$CURRENT" = yes ] && [ "$STRONG" = yes ]; then
  echo "keys=kept"
elif [ -n "$HAVE" ] && [ "$HAVE" != "$ROLE" ] && [ "$REPLACE" != yes ]; then
  echo "this server has keys for role $HAVE; replace them to make it a $ROLE" >&2; exit 3
else
  sudo -n systemctl stop advanced-vpn.service 2>/dev/null || true
  sudo -n rm -rf $E
  # The host is tested first (docs/HARDWARE_BOUND_SESSIONS.md, servers without a TPM):
  # keys are sealed to its TPM2 when systemd-creds can really use one (systemd 250+, a
  # TPM, the TSS2 libraries this script installs), probed by sealing and opening a
  # throwaway credential rather than trusted from a version number. Otherwise they are
  # locked to the operator's Nitrokey (operator protection): the server cannot open
  # them after a reboot until the operator unlocks it. Never plain files, and never the
  # host key alone, whose secret sits on the same disk as the keys.
  # The probe runs through a pipe, never a file: a root-written file in the sticky /tmp
  # could not be removed by this (unprivileged) script, and under `set -e` that failed
  # removal would abort the setup on exactly the hosts where sealing works.
  PROTECT=
  PROBE_ARGS=
  if command -v systemd-creds >/dev/null 2>&1 \
     && [ "$(printf avpn | sudo -n systemd-creds encrypt --with-key=host+tpm2 --name=avpn-probe - - 2>/dev/null \
            | sudo -n systemd-creds decrypt --name=avpn-probe - - 2>/dev/null)" = avpn ]; then
    PROTECT=systemd-creds
  elif [ "$UNLOCK" = yes ]; then
    PROTECT=operator
    PROBE_ARGS="--unlock-key /tmp/avpn-unlock.pub"
    echo "NOTE: no usable TPM2 here (systemd $(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')): the keys are locked to the operator's Nitrokey; unlock after each reboot with avpn cloud unlock." >&2
  else
    echo "this host cannot seal keys to a TPM2 (systemd $(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')); give the operator's vault (--vault) to lock them to its Nitrokey instead" >&2
    exit 4
  fi
  sudo -n /opt/advanced-vpn/bin/avpnctl request --role "$ROLE" --protect "$PROTECT" $PROBE_ARGS --out /root/request.json >/dev/null
  if [ "$HAVE" = "$ROLE" ]; then echo "keys=renewed"; else echo "keys=new"; fi
fi
sudo -n cat $E/request.json > /tmp/avpn-request.json
sudo -n rm -f /tmp/avpn-unlock.pub
echo "protection=$(sudo -n python3 -c 'import json;print(json.load(open("/etc/advanced-vpn/enrolled/protection.json")).get("mode"))' 2>/dev/null || echo unknown) tpm2=$(systemd-analyze has-tpm2 >/dev/null 2>&1 && echo yes || echo no) creds_key=$(sudo -n python3 -c 'import json;print(json.load(open("/etc/advanced-vpn/enrolled/protection.json")).get("creds_key"))')"
sudo -n rm -rf /tmp/avpn-src /tmp/avpn-src.tgz
""".replace("@@HARDEN@@", retention.HARDEN.rstrip("\n"))

# Security updates in a counted maintenance window: bash -s.
HOST_UPDATE = r"""set -e
# Updates and installs need the network the egress lock closes (tools/server_egress.py):
# open a counted maintenance window first. A running supervisor reopens its egress table
# with root allowed; with none running, the retained lock is removed and the next start
# rebuilds it. Traffic still counts against the monthly cap; a capped server stays shut.
M=/etc/advanced-vpn/metering/enrolled
sudo -n install -d -m 0700 /etc/advanced-vpn/metering $M
echo $(( $(date +%s) + 1800 )) | sudo -n tee $M/maintenance-until >/dev/null
trap 'sudo -n rm -f /etc/advanced-vpn/metering/enrolled/maintenance-until' EXIT
if systemctl is-active -q advanced-vpn.service 2>/dev/null; then sleep 7
else sudo -n nft delete table inet advanced_vpn_egress 2>/dev/null || true; fi
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update -qq
sudo -n apt-get -y -qq -o Dpkg::Options::=--force-confold upgrade >/dev/null
date -u +%Y-%m-%dT%H:%M:%SZ | sudo -n tee $M/last-update >/dev/null
echo "updated $(cat /var/run/reboot-required 2>/dev/null && echo '(reboot required)')"
"""

# Restart an unlocked server's service and report whether it runs.
HOST_RESTART = r"""set -e
sudo -n systemctl reset-failed advanced-vpn.service 2>/dev/null || true
sudo -n systemctl restart advanced-vpn.service
sleep 3
systemctl is-active advanced-vpn.service
"""

# Install a signed bundle on a server and (re)start it: bash -s -- (bundle on stdin is not used).
HOST_ENROLL = r"""set -e
sudo -n systemctl stop advanced-vpn.service 2>/dev/null || true
sudo -n /opt/advanced-vpn/bin/avpnctl enroll /tmp/avpn-bundle.avpn --operator-key /tmp/avpn-operator.pub --replace >/dev/null
rm -f /tmp/avpn-bundle.avpn /tmp/avpn-operator.pub
# A locked server may have hit the unit's start limit while it waited for its unlock.
sudo -n systemctl reset-failed advanced-vpn.service 2>/dev/null || true
sudo -n systemctl restart advanced-vpn.service
sleep 3
systemctl is-active advanced-vpn.service
"""


def eice_admin(record):
    """The Instance Connect Endpoint a server is administered through, or None."""
    admin = record.get("admin")
    return admin if isinstance(admin, dict) and admin.get("via") == "eice" else None


def ssh_base(name, record):
    """ssh/scp options for a recorded host: its key (or SSH config), its own known_hosts.
    A server administered through an EC2 Instance Connect Endpoint is reached through it
    (IAM-authorised, from any address); its host key stays filed under its public address."""
    known = INVENTORY.parent / "ssh" / (name + ".known_hosts")
    known.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    opts = ["-F", record["ssh_config"]] if record.get("ssh_config") else []
    admin = eice_admin(record)
    if admin:
        tunnel = [tool("aws"), "ec2-instance-connect", "open-tunnel", "--instance-id", admin["instance"],
                  "--profile", record["profile"], "--region", record["region"]]  # fmt: skip
        opts += [
            "-o",
            "ProxyCommand=" + " ".join(shlex.quote(x) for x in tunnel),
            "-o",
            "HostKeyAlias=" + record["public_ip"],
        ]
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
    if eice_admin(record):
        return "%s@%s" % (record.get("ssh_user", "admin"), eice_admin(record)["instance"])
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
    """(ssh, scp, base options, target) for one recorded server. A Fly.io Machine has no
    sshd: it is reached through the Machines API's exec call, shaped like ssh and scp
    (tools/fly-ssh, tools/fly-scp)."""
    if record.get("provider") == "fly":
        here = Path(__file__).resolve().parent
        return str(here / "fly-ssh"), str(here / "fly-scp"), ["--app", record["app"]], record["machine"]
    ensure_bastion(name, record)
    return tool("ssh"), tool("scp"), ssh_base(name, record), ssh_target(record)


# OCI bastion sessions last at most 3 hours. A server reached through one (recorded with
# `host bastion`) gets a fresh session whenever the one in its SSH config is gone or has
# less than this left: `cloud unlock` must work whenever the server restarts, not only
# within 3 hours of the last login.
BASTION_MARGIN = 20 * 60
BASTION_TTL = 10800
_bastion_fresh = set()


def ssh_config_user(config, host):
    """The User of `Host host` in an SSH config file, or None."""
    current = None
    for line in Path(config).read_text().splitlines():
        words = line.split()
        if words[:1] == ["Host"]:
            current = words[1:]
        elif current == [host] and words[:1] == ["User"] and len(words) == 2:
            return words[1]
    return None


def set_ssh_config_user(config, host, user):
    """Replace the User of `Host host` in an SSH config file (kept private, written atomically)."""
    lines, current, done = [], None, False
    for line in Path(config).read_text().splitlines(keepends=True):
        words = line.split()
        if words[:1] == ["Host"]:
            current = words[1:]
        elif current == [host] and words[:1] == ["User"] and not done:
            line = line[: len(line) - len(line.lstrip())] + "User " + user + "\n"
            done = True
        lines.append(line)
    if not done:
        raise CloudError("no User line for Host %s in %s" % (host, config))
    tmp = Path(str(config) + ".tmp")
    tmp.write_text("".join(lines))
    tmp.chmod(0o600)
    tmp.replace(config)


def bastion_ssh_config(name, key, private_ip, region):
    """An SSH config reaching `name` at its private address through an OCI bastion. The
    bastion Host's User is a session OCID, written by ensure_bastion (PENDING until then)."""
    d = INVENTORY.parent / "ssh"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    common = (
        "  IdentityFile %s\n  IdentitiesOnly yes\n  IdentityAgent none\n  StrictHostKeyChecking accept-new\n"
        "  ServerAliveInterval 15\n  ServerAliveCountMax 3\n" % key
    )
    text = (
        "Host %s-bastion\n  HostName host.bastion.%s.oci.oraclecloud.com\n  User PENDING\n%s"
        "  UserKnownHostsFile %s\n"
        "Host %s\n  HostName %s\n  User ubuntu\n%s  UserKnownHostsFile %s\n  ProxyJump %s-bastion\n"
        "  ConnectTimeout 30\n"
        % (name, region, common, d / (name + "-bastion.known_hosts"), name, private_ip, common,
           d / (name + ".known_hosts"), name)
    )  # fmt: skip
    path = d / (name + ".conf")
    tmp = path.with_suffix(".conf.tmp")
    tmp.write_text(text)
    tmp.chmod(0o600)
    tmp.replace(path)
    return path


def ensure_bastion(name, record, now=None):
    """Make sure the OCI bastion session `name` is reached through is valid for a while."""
    b = record.get("bastion")
    if not b or name in _bastion_fresh:
        return
    oc = Oci(b.get("oci_profile", "DEFAULT"))
    config = record["ssh_config"]
    session = ssh_config_user(config, b["host"])
    now = time.time() if now is None else now
    fresh = False
    if session and session.startswith("ocid1.bastionsession."):
        try:
            data = oc("bastion", "session", "get", "--session-id", session)["data"]
            created = datetime.datetime.fromisoformat(data["time-created"]).timestamp()
            left = created + int(data["session-ttl-in-seconds"]) - now
            fresh = data.get("lifecycle-state") == "ACTIVE" and left > BASTION_MARGIN
        except (CloudError, KeyError, ValueError):
            fresh = False
    if not fresh:
        stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        made = oc("bastion", "session", "create-managed-ssh", "--bastion-id", b["id"],
                  "--target-resource-id", b["instance"], "--target-os-username", b["user"],
                  "--ssh-public-key-file", b["public_key"], "--session-ttl", str(BASTION_TTL),
                  "--display-name", "%s-%s" % (name, stamp), "--wait-for-state", "SUCCEEDED",
                  "--max-wait-seconds", "600")  # fmt: skip
        resources = (made.get("data") or {}).get("resources") or []
        session = next((r.get("identifier") for r in resources if r.get("identifier")), None)
        if not session:
            raise CloudError("the OCI bastion did not return a session for %s" % name)
        set_ssh_config_user(config, b["host"], session)
        # Connections cached for the old session would outlive it: close them.
        for host in (b["host"], ssh_target(record).rsplit("@", 1)[-1]):
            subprocess.run([tool("ssh"), "-F", str(config), "-O", "exit", host], capture_output=True, timeout=30)
    _bastion_fresh.add(name)


def host_bastion(a):
    """`host bastion`: record that a server is reached through an OCI bastion, so its
    sessions are renewed automatically."""
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    if not record or not record.get("ssh_config"):
        raise CloudError("%s is not a recorded host with an SSH config (host add --ssh-config)" % a.name)
    if ssh_config_user(record["ssh_config"], a.host) is None:
        raise CloudError("no Host %s with a User line in %s" % (a.host, record["ssh_config"]))
    key = Path(a.public_key).expanduser().resolve()
    if not key.is_file():
        raise CloudError("no public key at %s" % key)
    for value, kind in ((a.bastion_id, "bastion"), (a.instance_id, "instance")):
        if not value.startswith("ocid1.%s." % kind):
            raise CloudError("--%s-id must be an OCI %s OCID" % (kind, kind))
    record["bastion"] = dict(id=a.bastion_id, instance=a.instance_id, user=a.user, host=a.host,
                             public_key=str(key), oci_profile=a.oci_profile)  # fmt: skip
    save_inventory(inv)
    _bastion_fresh.discard(a.name)
    ensure_bastion(a.name, record)
    return [dict(label=a.name, value="through OCI bastion %s...; sessions renewed automatically" % a.bastion_id[:32])]


def setup_server(name, record, role, port, out, source, replace=False, source_arm=None, unlock_pub=None):
    """Install or upgrade the package on a recorded server and fetch its public request
    for `role`, with the tunnel `port` accepted by the host firewall. Returns
    (kept|new, TPM report)."""
    image = record.get("provider") == "fly"  # the package is in the image already
    if image:
        ssh, scp, base, host = remote(name, record)
    else:
        ssh, scp, base, host = tool("ssh"), tool("scp"), ssh_base(name, record), ssh_target(record)

    def reachable():
        try:
            # A new server's bastion plugin takes minutes to start: retry the session too.
            if not image:
                ensure_bastion(name, record)
            call([ssh, *base, host, "true"], parse=False)
            return True
        except CloudError:
            return False

    wait("SSH on " + name, reachable, timeout=900 if record.get("bastion") else 300, every=10)
    # The binaries must match the server's processor: an ARM server (Ampere A1) gets the
    # ARM build, built on (or for) that architecture.
    machine = call([ssh, *base, host, "uname -m"], parse=False).strip()
    if machine == "aarch64":
        if not source_arm:
            raise CloudError("%s is an ARM (aarch64) server: give an ARM build with --source-arm" % name)
        source = source_arm
    try:
        need = glibc_needed(source)
    except FileNotFoundError as e:
        raise CloudError("%s is missing: build first (cargo build --release)" % e.filename) from None
    check_glibc(name, call([ssh, *base, host, "getconf GNU_LIBC_VERSION"], parse=False), need)
    if not image:
        with tempfile.TemporaryDirectory() as d:
            tgz = source_tarball(Path(source).resolve(), Path(d) / "avpn-src.tgz")
            call([scp, "-q", *base, str(tgz), host + ":/tmp/avpn-src.tgz"], parse=False)
    args = [role, str(port), "yes" if replace else "no"]
    args.append("yes" if record.get("shared") else "no")
    # The operator's unlock key: a host without a usable TPM2 locks its keys to it.
    if unlock_pub is not None:
        call([scp, "-q", *base, str(unlock_pub), host + ":/tmp/avpn-unlock.pub"], parse=False)
    args.append("yes" if unlock_pub is not None else "no")
    report = call([ssh, *base, host, "bash", "-s", "--", *args], parse=False, stdin=HOST_SETUP)
    out.parent.mkdir(parents=True, exist_ok=True)
    call([scp, "-q", *base, host + ":/tmp/avpn-request.json", str(out)], parse=False)
    if json.loads(out.read_text()).get("role") != role:
        raise CloudError("the request from %s is not for role %s" % (name, role))
    lines = report.strip().splitlines()
    keys = next((x.split("=", 1)[1] for x in lines if x.startswith("keys=")), "new")
    # Bug 9a: the host's key-protection mode travels with the report, so it can be
    # recorded and shown loudly wherever plain keys had to be accepted.
    protection = next((x.split("=", 1)[1].split()[0] for x in lines if x.startswith("protection=")), "unknown")
    return keys, protection, (lines[-1] if lines else "")


def host_update(a):
    """`host update NAME`: apply security updates in a counted maintenance window (a
    server's egress lock admits nothing else, and its update timers are off)."""
    inv = load_inventory()
    rec = inv["resources"].get(a.name)
    if not rec:
        raise CloudError("%s is not recorded" % a.name)
    ssh, _scp, base, host = remote(a.name, rec)
    out = call([ssh, *base, host, "bash", "-s"], parse=False, stdin=HOST_UPDATE).strip().splitlines()
    return [dict(label=a.name, value=out[-1] if out else "no answer")]


def host_setup(a):
    """`host setup`: install on a recorded server and fetch its public request."""
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    reachable = record and (record.get("ssh_key") or record.get("ssh_config") or record.get("provider") == "fly")
    if not record or not record.get("public_ip") or not reachable:
        raise CloudError("%s is not a recorded host with an address and SSH access" % a.name)
    role = a.role or record.get("role")
    if role not in ROLES:
        raise CloudError("give --role relay|middle|exit for %s" % a.name)
    port = record["port"] if record.get("role") == role and record.get("port") else ROLES[role]
    unlock_pub = ensure_unlock_key(a.vault) if getattr(a, "vault", None) else None
    keys, protection, tpm = setup_server(a.name, record, role, port, a.out, a.source, replace=a.replace,
                                        source_arm=getattr(a, "source_arm", None), unlock_pub=unlock_pub)  # fmt: skip
    record.update(role=role, port=port, request=str(a.out), key_protection=protection)
    save_inventory(inv)
    return [
        dict(label="host", value="%s %s (%s)" % (a.name, record["public_ip"], role)),
        dict(label="installed", value="/opt/advanced-vpn (service not enabled)"),
        dict(
            label="keys",
            value="%s; %s; %s"
            % (
                {"kept": "kept", "renewed": "renewed (older than this release)"}.get(keys, "generated"),
                "PLAINTEXT KEYS (this host cannot seal with systemd-creds)"
                if protection == "none"
                else "sealed: " + protection,
                tpm,
            ),
        ),
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
        raise CloudError("--provider must be one of " + ", ".join(sorted(providers.ALL_KEYS)))
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
        if r.get("public_ip") and (r.get("ssh_key") or r.get("ssh_config") or r.get("provider") == "fly"):
            out[name] = r.get("catalog", r["provider"])
    return out


FIRST_HOP_PORT = ROLES["relay"]  # the HTTP/3 cloak in front of WireGuard, whatever the first hop's role


def transports(port):
    """What a hop's firewall admits on its port: the first hop takes the camouflage's
    QUIC on UDP and its TLS fallback on TCP; every later hop takes UDP only."""
    return "udp+tcp" if port == FIRST_HOP_PORT else "udp"


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
    exit_ip = inv[names[-1]]["public_ip"] + ("/128" if ":" in inv[names[-1]]["public_ip"] else "/32")
    hops = []
    for k, (name, role) in enumerate(zip(names, roles, strict=True)):
        port = FIRST_HOP_PORT if k == 0 else ROLES[role]
        prev = inv[names[k - 1]]["public_ip"] if k else ""
        sources = [ANY] if k == 0 else [prev + ("/128" if ":" in prev else "/32")]
        # Connected through the chain, your SSH reaches every other hop from the exit's
        # address, and the exit itself at its tunnel address (EXIT_TUNNEL_IP), which
        # needs no firewall rule at all; so no rule names you.
        ssh = [] if name == names[-1] else [exit_ip]
        nxt = None
        if k + 1 < len(names):
            later = names[k + 1]
            nxt = hostport(inv[later]["public_ip"], ROLES[roles[k + 1]])
        hops.append(dict(name=name, role=role, port=port, sources=sources, ssh=ssh, record=inv[name], next=nxt))
    return hops


def sg_diff(perms, wanted, unmanaged=()):
    """Authorize/revoke lists that make a group's managed rules exactly `wanted`.

    Managed rules are every single-port UDP permission, TCP 22, and TCP on the
    camouflage port (its TLS fallback); `wanted` maps (protocol, port) to the set of
    IPv4 CIDRs it should admit.
    """
    have = {}
    extra = {}
    for q in perms:
        key = (q.get("IpProtocol"), q.get("FromPort"))
        managed = (key[0] == "udp" and q.get("FromPort") == q.get("ToPort")) or (
            key[0] == "tcp" and q.get("FromPort") == q.get("ToPort") in (22, FIRST_HOP_PORT)
        )
        managed = managed and key not in unmanaged
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


def egress6_diff(perms, wanted):
    """(authorize, revoke) permission lists that leave a group's IPv6 egress exactly
    `wanted`, a set of (protocol, port or None, CIDR). AWS revokes single ranges out of a
    rule, so an IPv6 range riding on an IPv4 rule (the `::/0` AWS adds when a VPC gets
    IPv6) is revoked alone and the IPv4 range stays."""
    have = set()
    for q in perms:
        for r in q.get("Ipv6Ranges", []):
            have.add((q.get("IpProtocol"), q.get("FromPort"), r["CidrIpv6"]))

    def perm(proto, port, cidr, describe):
        out = dict(IpProtocol=proto, Ipv6Ranges=[dict(CidrIpv6=cidr)])
        if port is not None:
            out.update(FromPort=port, ToPort=port)
        if describe:
            out["Ipv6Ranges"][0]["Description"] = "avpn: the next hop (paced TCP link)"
        return out

    add = [perm(*w, True) for w in sorted(wanted - have, key=str)]
    remove = [perm(*h, False) for h in sorted(have - wanted, key=str)]
    return add, remove


def set_firewall(name, record, port, sources, ssh, next_hop=None):
    """Make a managed server's firewall admit exactly the tunnel `sources` on `port`
    and SSH from `ssh`, and (AWS) let it send over IPv6 only to an IPv6 `next_hop`
    ("[addr]:port"), and nowhere at all over IPv6 otherwise. Returns a description, or
    None for a firewall this tool does not manage."""
    if record["provider"] == "aws":
        aws = Aws(record["profile"], record["region"])
        groups = aws.owned(name)["security_groups"]
        if len(groups) != 1:
            raise CloudError("expected one security group tagged %s=%s" % (NAME, name))
        # Outbound IPv6: exactly the next hop, when it is reached over IPv6 (a Fly.io exit),
        # which needs this server to have an IPv6 address of its own.
        wanted6 = set()
        if next_hop and next_hop.startswith("["):
            addr, link_port = next_hop[1:].split("]:", 1)
            if record.get("instance"):
                found = aws.ec2("describe-instances", "--instance-ids", record["instance"])
                six = [a for r in found.get("Reservations", []) for i in r["Instances"]
                       for n in i.get("NetworkInterfaces", []) for a in n.get("Ipv6Addresses", [])]  # fmt: skip
                if not six:
                    raise CloudError("%s has no IPv6 address, and its next hop is reachable only over IPv6: give it "
                                     "one first (docs/FLY_EXIT.md)" % name)  # fmt: skip
            wanted6 = {("tcp", int(link_port), addr + "/128")}
        add6, remove6 = egress6_diff(groups[0].get("IpPermissionsEgress", []), wanted6)
        if add6:
            aws.ec2("authorize-security-group-egress", "--group-id", groups[0]["GroupId"], "--ip-permissions",
                    json.dumps(add6))  # fmt: skip
        if remove6:
            aws.ec2("revoke-security-group-egress", "--group-id", groups[0]["GroupId"], "--ip-permissions",
                    json.dumps(remove6))  # fmt: skip
        wanted = {("udp", port): set(sources), ("tcp", 22): set(ssh)}
        # The first hop also takes the camouflage's TLS/TCP fallback on the same port.
        wanted[("tcp", FIRST_HOP_PORT)] = set(sources) if port == FIRST_HOP_PORT else set()
        # Administered through its Instance Connect Endpoint: SSH admits only that
        # endpoint's group, never an address, and is not this function's to change.
        unmanaged = {("tcp", 22)} if eice_admin(record) else set()
        for key in unmanaged:
            wanted.pop(key)
        add, remove = sg_diff(groups[0].get("IpPermissions", []), wanted, unmanaged)
        gid = groups[0]["GroupId"]
        if add:
            aws.ec2("authorize-security-group-ingress", "--group-id", gid, "--ip-permissions", json.dumps(add))
        if remove:
            aws.ec2("revoke-security-group-ingress", "--group-id", gid, "--ip-permissions", json.dumps(remove))
        return "%s: %s %d from %s; SSH from %s" % (
            gid,
            transports(port),
            port,
            ", ".join(sources),
            "its Instance Connect Endpoint only" if unmanaged else (", ".join(ssh) or "nobody"),
        )
    if record["provider"] == "oci" and record.get("managed_list"):
        oc = Oci(record.get("profile", "DEFAULT"), record.get("compartment"))
        oc("network", "security-list", "update", "--security-list-id", record["security_list"],
           "--ingress-security-rules", json.dumps(oci_ingress(port, sources, ssh, tcp=port == FIRST_HOP_PORT)), "--force")  # fmt: skip
        return "security list: %s %d from %s; SSH from %s" % (
            transports(port),
            port,
            ", ".join(sources),
            ", ".join(ssh) or "nobody",
        )
    return None


def controller():
    """The controller used to sign the chain (`AVPN_CTL` overrides it in tests).

    `avpn-cloud` runs under the bare system Python, whose cryptography may lack
    ML-DSA; signing needs the hash-locked environment. An installed copy (user or
    system) has its `bin/avpnctl` launcher beside `tools/`, which runs in that
    environment: use it. A source checkout has no `bin/`, so the interpreter
    running this file (its venv) signs."""
    override = os.environ.get("AVPN_CTL")
    if override:
        return [override]
    launcher = Path(__file__).resolve().parents[1] / "bin" / "avpnctl"
    if launcher.is_file() and os.access(launcher, os.X_OK):
        return [str(launcher)]
    return [sys.executable, str(Path(__file__).with_name("avpnctl.py"))]


def rate_row(cap, hours_per_day, accept_cost, links):
    """The chain plan's rate row: the class `avpn init --rate auto` will sign, or why none fits."""
    from rates import choose_rate  # standard library only: cloud runs under the system Python

    try:
        rate, why = choose_rate("auto", cap, hours_per_day, accept_cost, links=links)
        return dict(label="rate", value="%s (%s)" % (rate, why))
    except ValueError as e:
        return dict(label="rate", value=str(e))


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
        if r["provider"] == "fly":
            how = "Fly.io's proxy delivers only this port"
        rows.append(
            dict(
                label="hop %d" % k,
                value="%s %s %s (%s)" % (h["role"], h["name"], r["public_ip"], r.get("catalog", r["provider"])),
            )
        )
        rows.append(
            dict(
                label="",
                value="%s %d from %s; firewall %s"
                % (
                    "tcp" if k > 1 and ":" in r["public_ip"] else transports(h["port"]),
                    h["port"],
                    ", ".join(h["sources"]),
                    how,
                ),  # fmt: skip
            )
        )
        if r.get("role") and r["role"] != h["role"]:
            rows.append(dict(label="", value="new keys: it was a %s" % r["role"]))
    extra = sorted(set(servers()) - set(names))
    if extra:
        rows.append(dict(label="unused", value=", ".join(extra) + " (a chain has at most 3 hops)"))
    caps = plan_caps(load_inventory(), [h["name"] for h in hops])
    for h in hops:
        c, why = caps[h["name"]]
        rows.append(dict(label="cap" if h is hops[0] else "", value="%s: %s" % (h["name"], why)))
    cap = per_link_allowance_gib(hops, caps)
    # Legal spheres of the two ends: one order should never reach both.
    keys = [r["record"].get("catalog", r["record"]["provider"]) for r in hops]
    ends = [providers.sphere(keys[0]), providers.sphere(keys[-1])] if len(hops) > 1 else []
    if ends:
        named = ["%s (%s)" % (k, s or "your host's country") for k, s in zip([keys[0], keys[-1]], ends, strict=True)]
        same = ends[0] is not None and ends[0] == ends[1]
        rows.append(
            dict(
                label="jurisdiction",
                value="entry %s, exit %s%s"
                % (
                    named[0],
                    named[1],
                    "; WARNING: both ends answer to %s law, so one legal order reaches both. Put one end on a "
                    "non-%s host (avpn cloud suggest lists some)" % (ends[0], ends[0])
                    if same
                    else "",
                ),
            )
        )
    # Providers: each one sees its own servers' traffic (flow logs, hypervisor counters).
    # One that hosts both ends sees your address and your destinations: refused unless
    # explicitly allowed. One that hosts two other hops shortens the path against it.
    if len(hops) > 1:
        if keys[0] == keys[-1] and keys[0] != "own" and not getattr(a, "allow_same_provider", False):
            raise CloudError(
                "the entry and the exit are both on %s, which would then see your address and your destinations; "
                "add a server with another provider, or pass --allow-same-provider" % keys[0]
            )
        for k in sorted(set(keys)):
            n = keys.count(k)
            if n > 1:
                rows.append(
                    dict(
                        label="provider",
                        value="%s hosts %d of %d hops: against %s the path is %d hop%s shorter"
                        % (k if k != "own" else "an unnamed host (own)", n, len(keys), k, n - 1, "" if n == 2 else "s"),
                    )
                )
    if cap:
        rows.append(rate_row(cap, a.hours_per_day, a.accept_cost, 2 if len(hops) > 1 else 1))
    rows.append(dict(label="sign", value="one Nitrokey PIN + touch (vault %s)" % a.vault))
    endpoint = [h["name"] for h in hops if eice_admin(h["record"])]
    if endpoint:
        value = "%s: through its Instance Connect Endpoint, from any network; " % ", ".join(endpoint)
        value += "the others only while connected (they admit the exit's address; the exit answers at %s)" % (
            EXIT_TUNNEL_IP
        )
    else:
        value = "afterwards only while connected: other hops admit the exit's address, the exit answers at %s" % (
            EXIT_TUNNEL_IP
        )
    rows.append(dict(label="ssh", value=value))
    for provider in sorted({h["record"]["provider"] for h in hops} & set(CALLER_LOG)):
        rows.append(caller_note(provider))
    return dict(rows=rows, hops=hops)


# Structured progress for the front end's checklist: one line per event on stderr,
# behind a record-separator byte so ordinary stderr text still passes through. Readers
# split on "\n" only (Python's str.splitlines() also breaks at \x1e).
PROGRESS_MARK = "\x1eAVPN "


class Progress:
    """The steps of a long operation, reported as they run. With AVPN_PROGRESS=events
    (the `avpn` front end) each change is a structured event that it draws as a
    checklist; on a terminal, or with AVPN_PROGRESS=1, a plain line per step with the
    seconds since the start; otherwise nothing (scripts, tests). stdout keeps its
    single JSON object either way."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.start = time.monotonic()
        self.current = None
        mode = os.environ.get("AVPN_PROGRESS")
        self.mode = "events" if mode == "events" else "lines" if mode == "1" or sys.stderr.isatty() else None
        self.send(plan=self.steps)

    def send(self, **event):
        """One structured event, when the front end asked for them."""
        if self.mode == "events":
            print(PROGRESS_MARK + json.dumps(event), file=sys.stderr, flush=True)

    def run(self, i, note=None):
        """Step `i` has started (it finishes when the next one starts, or at `finish`)."""
        if self.current is not None and self.current != i:
            self.send(step=self.current, state="done")
        self.current = i
        self.send(step=i, state="run")
        if self.mode == "lines":
            text = self.steps[i] + (" (%s)" % note if note else "")
            print("  [%4ds] %s" % (time.monotonic() - self.start, text), file=sys.stderr, flush=True)

    def wait(self, i, note):
        """Step `i` waits for the person: a PIN, a touch."""
        self.run(i, note)
        self.send(step=i, state="wait", note=note)

    def finish(self):
        """The last step has completed."""
        if self.current is not None:
            self.send(step=self.current, state="done")
            self.current = None

    def fail(self, message):
        """The running step failed with `message`."""
        if self.current is not None:
            self.send(step=self.current, state="fail", note=message)
            self.current = None


def chain_apply(a, plan):
    """Build the chain: firewalls, packages and requests, one signature, enrollment."""
    hops = plan["hops"]
    n = len(hops)
    progress = Progress(
        ["Open the firewalls"]
        + ["Check the operator's unlock key"]
        + ["Install %s as the %s" % (h["name"], h["role"]) for h in hops]
        + ["Sign the chain"]
        + ["Start %s" % h["name"] for h in reversed(hops)]
        + ["Close SSH from here"]
    )
    try:
        rows = chain_steps(a, hops, progress, n)
    except BaseException as e:
        progress.fail(str(e) or type(e).__name__)
        raise
    progress.finish()
    return rows


def ssh_by_address(rec):
    """Whether this tool opens SSH to a server by the caller's address (an AWS server
    without an Instance Connect Endpoint, or an OCI server on a managed security list).
    Instance Connect (IAM), OCI bastions and Fly.io's API do not depend on it."""
    if rec.get("provider") == "aws":
        return not eice_admin(rec)
    return rec.get("provider") == "oci" and bool(rec.get("managed_list"))


def setup_ssh_source(hops):
    """This machine's public address for the setup SSH rules, looked up only when a hop is
    reached by address: a chain of Instance Connect, bastion and Fly.io hops builds the
    same from any address, and a VPN changing it mid-build does not matter."""
    return single_ip("auto") if any(ssh_by_address(h["record"]) for h in hops) else None


def chain_steps(a, hops, progress, n):
    """The work of chain_apply, step by step (see its Progress list)."""
    # Every server's monthly cap, decided before anything changes: a hop whose account has
    # no free allowance on record stops the build here (no fees from a free account).
    caps = require_caps(load_inventory(), [h["name"] for h in hops])
    me = setup_ssh_source(hops)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    work = INVENTORY.parent / "chains" / stamp
    work.mkdir(mode=0o700, parents=True)
    done = []
    # 1. Open each managed firewall in its final form, plus SSH from here for setup.
    progress.run(0)
    for h in hops:
        set_firewall(h["name"], h["record"], h["port"], h["sources"], sorted(set(h["ssh"]) | ({me} if me else set())),
                     h.get("next"))  # fmt: skip
    # 1b. The operator's unlock key, made once (PIN + touch the first time only): a server
    # without a usable TPM2 locks its keys to it (docs/HARDWARE_BOUND_SESSIONS.md).
    unlock_pub = ensure_unlock_key(a.vault, progress, 1)
    # 2. Install or upgrade each server and collect its request for its role.
    requests = {}
    for k, h in enumerate(hops):
        out = work / "requests" / (h["role"] + ".req")
        progress.run(2 + k, "packages and keys; a few minutes")
        keys, protection, tpm = setup_server(h["name"], h["record"], h["role"], h["port"], out, a.source,
                                             replace=True, source_arm=getattr(a, "source_arm", None),
                                             unlock_pub=unlock_pub)  # fmt: skip
        h["record"]["key_protection"] = protection
        h["record"]["request"] = str(out)
        requests[h["role"]] = out
        done.append(
            dict(
                label=h["name"],
                value="%s, keys %s, %s"
                % (
                    h["role"],
                    keys,
                    "PLAINTEXT KEYS; " + tpm
                    if protection == "none"
                    else "keys locked to the operator's Nitrokey (unlock after each reboot: avpn cloud unlock %s)"
                    % h["name"]
                    if protection == "operator"
                    else tpm,
                ),
            )
        )
    # 3. One signature over the whole chain.
    endpoint = {h["role"]: hostport(h["record"]["public_ip"], h["port"]) for h in hops}
    argv = [*controller(), "--json", "init", "--out", str(work / "bundles"), "--hops", str(len(hops))]
    argv += ["--exit", endpoint["exit"], "--vault", str(a.vault)]
    # The rate class: auto picks the fastest the smallest hop's monthly cap fits (the cap
    # each server enforces: its account's free allowance, shared, less a margin).
    allowance = per_link_allowance_gib(hops, caps)
    if allowance:
        argv += ["--allowance-gib", str(allowance)]
    argv += ["--hours-per-day", "%g" % a.hours_per_day] + (["--accept-cost"] if a.accept_cost else [])
    # A later hop reachable only over IPv6 TCP (a Fly.io exit: no UDP there without a paid
    # IPv4) needs the paced links between servers over TCP.
    if any(":" in h["record"]["public_ip"] for h in hops[1:]):
        argv += ["--link-transport", "tcp"]
    if hops[0]["record"].get("public_dns"):
        argv += ["--cover-name", hops[0]["record"]["public_dns"]]
    for role in ("relay", "middle"):
        if role in endpoint:
            argv += ["--" + role, endpoint[role]]
    argv += ["--request", "client=%s" % Path(a.client_request).resolve()]
    argv += [x for role, f in requests.items() for x in ("--request", "%s=%s" % (role, f))]
    # The same PIN and touch also unwraps the data keys of servers locked to the
    # operator: printed to this pipe only, held in this process's memory only.
    argv += ["--emit-unlock"]
    progress.wait(n + 2, "enter the Nitrokey PIN, then touch the key")
    signed = json.loads(call(argv, parse=False).strip().splitlines()[-1])
    data_keys = signed.get("unlock") or {}
    bundles = work / "bundles"
    # 4. Enroll and start, exit first, so each hop's next hop is already up.
    for k, h in enumerate(reversed(hops)):
        progress.run(n + 3 + k)
        ssh, scp, base, host = remote(h["name"], h["record"])
        if h["role"] in data_keys:
            send_data_key(h["name"], h["record"], data_keys[h["role"]])
        call([scp, "-q", *base, str(bundles / (h["role"] + ".avpn")), host + ":/tmp/avpn-bundle.avpn"], parse=False)
        call([scp, "-q", *base, str(bundles / "operator.pub"), host + ":/tmp/avpn-operator.pub"], parse=False)
        push_cap(h["name"], h["record"], *caps[h["name"]])
        state = call([ssh, *base, host, "bash", "-s"], parse=False, stdin=HOST_ENROLL).strip().splitlines()
        if not state or state[-1] != "active":
            raise CloudError("%s did not start after enrolling" % h["name"])
    # 5. SSH only through the chain from now on.
    progress.run(2 * n + 3, "from now on: while connected")
    for h in hops:
        set_firewall(h["name"], h["record"], h["port"], h["sources"], h["ssh"], h.get("next"))
    inv = load_inventory()
    for h in hops:
        inv["resources"][h["name"]].update(role=h["role"], port=h["port"], first_hop=h is hops[0])
    for h in hops:
        inv["resources"][h["name"]].update(request=h["record"]["request"], key_protection=h["record"]["key_protection"])
    inv["chain"] = dict(
        hops=[h["name"] for h in hops], created=stamp, bundles=str(bundles), vault=str(Path(a.vault).resolve())
    )
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


def ensure_unlock_key(vault, progress=None, step=None):
    """The operator's unlock public key file, made on first use (PIN + touch once)."""
    pub = Path(vault).resolve() / "operator-unlock.pub"
    if not pub.exists():
        if progress is not None:
            progress.wait(step, "first time only: enter the Nitrokey PIN, then touch the key")
        call([*controller(), "--json", "unlock-key", "--vault", str(vault)], parse=False)
    elif progress is not None:
        progress.run(step, "present")
    if not pub.exists():
        raise CloudError("the operator's unlock key was not created in %s" % vault)
    return pub


def send_data_key(name, record, data_key_hex):
    """Hand a server its data key over SSH (stdin, never argv or a file); it holds it in RAM."""
    ssh, scp, base, host = remote(name, record)
    out = call([ssh, *base, host, "sudo -n /opt/advanced-vpn/bin/avpnctl --json server-unlock"], parse=False,
               stdin=data_key_hex + "\n")  # fmt: skip
    if not json.loads(out.strip().splitlines()[-1]).get("ok"):
        raise CloudError("%s did not accept its data key" % name)


def unlock(a):
    """`unlock NAME`: after a server without a TPM restarts, unwrap its data key with the
    operator's Nitrokey (PIN + touch) and start it again. The unwrap is bound to your own
    copy of that server's request, not to anything the server sends back."""
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    if not record:
        raise CloudError("%s is not recorded" % a.name)
    if record.get("key_protection") != "operator":
        raise CloudError("%s does not lock its keys to the operator (%s)" % (a.name, record.get("key_protection")))
    request = Path(record.get("request") or "")
    if not request.is_file():
        raise CloudError("your copy of %s's request is missing (%s); rebuild the chain" % (a.name, request))
    vault = a.vault or (inv.get("chain") or {}).get("vault")
    if not vault:
        raise CloudError("give --vault (the operator's Nitrokey vault)")
    ssh, scp, base, host = remote(a.name, record)
    current = call([ssh, *base, host, "sudo -n cat /etc/advanced-vpn/enrolled/protection.json"], parse=False)
    with tempfile.TemporaryDirectory() as d:
        wrapped = Path(d) / "protection.json"
        wrapped.write_text(current)
        print("Unlock %s: enter the Nitrokey PIN, then touch the key." % a.name, file=sys.stderr, flush=True)
        out = call([*controller(), "--json", "unwrap", "--vault", str(vault), "--request", "%s=%s" % (a.name, request),
                    "--wrapped", "%s=%s" % (a.name, wrapped)], parse=False)  # fmt: skip
    data_key = json.loads(out.strip().splitlines()[-1])["unlock"][a.name]
    send_data_key(a.name, record, data_key)
    state = call([ssh, *base, host, "bash", "-s"], parse=False, stdin=HOST_RESTART).strip().splitlines()
    if not state or state[-1] != "active":
        raise CloudError("%s accepted its data key but its service did not start" % a.name)
    return [dict(label=a.name, value="unlocked until its next reboot; the VPN service is active")]


# What `health` asks a running server over SSH (no secrets: states and counts only).
HOST_HEALTH = r"""A=$(systemctl is-active advanced-vpn.service 2>/dev/null || true)
M=$(sudo -n python3 -c 'import json;print(json.load(open("/etc/advanced-vpn/enrolled/protection.json"))["mode"])' 2>/dev/null || echo unknown)
K=$(sudo -n sh -c 'ls /run/advanced-vpn-unlock 2>/dev/null | wc -l')
echo "active=$A mode=$M unlocked=$K"
echo "updates=$(sudo -n stat -c %Y /etc/advanced-vpn/metering/enrolled/last-update 2>/dev/null || echo 0) image=$([ -f /opt/advanced-vpn/IMAGE ] && echo yes || echo no) shared=$([ -f /etc/advanced-vpn/shared-host ] && echo yes || echo no)"
echo "status=$(sudo -n /opt/advanced-vpn/bin/avpnctl --state /etc/advanced-vpn/enrolled status 2>/dev/null | tail -1)"
echo "metering=$(sudo -n python3 -c '
import json, pathlib
b = pathlib.Path("/etc/advanced-vpn/metering/enrolled")
def load(n):
    try:
        return json.loads((b / n).read_text())
    except Exception:
        return None
u, c = load("usage.json"), load("cap.json")
print(json.dumps(dict(usage=u and dict(month=u["month"], bytes=u["bytes"]), cap=c and dict(cap_bytes=c.get("cap_bytes"), unlimited=c.get("unlimited"))), separators=(",", ":")))' 2>/dev/null)"
"""
CREDIT_FLOOR = 20  # USD: warn below this
EXPIRY_WARN_DAYS = 30


def notify_user(title, body):
    """A desktop notification for the person running this command (nothing without a desktop)."""
    exe = shutil.which("notify-send")
    if not exe or not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        return False
    r = subprocess.run([exe, "--app-name=ADVANCED VPN", "--urgency=critical", title, body],
                       capture_output=True, timeout=10, check=False)  # fmt: skip
    return r.returncode == 0


def server_health(name, rec, now=None):
    """(state, problem or None, fix or None) for one recorded server."""
    instance = rec.get("instance") or (rec.get("bastion") or {}).get("instance")
    if rec.get("provider") == "aws" and instance:
        found = Aws(rec["profile"], rec.get("region")).ec2("describe-instances", "--instance-ids", instance)
        states = [i["State"]["Name"] for r in found.get("Reservations", []) for i in r["Instances"]]
        state = states[0] if states else "gone"
    elif instance and instance.startswith("ocid1.instance."):
        profile = rec.get("profile") or (rec.get("bastion") or {}).get("oci_profile") or "DEFAULT"
        state = Oci(profile)("compute", "instance", "get", "--instance-id", instance)["data"]["lifecycle-state"].lower()
    else:
        state = "unknown"
    if state in ("stopped", "stopping"):
        start = (
            "aws ec2 start-instances --instance-ids %s --profile %s" % (instance, rec.get("profile"))
            if rec.get("provider") == "aws"
            else "oci compute instance action --action START --instance-id %s" % instance
        )
        then = ", then: avpn cloud unlock %s" % name if rec.get("key_protection") == "operator" else ""
        return state, "stopped by its provider (free tiers stop idle servers)", start + then
    if state in ("terminated", "terminating", "shutting-down", "gone"):
        return state, "no longer exists", "create a new server and run avpn cloud chain --apply"
    try:
        ssh, scp, base, host = remote(name, rec)
        lines = call([ssh, *base, host, "bash", "-s"], parse=False, stdin=HOST_HEALTH).strip().splitlines()
        line = next(x for x in lines if x.startswith("active="))
    except (CloudError, StopIteration) as e:
        return state, "not reachable over SSH (%s)" % str(e)[-80:], "check its firewall and admin path"
    seen = dict(x.split("=", 1) for x in line.split() if "=" in x)
    monthly_row(name, lines)
    updates_row(name, rec, lines)
    if seen.get("active") == "active" and LAST_MONTHLY.get(name, {}).get("capped"):
        return "running, CAPPED for the month", "reached its monthly cap: stopped so its account is never billed", (
            "wait for %s, or raise its cap (avpn cloud cap %s --gb N --apply)" % (
                LAST_MONTHLY[name].get("resumes", "the 1st")[:10], name))  # fmt: skip
    if seen.get("active") == "active":
        return "running, VPN service active", None, None
    if seen.get("mode") == "operator" and seen.get("unlocked") == "0":
        return "running, keys LOCKED since a reboot", "locked: it cannot open its keys", "avpn cloud unlock " + name
    return (
        "running, VPN service %s" % (seen.get("active") or "unknown"),
        "the VPN service is not running",
        ("avpn cloud chain --apply (or check the server)"),
    )


LAST_MONTHLY = {}  # name -> the monthly row health last read from each server
CAP_WARN = 0.8  # warn at 80% of a cap, or when this month's pace reaches it


def monthly_row(name, lines, now=None):
    """Read a server's month (from its running status, else its metering files) into LAST_MONTHLY."""
    now = now or time.time()
    LAST_MONTHLY.pop(name, None)
    got = {}
    for x in lines:
        key, _, value = x.partition("=")
        if key in ("status", "metering") and value.startswith("{"):
            try:
                got[key] = json.loads(value)
            except ValueError:
                pass
    live = (got.get("status") or {}).get("monthly")
    if live:
        LAST_MONTHLY[name] = dict(live, capped=live.get("capped") or got["status"].get("state") == "capped")
        return LAST_MONTHLY[name]
    files = got.get("metering") or {}
    usage, cap = files.get("usage") or {}, files.get("cap")
    used = usage.get("bytes", 0) if usage.get("month") == fee_guard.month_of(now) else 0
    if cap is None:
        LAST_MONTHLY[name] = dict(month=fee_guard.month_of(now), used_bytes=used, cap_bytes=None, capped=False,
                                  missing_cap=True)  # fmt: skip
    else:
        LAST_MONTHLY[name] = fee_guard.verdict(used, None if cap.get("unlimited") else cap.get("cap_bytes"), now)
    return LAST_MONTHLY[name]


LAST_UPDATES = {}  # name -> (row text, problem or None)
UPDATES_OVERDUE_DAYS = 3  # the supervisor updates daily: three missed days is a problem
IMAGE_OVERDUE_DAYS = 14  # an image host is patched by rebuilding its image


def updates_row(name, rec, lines, now=None):
    """Whether a server's security updates are current (LAST_UPDATES)."""
    now = now or time.time()
    LAST_UPDATES.pop(name, None)
    line = next((x for x in lines if x.startswith("updates=")), None)
    if line is None:
        return
    seen = dict(x.split("=", 1) for x in line.split() if "=" in x)
    if seen.get("shared") == "yes":
        LAST_UPDATES[name] = ("security updates: the shared host's own business", None)
        return
    if seen.get("image") == "yes":
        tag = (rec.get("image") or "").rsplit(":", 1)[-1]
        try:
            built = datetime.datetime.strptime(tag, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            built = 0
        days = (now - built) / 86400
        text = "image built %s" % (tag if built else "at an unknown time")
        LAST_UPDATES[name] = (text, None if days <= IMAGE_OVERDUE_DAYS else (
            "%s: its image is %d days old; rebuild it for security updates" % (name, days)))  # fmt: skip
        return
    try:
        last = float(seen.get("updates") or 0)
    except ValueError:
        last = 0
    days = (now - last) / 86400
    text = "security updates %s" % ("never applied" if not last else "%.1f days ago" % days)
    LAST_UPDATES[name] = (text, None if last and days <= UPDATES_OVERDUE_DAYS else (
        "%s: security updates overdue (%s; capped servers wait for the month to turn): "
        "avpn cloud host update --name %s" % (name, text, name)))  # fmt: skip


def usage_rows(names):
    """Rows and problems for every server's month: used against its cap, and the pace."""
    rows, problems = [], []
    for name in names:
        m = LAST_MONTHLY.get(name)
        if not m:
            continue
        if m.get("missing_cap"):
            rows.append(
                dict(
                    label=name + " usage",
                    value="%.1f GB sent this month, NO CAP SET" % (m["used_bytes"] / fee_guard.GB),
                )
            )
            problems.append("%s has no monthly cap: its account could be billed (avpn cloud cap --apply)" % name)
            continue
        rows.append(dict(label=name + " usage", value=fee_guard.describe(m)))
        if name in LAST_UPDATES:
            text, problem = LAST_UPDATES[name]
            rows.append(dict(label="", value=text))
            if problem:
                problems.append(problem)
        cap = m.get("cap_bytes")
        if cap and not m.get("capped") and (m["used_bytes"] >= CAP_WARN * cap or m.get("runs_out")):
            problems.append("%s: %s" % (name, fee_guard.describe(m)))
    return rows, problems


def account_health(inv, now=None):
    """Rows and problems for the accounts the servers run in: credits, expiry, free-tier reclaims."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rows, problems = [], []
    aws_profiles = sorted({r["profile"] for r in inv["resources"].values() if r.get("provider") == "aws"})
    for profile in aws_profiles:
        try:
            plan = Aws(profile)("freetier", "get-account-plan-state")
        except CloudError as e:
            rows.append(dict(label="aws " + profile, value="plan unknown (%s)" % str(e)[-80:]))
            continue
        credits = (plan.get("accountPlanRemainingCredits") or {}).get("amount")
        expires = plan.get("accountPlanExpirationDate")
        value = "%s plan, %s" % (plan.get("accountPlanType"), plan.get("accountPlanStatus"))
        if credits is not None:
            value += ", %s USD credits left" % credits
        if expires:
            value += ", plan ends %s" % expires[:10]
        rows.append(dict(label="aws " + profile, value=value))
        if plan.get("accountPlanType") == "PAID":
            # The monthly cap bounds traffic only: on a paid plan the instance hours, its
            # public IPv4 and its disk are billed too, with no credits to absorb them.
            problems.append("AWS %s is on the paid plan: its servers' hours, public IPv4 and disks are billed "
                            "(the monthly cap covers traffic only)" % profile)  # fmt: skip
        if plan.get("accountPlanStatus") not in (None, "ACTIVE"):
            problems.append("AWS %s plan is %s: its servers may stop" % (profile, plan.get("accountPlanStatus")))
        if credits is not None and credits < CREDIT_FLOOR:
            problems.append("AWS %s has only %s USD of credits left" % (profile, credits))
        if expires:
            left = datetime.datetime.fromisoformat(expires) - now
            if left.days < EXPIRY_WARN_DAYS:
                problems.append("AWS %s free plan ends in %d days (%s)" % (profile, max(left.days, 0), expires[:10]))
    oci_profiles = sorted({(r.get("profile") or (r.get("bastion") or {}).get("oci_profile") or "DEFAULT")
                           for r in inv["resources"].values()
                           if r.get("provider") == "oci" or r.get("catalog") == "oci" or r.get("bastion")})  # fmt: skip
    for profile in oci_profiles:
        try:
            oc = Oci(profile)
            items = oc("osp-gateway", "subscription-service", "subscription", "list", "--osp-home-region",
                       oc.region, "--compartment-id", oc.tenancy)["data"]["items"]  # fmt: skip
        except (CloudError, KeyError) as e:
            rows.append(dict(label="oci " + profile, value="plan unknown (%s)" % str(e)[-80:]))
            continue
        for it in items:
            rows.append(dict(label="oci " + profile, value="%s (%s)" % (it.get("plan-type"), it.get("upgrade-state"))))
            if it.get("plan-type") != "FREE_TIER":
                problems.append("Oracle %s is upgraded (%s): anything beyond Always Free is billed; keep only "
                                "Always Free shapes" % (profile, it.get("plan-type")))  # fmt: skip
            if it.get("plan-type") == "FREE_TIER":
                rows.append(dict(label="", value="free tier: Oracle stops Always Free servers idle for 7 days "
                                 "(CPU, network and memory under 20%); a VPN-only server can look idle"))  # fmt: skip
    return rows, problems


def health(a):
    """`health`: whether each chain server runs, is locked, or was stopped, and whether the
    accounts behind them are running out. Asks the providers, so it runs when you ask (or
    the VPN tells you to), never on a timer from your address."""
    inv = load_inventory()
    names = (inv.get("chain") or {}).get("hops") or [n for n, r in inv["resources"].items() if r.get("role")]
    rows, problems = [], []
    for name in names:
        rec = inv["resources"].get(name)
        if not rec:
            continue
        try:
            state, problem, fix = server_health(name, rec)
        except CloudError as e:
            state, problem, fix = "unknown", "could not ask its provider (%s)" % str(e)[-80:], None
        rows.append(dict(label=name, value=("PROBLEM: %s; %s" % (problem, state)) if problem else state))
        if fix:
            rows.append(dict(label="", value="fix: " + fix))
        if problem:
            problems.append("%s: %s" % (name, problem))
    more, usage_problems = usage_rows(names)
    rows += more
    problems += usage_problems
    more, account_problems = account_health(inv)
    rows += more
    problems += account_problems
    result = dict(schema=1, checked=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  problems=problems)  # fmt: skip
    path = INVENTORY.parent / "health.json"
    path.write_text(json.dumps(result, indent=1))
    path.chmod(0o600)
    if getattr(a, "notify", False) and problems:
        notify_user("VPN: %d problem%s" % (len(problems), "" if len(problems) == 1 else "s"), "\n".join(problems))
    rows.append(dict(label="result", value="; ".join(problems) if problems else "no problem found"))
    return rows


def hostport(ip, port):
    """IP:PORT, with an IPv6 address in brackets."""
    return ("[%s]:%d" if ":" in ip else "%s:%d") % (ip, port)


FLY_PORT = 4444
FLY_MEMORY_MB = 256  # the smallest machine: what the $5 waiver leaves room for
FLY_VOLUME_GB = 1


def fly_server(a):
    """`fly server --apply|--teardown`: one exit on a Fly.io Machine (docs/FLY_EXIT.md). The
    fee guard is asked first, so a second Fly server in the organization, or a machine too
    large for the $5 waiver, is refused before anything is created. Then: the image built
    from this tree and pushed to the app's registry, a 1 GB encrypted volume with snapshots
    off, the app's free IPv6 (never a paid IPv4), and a 256 MB machine serving raw TCP on
    one port."""
    import fly_api

    inv = load_inventory()
    if a.teardown:
        rec = inv["resources"].get(a.name)
        if not rec or rec.get("provider") != "fly":
            raise CloudError("%s is not a recorded Fly.io server" % a.name)
        rows = [dict(label="delete", value="machine %s and volume %s" % (rec["machine"], rec["volume"]))]
        if a.dry_run or not confirm(a, "Delete Fly.io %s" % a.name):
            return rows
        fly_api.api("DELETE", "/apps/%s/machines/%s?force=true" % (rec["app"], rec["machine"]))
        wait("the machine to go", lambda: fly_gone(fly_api, rec), timeout=120, every=3)
        fly_api.api("DELETE", "/apps/%s/volumes/%s" % (rec["app"], rec["volume"]))
        inv["resources"].pop(a.name)
        save_inventory(inv)
        return rows + [dict(label="deleted", value=a.name)]
    if a.name in inv["resources"]:
        raise CloudError("%s is already recorded" % a.name)
    app = fly_api.api("GET", "/apps/%s" % a.app)
    record = dict(provider="fly", catalog="fly", app=a.app, account=app["organization"]["slug"], region=a.region,
                  role=a.role, port=FLY_PORT, memory_mb=FLY_MEMORY_MB, volume_gb=FLY_VOLUME_GB)  # fmt: skip
    trial = dict(inv, resources=dict(inv["resources"], **{a.name: record}))
    ((cap, why),) = plan_caps(trial, [a.name]).values()  # raises when the waiver cannot hold it
    rows = [dict(label="server", value="%s: %s in %s (%s), %d MB" % (a.name, a.role, a.region, a.app, FLY_MEMORY_MB)),
            dict(label="monthly cap", value=why)]  # fmt: skip
    if a.dry_run or not confirm(a, "Create Fly.io %s" % a.name):
        return rows
    image = a.image or fly_push_image(a.app)
    vol = fly_api.api("POST", "/apps/%s/volumes" % a.app, dict(
        name="avpn_" + a.name.removeprefix("avpn-").replace("-", "_"), region=a.region, size_gb=FLY_VOLUME_GB,
        encrypted=True, auto_backup_enabled=False, snapshot_retention=1))  # fmt: skip
    record["volume"] = vol["id"]
    save_inventory(dict(inv, resources=dict(inv["resources"], **{a.name: record})))
    ips = fly_api.api("GET", "/apps/%s/ip_assignments" % a.app).get("ips") or []
    v6 = next((x["ip"] for x in ips if ":" in x["ip"] and not x.get("shared") and not x["ip"].startswith("fdaa")), None)
    if not v6:
        v6 = fly_api.api("POST", "/apps/%s/ip_assignments" % a.app, dict(type="v6"))["ip"]
    machine = fly_api.api("POST", "/apps/%s/machines" % a.app, dict(name=a.name, region=a.region, config=dict(
        image=image, guest=dict(cpu_kind="shared", cpus=1, memory_mb=FLY_MEMORY_MB),
        mounts=[dict(volume=vol["id"], path="/data")],
        services=[dict(protocol="tcp", internal_port=FLY_PORT, ports=[dict(port=FLY_PORT)],
                       autostop="off", autostart=False, min_machines_running=1)],
        restart=dict(policy="always"))))  # fmt: skip
    record.update(machine=machine["id"], public_ip=v6, image=image, added=datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds"))  # fmt: skip
    inv = load_inventory()
    inv["resources"][a.name] = record
    save_inventory(inv)
    fly_api.api("GET", "/apps/%s/machines/%s/wait?state=started&timeout=60" % (a.app, machine["id"]), timeout=90)
    return rows + [dict(label="machine", value="%s, %s port %d (TCP, IPv6 only)" % (machine["id"], v6, FLY_PORT)),
                   dict(label="next", value="avpn cloud host setup --name %s --role %s --out FILE --vault DIR" % (
                       a.name, a.role))]  # fmt: skip


def fly_gone(fly_api, rec):
    """Whether a Fly machine is destroyed (its volume can then be deleted)."""
    try:
        return fly_api.api("GET", "/apps/%s/machines/%s" % (rec["app"], rec["machine"])).get("state") == "destroyed"
    except fly_api.FlyError:
        return True


def fly_push_image(app):
    """Build the exit image from this tree and push it to the app's registry; its reference."""
    import fly_api

    root = Path(__file__).resolve().parents[1]
    tag = "registry.fly.io/%s:%s" % (app, datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    call([str(root / "deploy/fly/build.sh"), tag], parse=False)
    docker = tool("docker")
    # The token goes on stdin, never in an argument list; and only to Fly's registry.
    call([docker, "login", "registry.fly.io", "-u", "x", "--password-stdin"], parse=False, stdin=fly_api.token())
    try:
        call([docker, "push", "-q", tag], parse=False)
    finally:
        call([docker, "logout", "registry.fly.io"], parse=False)
    return tag


def per_link_allowance_gib(hops, caps):
    """The rate-class allowance for `avpn init --allowance-gib` (which counts two links when
    the chain has more than one hop): each hop's cap divided by the streams it sends (a
    relay or middle two, the exit one), the tightest of them, as GiB for two links."""
    shares = []
    for h in hops:
        c = caps[h["name"]][0]
        if c is not None:
            links = 1 if h["role"] == "exit" else 2
            shares.append(c / links)
    if not shares:
        return None
    links = 2 if len(hops) > 1 else 1
    return max(1, int(min(shares) * links) >> 30)


def fee_server(rec):
    """What the fee guard needs to know about a recorded server."""
    provider = rec.get("catalog") or rec.get("provider")
    account = rec.get("profile") or (rec.get("bastion") or {}).get("oci_profile") or rec.get("account") or ""
    d = dict(provider=provider, account=account, region=rec.get("region", ""))
    for k in ("cap_gb", "unlimited", "memory_mb", "volume_gb"):
        if k in rec:
            d[k] = rec[k]
    return d


def plan_caps(inv, names):
    """{name: (cap bytes or None, why)} for `names`. An account's allowance is shared by
    every server recorded in it that carries traffic (the chain's hops and standbys)."""
    chain = set((inv.get("chain") or {}).get("hops") or []) | set(names)
    active = {n: r for n, r in inv["resources"].items() if n in chain or r.get("standby")}
    try:
        planned = fee_guard.plan_caps({n: fee_server(r) for n, r in active.items()})
    except fee_guard.FeeGuardError as e:
        raise CloudError(str(e)) from None
    return {n: planned[n] for n in names}


def require_caps(inv, names):
    """plan_caps, refusing any server whose cap would be unknown (no fees from a free account)."""
    caps = plan_caps(inv, names)
    unknown = [n for n, (c, _) in caps.items() if c is None and not inv["resources"][n].get("unlimited")]
    if unknown:
        raise CloudError("no monthly cap for %s: %s" % (", ".join(unknown), caps[unknown[0]][1]))
    return caps


def push_cap(name, rec, cap_bytes, why):
    """Write a server's cap where its supervisor reads it (beside the enrolled state)."""
    ssh, _scp, base, host = remote(name, rec)
    body = dict(schema=1, why=why, checked=fee_guard.CHECKED)
    body.update(unlimited=True) if cap_bytes is None else body.update(cap_bytes=int(cap_bytes))
    d = "/etc/advanced-vpn/metering/enrolled"
    script = (
        "set -e; sudo -n install -d -m 0700 /etc/advanced-vpn/metering %s; "
        "sudo -n sh -c 'umask 077; cat > %s/cap.json.tmp && mv %s/cap.json.tmp %s/cap.json'" % (d, d, d, d)
    )
    call([ssh, *base, host, script], parse=False, stdin=json.dumps(body))


def cap(a):
    """`cap [NAME] [--gb N | --unlimited | --auto] [--apply]`: each server's monthly cap,
    from its account's free allowance (shared by the servers in that account), or one you
    set; --apply writes them to the servers, which enforce them within seconds."""
    inv = load_inventory()
    names = (inv.get("chain") or {}).get("hops") or []
    if a.name:
        valid_name(a.name)
        if a.name not in inv["resources"]:
            raise CloudError("%s is not recorded" % a.name)
        rec = inv["resources"][a.name]
        if a.gb is not None or a.unlimited or a.auto:
            for k in ("cap_gb", "unlimited"):
                rec.pop(k, None)
            if a.gb is not None:
                if a.gb <= 0:
                    raise CloudError("--gb must be positive")
                rec["cap_gb"] = a.gb
            elif a.unlimited:
                rec["unlimited"] = True
            save_inventory(inv)
        names = [a.name]
    if not names:
        raise CloudError("no chain recorded yet: avpn cloud chain --apply")
    caps = plan_caps(inv, names)
    rows = []
    for n in names:
        c, why = caps[n]
        unknown = c is None and not inv["resources"][n].get("unlimited")
        rows.append(dict(label=n, value=("NOT SET: " if unknown else "") + why))
        if a.apply and not unknown:
            push_cap(n, inv["resources"][n], c, why)
            rows.append(dict(label="", value="written to the server"))
    return rows


AZURE_SIZE = "Standard_B1s"  # Azure free services: 750 hours a month for 12 months


def azure_subscription():
    """(subscription id, name) of the Azure CLI's current sign-in."""
    got = call([tool("az"), "account", "show", "--output", "json"])
    return got["id"], got.get("name", "")


def relay_jump_config(name, relay_name, relay):
    """SSH config lines reaching `name` through the chain's relay (itself reached through its
    EC2 Instance Connect Endpoint): administration that never names your address."""
    admin = eice_admin(relay)
    if not admin:
        raise CloudError("%s is not administered through an Instance Connect Endpoint" % relay_name)
    tunnel = " ".join(shlex.quote(x) for x in [tool("aws"), "ec2-instance-connect", "open-tunnel", "--instance-id",
                                                admin["instance"], "--profile", relay["profile"], "--region",
                                                relay["region"]])  # fmt: skip
    known = INVENTORY.parent / "ssh"
    return (
        "Host %s-relay\n  HostName %s\n  HostKeyAlias %s\n  User %s\n  ProxyCommand %s\n  IdentityFile %s\n"
        "  IdentitiesOnly yes\n  IdentityAgent none\n  UserKnownHostsFile %s\n  ServerAliveInterval 15\n"
        % (name, admin["instance"], relay["public_ip"], relay.get("ssh_user", "admin"), tunnel, relay["ssh_key"],
           known / (relay_name + ".known_hosts"))
    )  # fmt: skip


def azure_server(a):
    """`azure server --apply|--teardown`: one Trusted Launch VM through OpenTofu (the
    azure-server module), administered through the relay; state encrypted with the vault's
    key (one PIN + touch for the whole run)."""
    import tofu_run

    inv = load_inventory()
    if a.teardown:
        rec = inv["resources"].get(a.name)
        if not rec or rec.get("engine") != "tofu":
            raise CloudError("%s is not an OpenTofu-managed server" % a.name)
        key = tofu_run.operator_key(a.vault, controller())
        d = tofu_run.workspaces() / a.name
        summary = tofu_run.plan(d, key, destroy=True)
        rows = [dict(label=act, value=", ".join(x.split(".")[-2] for x in addrs)) for act, addrs in summary.items()]
        if a.dry_run or not confirm(a, "Remove Azure %s" % a.name):
            return rows
        tofu_run.apply(d, key)
        del inv["resources"][a.name]
        save_inventory(inv)
        return rows + [dict(label="removed", value="%s and its resource group" % a.name)]
    if a.name in inv["resources"]:
        raise CloudError("%s is already recorded; tear it down first" % a.name)
    relay_name = a.admin_via
    relay = inv["resources"].get(relay_name)
    if not relay or not relay.get("public_ip"):
        raise CloudError("--admin-via %s is not a recorded server with an address" % relay_name)
    subscription, sub_name = azure_subscription()
    key_path = ssh_key_dir(a.name)
    if not key_path.exists():
        subprocess.run([shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                        a.name, "-f", str(key_path)], check=True)  # fmt: skip
    port = a.port or ROLES[a.role]
    user_data = first_boot_file()
    try:
        variables = dict(
            name=a.name, location=a.location, size=a.size, port=port, tunnel_sources=a.allow_from,
            tcp_fallback=port == FIRST_HOP_PORT, admin_sources=[relay["public_ip"] + "/32"],
            ssh_public_key=Path(str(key_path) + ".pub").read_text().strip(),
            user_data=base64.b64encode(user_data.read_bytes()).decode(),
        )  # fmt: skip
    finally:
        user_data.unlink(missing_ok=True)
    d = tofu_run.workspace(a.name, "azure-server", variables, dict(subscription=subscription))
    key = tofu_run.operator_key(a.vault, controller())
    tofu_run.init(d, key)
    summary = tofu_run.plan(d, key)
    rows = [
        dict(label="subscription", value=sub_name),
        dict(label="server", value="%s %s in %s, Trusted Launch (secure boot, vTPM)" % (a.name, a.size, a.location)),
        dict(
            label="firewall",
            value="udp %d from %s; SSH 22 only from the relay %s (%s)"
            % (port, ", ".join(a.allow_from), relay_name, relay["public_ip"]),
        ),  # fmt: skip
        dict(
            label="cost",
            value="Azure free services: %s 750 h/month for 12 months; outbound traffic beyond the free "
            "allowance is billed to the subscription" % a.size,
        ),  # fmt: skip
    ] + [dict(label=act, value=", ".join(x.split(".")[-2] for x in addrs)) for act, addrs in summary.items()]
    rows.append(caller_note("azure"))
    if a.dry_run or not confirm(a, "Create Azure %s %s" % (a.role, a.name)):
        return rows
    out = tofu_run.apply(d, key)["server"]["value"]
    config = INVENTORY.parent / "ssh" / (a.name + ".conf")
    text = relay_jump_config(a.name, relay_name, relay) + (
        "Host %s\n  HostName %s\n  User ubuntu\n  IdentityFile %s\n  IdentitiesOnly yes\n  IdentityAgent none\n"
        "  StrictHostKeyChecking accept-new\n  UserKnownHostsFile %s\n  ProxyJump %s-relay\n  ConnectTimeout 30\n"
        % (a.name, out["public_ip"], key_path, INVENTORY.parent / "ssh" / (a.name + ".known_hosts"), a.name)
    )  # fmt: skip
    tmp = config.with_suffix(".conf.tmp")
    tmp.write_text(text)
    tmp.chmod(0o600)
    tmp.replace(config)
    inv["resources"][a.name] = dict(
        provider="azure", catalog="azure", engine="tofu", role=a.role, port=port, public_ip=out["public_ip"],
        ssh="ubuntu@" + a.name, ssh_config=str(config), ssh_key=str(key_path), location=a.location,
        subscription=subscription, vm=out["vm_id"], resource_group=out["resource_group"],
        created=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    )  # fmt: skip
    save_inventory(inv)
    return rows + [dict(label="public address", value="%s (udp %d)" % (out["public_ip"], port)),
                   dict(label="ssh", value="through the relay: ssh -F %s %s" % (config, a.name)),
                   dict(label="next", value="avpn cloud chain --apply")]  # fmt: skip


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
    rows.append(
        dict(
            label="non-US",
            value="for ends in different legal spheres (every free tier above is a US company): "
            + ", ".join("%s (%s) %s" % (p["name"], p["parent"], p["source"]) for p in providers.NON_US)
            + "; paid, check terms; record one with avpn cloud host add --provider KEY",
        )
    )
    for p in providers.low_cost_rows():
        rows.append(dict(label=p["key"], value="%s (%s, paid): %s; %s" % (p["name"], p["parent"], p["price"],
                                                                         p["traffic"])))  # fmt: skip
        rows.append(dict(label="", value="note: %s; %s" % (p["covers"], p["note"])))
    for p in providers.UNTESTED:
        rows.append(dict(label=p["key"], value="%s: not yet usable: %s" % (p["name"], p["blockers"])))
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
            # A firewall rule (`oci allow`) names its source; a server (`oci server`) its address.
            where = r.get("source") or r.get("public_ip") or "(no instance)"
            detail += " %s:%s" % (where, r.get("port", "?"))
        if r.get("key_protection") == "none":
            # Bug 9a: a host that could not seal its keys says so wherever it is listed.
            detail += " [PLAINTEXT KEYS]"
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
    rot = s.add_parser("rotate", help="trade an exit's public IP for a fresh one (STREAMING_GEO_PARITY section 4.4)")
    rot.add_argument("--name", required=True, help="the server's name and tag (avpn-*)")
    rot.add_argument(
        "--strategy",
        choices=["reallocate", "reprovision"],
        default="reallocate",
        help="trade the address (default) or teardown plus re-apply, possibly in a new region",
    )
    rot.add_argument("--reason", default="unspecified", help="why (journal; for example: netflix-blocked)")
    rot.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "default"), help="AWS CLI profile")
    rot.add_argument("--region", help="must equal the profile's Region (the project has one Region)")
    rot.add_argument(
        "--tunnel-down",
        action="store_true",
        help="attest the tunnel using this exit is stopped (required to apply; there is no --force)",
    )
    rot.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    rot.add_argument("--yes", action="store_true", help="do not ask for confirmation")
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
    endpoint = aws_s.add_parser(
        "admin-endpoint", help="administer a server through an EC2 Instance Connect Endpoint, with no SSH address rule"
    )
    endpoint.add_argument(
        "--apply", action="store_true", required=True, help="create the endpoint and switch SSH to it"
    )
    endpoint.add_argument("--name", default="avpn-relay", help="the server's name and tag (avpn-*)")
    endpoint.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "default"), help="AWS CLI profile")
    endpoint.add_argument("--region", help="must equal the profile's Region (the project has one Region)")
    endpoint.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    endpoint.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    h = s.add_parser("host", help="servers this tool created")
    h_s = h.add_subparsers(dest="kind", required=True)
    setup = h_s.add_parser("setup", help="install the package over SSH and fetch the public request")
    setup.add_argument("--name", required=True, help="the recorded server (avpn-*)")
    setup.add_argument(
        "--source", default=str(Path(__file__).resolve().parents[1]), help="built checkout to install from"
    )
    setup.add_argument("--source-arm", help="built ARM (aarch64) checkout, for ARM servers such as OCI Ampere A1")
    setup.add_argument("--out", type=Path, required=True, help="where to save the server's public request")
    setup.add_argument("--role", choices=sorted(ROLES), help="the server's role (default: its recorded role)")
    setup.add_argument("--replace", action="store_true", help="replace keys made for another role")
    setup.add_argument(
        "--vault", type=Path,
        help="the operator's Nitrokey vault: a host without a usable TPM2 locks its keys to its unlock key",
    )  # fmt: skip
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
        help="where it runs: a free tier (oci, aws, azure, gcp), own, or a paid host key from avpn cloud suggest",
    )
    add.add_argument("--shared", action="store_true", help="it also runs other things: leave its journal alone")
    hu = h_s.add_parser("update", help="apply security updates in a counted maintenance window")
    hu.add_argument("--name", required=True)
    hb = h_s.add_parser("bastion", help="record that a server is reached through an OCI bastion (sessions renewed)")
    hb.add_argument("--name", required=True, help="the recorded server")
    hb.add_argument("--bastion-id", required=True, help="the OCI bastion's OCID")
    hb.add_argument("--instance-id", required=True, help="the server's OCI instance OCID")
    hb.add_argument("--host", required=True, help="the bastion's Host alias in the server's SSH config")
    hb.add_argument("--public-key", required=True, help="the SSH public key a session admits")
    hb.add_argument("--user", default="ubuntu", help="the login user on the server (default ubuntu)")
    hb.add_argument("--oci-profile", default="DEFAULT", help="the OCI CLI profile (default DEFAULT)")
    forget = h_s.add_parser("forget", help="drop a recorded server from the inventory (it is not changed)")
    forget.add_argument("--name", required=True, help="the recorded server")
    hl = s.add_parser("health", help="are the chain's servers running, locked or stopped, and the accounts healthy?")
    hl.add_argument("--notify", action="store_true", help="also show a desktop notification when something is wrong")
    fl = s.add_parser("fly", help="an exit on a Fly.io Machine (IPv6 TCP; within the $5 waiver)")
    fl_s = fl.add_subparsers(dest="kind", required=True)
    fls = fl_s.add_parser("server", help="one 256 MB Machine with an encrypted volume and the app's free IPv6")
    fmode = fls.add_mutually_exclusive_group(required=True)
    fmode.add_argument("--apply", action="store_true", help="create the server")
    fmode.add_argument("--teardown", action="store_true", help="delete its machine and volume")
    fls.add_argument("--name", default="avpn-flyexit")
    fls.add_argument("--app", default="advanced-vpn", help="the Fly.io app the deploy token is for")
    fls.add_argument("--region", default="fra", help="a Fly.io region (default fra; iad/ewr are cheapest)")
    fls.add_argument("--role", choices=["exit", "middle"], default="exit")
    fls.add_argument("--image", help="an image already pushed (default: build and push this tree's)")
    fls.add_argument("--dry-run", action="store_true")
    fls.add_argument("--yes", action="store_true")
    cp = s.add_parser("cap", help="each server's monthly outbound cap, so a free account is never billed")
    cp.add_argument("name", nargs="?", help="one server (default: every hop of the chain)")
    how = cp.add_mutually_exclusive_group()
    how.add_argument("--gb", type=float, help="set this server's cap, in GB (decimal, as providers bill)")
    how.add_argument("--unlimited", action="store_true", help="no cap: a host whose traffic costs you nothing")
    how.add_argument("--auto", action="store_true", help="back to the cap from its account's free allowance")
    cp.add_argument("--apply", action="store_true", help="write the caps to the servers")
    az = s.add_parser("azure", help="Azure servers, through OpenTofu")
    az_s = az.add_subparsers(dest="kind", required=True)
    azs = az_s.add_parser("server", help="one Trusted Launch VM (vTPM), administered through the relay")
    mode = azs.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="create the server")
    mode.add_argument("--teardown", action="store_true", help="delete it and its resource group")
    azs.add_argument("--name", default="avpn-exit-az", help="resource name and tag (avpn-*)")
    azs.add_argument("--role", choices=sorted(ROLES), default="exit", help="what the server is in the chain")
    azs.add_argument("--location", default="swedencentral", help="Azure region (default swedencentral)")
    azs.add_argument("--size", default=AZURE_SIZE, help="VM size (default %s, a free-services size)" % AZURE_SIZE)
    azs.add_argument("--port", type=int, help="tunnel port (default by role)")
    azs.add_argument("--allow-from", action="append", default=[], help="previous hop's public IPv4")
    azs.add_argument("--admin-via", default="avpn-relay", help="the relay SSH goes through (default avpn-relay)")
    azs.add_argument("--vault", type=Path, required=True, help="the operator's Nitrokey vault (the state key)")
    azs.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    azs.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    ul = s.add_parser("unlock", help="unlock a server without a TPM after it restarts (Nitrokey PIN + touch)")
    ul.add_argument("name", help="the recorded server (avpn-*)")
    ul.add_argument("--vault", type=Path, help="the operator's Nitrokey vault (default: the chain's)")
    ch = s.add_parser("chain", help="join the recorded servers into one multi-hop chain")
    ch.add_argument("--apply", action="store_true", required=True, help="build (or rebuild) the chain")
    ch.add_argument("--client-request", type=Path, required=True, help="the client device's public request")
    ch.add_argument("--vault", type=Path, required=True, help="the operator's Nitrokey vault directory")
    ch.add_argument("--order", help="hop order, client side first: NAME,NAME[,NAME] (default: automatic)")
    ch.add_argument(
        "--allow-same-provider",
        action="store_true",
        help="allow the entry and the exit on one provider (which then sees your address and your destinations)",
    )
    ch.add_argument(
        "--source", default=str(Path(__file__).resolve().parents[1]), help="built package or checkout to install"
    )
    ch.add_argument("--source-arm", help="built ARM (aarch64) checkout, for ARM servers such as OCI Ampere A1")
    ch.add_argument(
        "--hours-per-day", type=float, default=8, help="hours connected per day, for the rate class (default 8)"
    )
    ch.add_argument(
        "--accept-cost", action="store_true", help="sign the rate class even if it exceeds a hop's free allowance"
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
    srv.add_argument(
        "--vcn",
        help="put the server in this existing VCN (own subnet, route table and security list; the VCN and its "
        "gateway are not changed): a free tenancy has only two VCNs",
    )
    srv.add_argument("--oci-profile", default="DEFAULT", help="profile in ~/.oci/config")
    srv.add_argument("--port", type=int, help="tunnel port (default: 41194 relay, 4445 middle, 4444 exit)")
    srv.add_argument(
        "--allow-from",
        action="append",
        default=[],
        help="previous hop's public IPv4, auto, or any (first hop only; the default for a relay)",
    )
    srv.add_argument("--admin-ip", default="auto", help="address allowed to SSH in (default: this machine)")
    srv.add_argument(
        "--wait-capacity",
        type=int,
        default=0,
        metavar="MINUTES",
        help="keep retrying a launch refused for lack of capacity (every 2 minutes, across fault domains)",
    )
    srv.add_argument(
        "--bastion",
        help="OCI bastion OCID: SSH only through it (no address rule; sessions renewed automatically); "
        "the server goes in the bastion's VCN",
    )
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
    if a.provider == "rotate":
        import ip_rotation  # lazy: ip_rotation imports this module

        return ip_rotation.run_rotate(a)
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
        if a.kind == "bastion":
            return dict(title="Bastion for %s" % a.name, summary="recorded", rows=host_bastion(a))
        if a.kind == "update":
            return dict(title="Update %s" % a.name, summary="updated", rows=host_update(a))
        return dict(title="Set up %s" % a.name, summary="installed", rows=host_setup(a))
    if a.provider == "azure" and a.kind == "server":
        valid_name(a.name)
        if a.apply:
            if not a.allow_from:
                raise CloudError("--allow-from is required: the previous hop's address")
            a.allow_from = [single_ip(x) for x in a.allow_from]
        title = ("Remove" if a.teardown else "Create") + " Azure %s" % a.name
        rows = azure_server(a)
        return dict(title=title, summary="plan" if a.dry_run else "done", rows=rows, dry_run=a.dry_run)
    if a.provider == "health":
        rows = health(a)
        bad = rows[-1]["value"] != "no problem found"
        return dict(title="Health", summary="problems found" if bad else "healthy", rows=rows)
    if a.provider == "fly" and a.kind == "server":
        valid_name(a.name)
        title = ("Remove" if a.teardown else "Create") + " Fly.io %s" % a.name
        return dict(title=title, summary="plan" if a.dry_run else "done", rows=fly_server(a), dry_run=a.dry_run)
    if a.provider == "cap":
        return dict(title="Monthly caps", summary="written" if a.apply else "planned", rows=cap(a))
    if a.provider == "unlock":
        valid_name(a.name)
        return dict(title="Unlock %s" % a.name, summary="unlocked", rows=unlock(a))
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
            a.admin_ip = None if getattr(a, "bastion", None) else single_ip(a.admin_ip)
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
        if a.kind == "admin-endpoint":
            plan = aws_admin_endpoint_plan(a, aws)
            title = "Administer AWS %s through an Instance Connect Endpoint" % a.name
            if a.dry_run:
                return dict(title=title, summary="plan", rows=plan["rows"], dry_run=True)
            if not confirm(a, title):
                return dict(title=title, summary="cancelled", rows=plan["rows"])
            return dict(title=title, summary="applied", rows=aws_admin_endpoint_apply(a, aws, plan))
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

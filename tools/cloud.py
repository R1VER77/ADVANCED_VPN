#!/usr/bin/env python3
"""Built-in cloud setup for ADVANCED_VPN chains (`avpn cloud`).

Runs as you, never as root, because it uses your own signed-in provider CLIs (`aws`,
`oci`). It only ever touches resources it tagged itself (`avpn:managed=true` plus
`avpn:name=<name>`), so a teardown cannot reach anything else in the account.

Commands:
- `status`: the local inventory, plus the tagged resources that still exist.
- `aws relay --apply|--teardown`: one NitroTPM-capable relay (or middle/exit) instance.
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
import subprocess
import sys
import tempfile
import time
import urllib.request

from install import pack  # the installer's own package format

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


def single_ip(value):
    """One IPv4 address (as a /32 CIDR); `auto` uses this machine's public address."""
    if value == "auto":
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as r:  # noqa: S310 (fixed https URL)
            value = r.read().decode().strip()
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_global:
        raise CloudError("%s is not a public IPv4 address" % value)
    return str(ip) + "/32"


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
    return dict(account=who["Account"], rows=rows, owned=owned, port=port)


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
    run = aws.ec2(
        "run-instances",
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
        json.dumps(
            [
                dict(
                    DeviceName=root,
                    Ebs=dict(VolumeSize=a.disk_gib, VolumeType="gp3", Encrypted=True, DeleteOnTermination=True),
                )
            ]
        ),
        "--tag-specifications",
        json.dumps(
            json.loads(aws.tags("instance", a.name, {"avpn:role": a.role})) + json.loads(aws.tags("volume", a.name))
        ),
    )
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
    return [dict(label="deleted", value=r["value"]) for r in plan["rows"] if r["label"] != "nothing"]


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


# What a fresh Debian/Ubuntu server needs. The TSS2 runtime libraries let systemd-creds
# actually use the TPM; without them it silently falls back to the host key.
HOST_SETUP = r"""set -e
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update -qq
TSS=$(apt-cache search --names-only '^libtss2-(esys|mu|rc|tcti-device)' | awk '{print $1}' | grep -v -- -dev | tr '\n' ' ')
sudo -n apt-get install -y -qq nftables python3-venv $TSS >/dev/null
# No retained data: a dedicated chain server keeps its system journal (sshd included,
# which records the admin's address) in RAM only, and drops what the boot wrote to disk.
sudo -n mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\n' | sudo -n tee /etc/systemd/journald.conf.d/50-advanced-vpn.conf >/dev/null
sudo -n systemctl restart systemd-journald
sudo -n rm -rf /var/log/journal
sudo -n rm -rf /tmp/avpn-src && mkdir -p /tmp/avpn-src && tar -C /tmp/avpn-src -xzf /tmp/avpn-src.tgz
if [ ! -e /opt/advanced-vpn ]; then sudo -n python3 -B /tmp/avpn-src/tools/install.py --out /root/avpn-stage-$$ --apply; fi
sudo -n test ! -e /etc/advanced-vpn/enrolled/profile.json || { echo 'already enrolled; not regenerating keys' >&2; exit 3; }
sudo -n rm -rf /etc/advanced-vpn/enrolled
sudo -n /opt/advanced-vpn/bin/avpnctl request --role "$1" --protect systemd-creds --out /root/request.json >/dev/null
sudo -n cat /root/request.json > /tmp/avpn-request.json
echo "tpm2=$(systemd-analyze has-tpm2 >/dev/null 2>&1 && echo yes || echo no) creds_key=$(sudo -n python3 -c 'import json;print(json.load(open("/etc/advanced-vpn/enrolled/protection.json")).get("creds_key"))')"
sudo -n rm -rf /tmp/avpn-src /tmp/avpn-src.tgz
"""


def ssh_base(record):
    """ssh/scp options for a recorded host: its throwaway key, its own known_hosts file."""
    known = Path(record["ssh_key"] + ".known_hosts")
    return [
        "-i", record["ssh_key"], "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + str(known),
        "-o", "ConnectTimeout=20", "-o", "BatchMode=yes",
    ]  # fmt: skip


def source_tarball(root, out):
    """The release package for a built checkout (the installer's own `pack`)."""
    try:
        return pack(root, out)
    except FileNotFoundError as e:
        raise CloudError(str(e)) from None


def host_setup(a):
    """Install the package on a host this tool created and fetch its public request."""
    inv = load_inventory()
    record = inv["resources"].get(a.name)
    if not record or not record.get("public_ip") or not record.get("ssh_key"):
        raise CloudError("%s is not a recorded host with an address and SSH key" % a.name)
    host = "admin@" + record["public_ip"]
    ssh, scp = tool("ssh"), tool("scp")
    base = ssh_base(record)

    def reachable():
        try:
            call([ssh, *base, host, "true"], parse=False)
            return True
        except CloudError:
            return False

    wait("SSH on " + record["public_ip"], reachable, timeout=300, every=10)
    with tempfile.TemporaryDirectory() as d:
        tgz = source_tarball(Path(a.source).resolve(), Path(d) / "avpn-src.tgz")
        call([scp, "-q", *base, str(tgz), host + ":/tmp/avpn-src.tgz"], parse=False)
    report = call([ssh, *base, host, "bash", "-s", "--", record["role"]], parse=False, stdin=HOST_SETUP)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    call([scp, "-q", *base, host + ":/tmp/avpn-request.json", str(a.out)], parse=False)
    if json.loads(a.out.read_text()).get("role") != record["role"]:
        raise CloudError("the request from %s is not for role %s" % (a.name, record["role"]))
    record["request"] = str(a.out)
    save_inventory(inv)
    return [
        dict(label="host", value="%s %s (%s)" % (a.name, record["public_ip"], record["role"])),
        dict(label="installed", value="/opt/advanced-vpn (service not enabled)"),
        dict(label="keys", value=report.strip().splitlines()[-1] if report.strip() else "generated"),
        dict(label="request", value="%s (public; give it to avpn init)" % a.out),
    ]


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
        "--allow-from", action="append", default=[], help="previous hop's public IPv4, or auto (repeatable)"
    )
    relay.add_argument("--admin-ip", default="auto", help="address allowed to SSH in (default: this machine)")
    relay.add_argument("--dry-run", action="store_true", help="show the plan and stop")
    relay.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    h = s.add_parser("host", help="servers this tool created")
    h_s = h.add_subparsers(dest="kind", required=True)
    setup = h_s.add_parser("setup", help="install the package over SSH and fetch the public request")
    setup.add_argument("--name", required=True, help="the recorded server (avpn-*)")
    setup.add_argument(
        "--source", default=str(Path(__file__).resolve().parents[1]), help="built checkout to install from"
    )
    setup.add_argument("--out", type=Path, required=True, help="where to save the server's public request")
    o = s.add_parser("oci", help="Oracle Cloud Infrastructure")
    o_s = o.add_subparsers(dest="kind", required=True)
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
    if a.provider == "status":
        return dict(title="Cloud", summary="inventory " + str(INVENTORY), rows=status(a))
    if a.provider == "host":
        valid_name(a.name)
        return dict(title="Set up %s" % a.name, summary="installed", rows=host_setup(a))
    if a.provider == "aws":
        valid_name(a.name)
        aws = Aws(a.profile, a.region)
        if a.apply:
            if not a.allow_from:
                raise CloudError("--allow-from is required: the previous hop's address (auto = this machine)")
            a.allow_from = [single_ip(x) for x in a.allow_from]
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

"""`avpn cloud` against recorded provider CLIs: exact calls, safety rules, teardown scope."""

import datetime
import json
import os
import re
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import cloud

STUB = r"""#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(argv) + "\n")
state = json.load(open(os.environ["STUB_STATE"]))
def out(v):
    print(json.dumps(v) if not isinstance(v, str) else v)
    sys.exit(0)
def fail(msg):
    print(msg, file=sys.stderr)
    sys.exit(254)
if state.get("expired"):
    fail("An error occurred (ExpiredToken): The security token included in the request is expired")
name = os.path.basename(sys.argv[0])
if name == "oci":
    if argv[:3] == ["network", "security-list", "get"] and "security_list" in state:
        out({"data": state["security_list"]})
    if argv[:3] == ["network", "security-list", "update"]:
        rules = argv[argv.index("--ingress-security-rules") + 1]
        ingress = json.load(open(rules[7:])) if rules.startswith("file://") else json.loads(rules)
        state.setdefault("security_list", {})["ingress-security-rules"] = ingress
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
        out({"data": {"lifecycle-state": "AVAILABLE"}})
    ops = state.setdefault("oci_ops", [])
    ops.append(argv[:3])
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    def oflag(f):
        return argv[argv.index(f) + 1] if f in argv else None
    if argv[:3] == ["iam", "region-subscription", "list"]:
        out({"data": [{"region-name": "eu-stockholm-1", "is-home-region": True},
                      {"region-name": "eu-frankfurt-1", "is-home-region": False}]})
    if argv[:3] == ["iam", "availability-domain", "list"]:
        out({"data": [{"name": "AD-1"}, {"name": "AD-2"}]})
    if argv[:3] == ["compute", "shape", "list"]:
        shapes = ["VM.Standard.E2.1.Micro"] if oflag("--availability-domain") == "AD-2" else []
        out({"data": [{"shape": x} for x in shapes + ["VM.Standard.A1.Flex"]]})
    if argv[:3] == ["compute", "image", "list"]:
        out({"data": [{"id": "ocid1.image.min", "display-name": "Canonical-Ubuntu-24.04-Minimal-2026.10.01-0"},
                      {"id": "ocid1.image.full", "display-name": "Canonical-Ubuntu-24.04-2026.10.01-0"}]})
    made = {("network", "vcn", "create"): {"id": "ocid1.vcn.1", "default-route-table-id": "ocid1.rt.1"},
            ("network", "internet-gateway", "create"): {"id": "ocid1.igw.1"},
            ("network", "security-list", "create"): {"id": "ocid1.sl.1"},
            ("network", "subnet", "create"): {"id": "ocid1.subnet.1"},
            ("network", "route-table", "create"): {"id": "ocid1.rt.own"},
            ("compute", "instance", "launch"): {"id": "ocid1.instance.1"}}
    if argv[:3] == ["compute", "instance", "launch"] and state.get("capacity_fail"):
        state["capacity_fail"] -= 1
        state.setdefault("launch_attempts", []).append(argv)
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
        if state.get("rate_limited"):
            fail('{"code": "TooManyRequests", "message": "Too many requests for the tenant"}')
        fail('{"code": "InternalError", "message": "Out of host capacity."}')
    if argv[:3] == ["compute", "instance", "launch"]:
        state.setdefault("launch_attempts", []).append(argv)
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
    if argv[:3] == ["compute", "instance", "launch"] and "--user-data-file" in argv:
        state["oci_user_data"] = open(oflag("--user-data-file")).read()
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
    if argv[:3] == ["iam", "compartment", "list"]:
        out({"data": state.get("oci_compartments", [])})
    if argv[:3] == ["logging", "log-group", "list"]:
        out({"data": state.get("oci_log_groups", {}).get(oflag("--compartment-id"), [])})
    if argv[:3] == ["logging", "log", "list"]:
        out({"data": state.get("oci_logs", {}).get(oflag("--log-group-id"), [])})
    if argv[:3] == ["network", "vtap", "list"]:
        out({"data": state.get("oci_vtaps", {}).get(oflag("--compartment-id"), [])})
    if argv[:3] == ["bastion", "session", "get"]:
        found = state.get("oci_sessions", {}).get(oflag("--session-id"))
        if not found:
            fail("ServiceError: NotAuthorizedOrNotFound")
        out({"data": found})
    if argv[:3] == ["bastion", "session", "create-managed-ssh"]:
        made = state.setdefault("oci_created_sessions", [])
        made.append(argv)
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
        out({"data": {"resources": [{"entity-type": "bastionsession", "identifier": "ocid1.bastionsession.new%d" % len(made)}]}})
    if argv[:3] == ["bastion", "bastion", "list"]:
        out({"data": [{"id": b["id"]} for b in state.get("oci_bastions", {}).get(oflag("--compartment-id"), [])]})
    if argv[:3] == ["bastion", "bastion", "get"]:
        every = [b for group in state.get("oci_bastions", {}).values() for b in group]
        out({"data": next(b for b in every if b["id"] == oflag("--bastion-id"))})
    if argv[:3] == ["network", "vcn", "get"] and oflag("--vcn-id") == "ocid1.vcn.shared":
        out({"data": {"display-name": "shared-vcn", "cidr-block": "10.0.0.0/16", "cidr-blocks": ["10.0.0.0/16"]}})
    if argv[:3] == ["network", "subnet", "list"]:
        out({"data": [{"cidr-block": "10.0.255.0/24"}, {"cidr-block": "10.0.0.0/24"}]})
    if argv[:3] == ["network", "internet-gateway", "list"]:
        out({"data": [{"id": "ocid1.igw.shared", "is-enabled": True}]})
    if tuple(argv[:3]) in made:
        out({"data": made[tuple(argv[:3])]})
    if argv[:3] == ["compute", "instance", "list-vnics"]:
        out({"data": [{"public-ip": "16.20.0.5", "private-ip": "10.0.254.7"}]})
    if argv[2:3] == ["get"] or argv[:3] == ["network", "route-table", "update"] or argv[2:3] in (["delete"], ["terminate"]) or argv[:3] == ["network", "security-list", "update"]:
        tags = state.get("oci_tags", {"avpn-managed": "true", "avpn-name": "avpn-exit"})
        out({"data": {"freeform-tags": tags, "lifecycle-state": "AVAILABLE"}})
    fail("unexpected oci call")
if argv[:2] == ["configure", "get"]:
    out(state.get("region", "eu-north-1"))
if argv[:2] == ["sts", "get-caller-identity"]:
    out({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root"})
if argv[:1] == ["freetier"]:
    out({"accountPlanType": "FREE"})
AUDIT_DEFAULTS = {
    "cloudtrail describe-trails": {"trailList": []},
    "cloudtrail list-event-data-stores": {"EventDataStores": []},
    "cloudtrail lookup-events": {"Events": []},
    "configservice describe-configuration-recorder-status": {"ConfigurationRecordersStatus": []},
    "route53resolver list-resolver-query-log-configs": {"ResolverQueryLogConfigs": []},
    "logs describe-log-groups": {"logGroups": []},
    "guardduty list-detectors": {"DetectorIds": []},
    "ec2 describe-flow-logs": {"FlowLogs": []},
    "ec2 describe-traffic-mirror-sessions": {"TrafficMirrorSessions": []},
}
key = " ".join(argv[:2])
if key in AUDIT_DEFAULTS:
    v = state.get("audit", {}).get(key)
    if key == "logs describe-log-groups":
        v = state.get("audit", {}).get(key + " " + argv[argv.index("--region") + 1], v)
    if v == "DENIED":
        fail("An error occurred (AccessDeniedException) when calling the operation: User is not authorized")
    out(AUDIT_DEFAULTS[key] if v is None else v)
op = argv[1]
def flag(f):
    return argv[argv.index(f) + 1] if f in argv else None
tagged = "Name=tag:avpn:managed,Values=true" in argv
if op == "describe-images":
    if flag("--owners") == "136693071363":
        out({"Images": [
            {"ImageId": "ami-old", "CreationDate": "2026-01-01T00:00:00Z", "RootDeviceName": "/dev/xvda"},
            {"ImageId": "ami-new", "CreationDate": "2026-10-01T00:00:00Z", "RootDeviceName": "/dev/xvda"}]})
    if flag("--image-ids") == "ami-copy":
        out({"Images": [{"State": "available", "RootDeviceName": "/dev/xvda",
                         "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-1"}}]}]})
    out({"Images": state.get("images", []) if tagged else []})
if op == "describe-instances":
    if flag("--instance-ids"):
        st = "terminated" if state.get("terminated") else "running"
        out({"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": st}, "PublicIpAddress": "16.0.0.9"}]}]})
    out({"Reservations": [{"Instances": state.get("instances", [])}] if tagged else []})
if op == "describe-security-groups":
    admin = any(a.endswith("-admin") for a in argv if a.startswith("Name=tag:avpn:name"))
    out({"SecurityGroups": (state.get("admin_groups", []) if admin else state.get("groups", [])) if tagged else []})
if op == "describe-snapshots":
    out({"Snapshots": state.get("snapshots", []) if tagged else []})
if op == "describe-key-pairs":
    out({"KeyPairs": state.get("keys", []) if tagged else []})
if op == "describe-vpcs":
    out({"Vpcs": [{"VpcId": "vpc-1"}]})
if op == "copy-image":
    out({"ImageId": "ami-copy"})
if op == "register-image":
    out({"ImageId": "ami-tpm"})
if op == "create-security-group":
    if flag("--group-name", ) and flag("--group-name").endswith("-admin"):
        g = {"GroupId": "sg-admin", "GroupName": flag("--group-name"), "IpPermissions": [],
             "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
        state.setdefault("admin_groups", []).append(g)
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
        out({"GroupId": "sg-admin"})
    out({"GroupId": "sg-1"})
if op in ("authorize-security-group-egress", "revoke-security-group-egress"):
    for g in state.get("admin_groups", []):
        if g["GroupId"] == flag("--group-id"):
            perms = json.loads(flag("--ip-permissions"))
            if op.startswith("authorize"):
                g["IpPermissionsEgress"] += perms
            else:
                g["IpPermissionsEgress"] = [q for q in g["IpPermissionsEgress"] if q not in perms]
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({"Return": True})
if op == "create-instance-connect-endpoint":
    state["endpoint"] = {"InstanceConnectEndpointId": "eice-1", "State": "create-complete",
                         "SubnetId": flag("--subnet-id"), "SecurityGroupIds": [flag("--security-group-ids")]}
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({"InstanceConnectEndpoint": state["endpoint"]})
if op == "describe-instance-connect-endpoints":
    e = state.get("endpoint")
    out({"InstanceConnectEndpoints": [e] if e else []})
if op == "delete-instance-connect-endpoint":
    state["endpoint"]["State"] = "delete-complete"
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({})
if op == "run-instances":
    if flag("--user-data"):
        state["user_data"] = open(flag("--user-data")[len("file://"):]).read()
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({"Instances": [{"InstanceId": "i-1"}]})
if op == "terminate-instances":
    state["terminated"] = True
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({})
if op in ("authorize-security-group-ingress", "revoke-security-group-ingress"):
    for g in state.get("groups", []):
        if g["GroupId"] != flag("--group-id"):
            continue
        for p in json.loads(flag("--ip-permissions")):
            key = (p["IpProtocol"], p["FromPort"], p["ToPort"])
            mine = [q for q in g.setdefault("IpPermissions", []) if (q["IpProtocol"], q["FromPort"], q["ToPort"]) == key]
            if op.startswith("authorize"):
                if not mine:
                    mine = [dict(IpProtocol=key[0], FromPort=key[1], ToPort=key[2], IpRanges=[])]
                    g["IpPermissions"].append(mine[0])
                have = {r["CidrIp"] for r in mine[0]["IpRanges"]}
                if have & {r["CidrIp"] for r in p.get("IpRanges", [])}:
                    fail("An error occurred (InvalidPermission.Duplicate)")
                mine[0]["IpRanges"] += p.get("IpRanges", [])
                if p.get("UserIdGroupPairs"):
                    mine[0].setdefault("UserIdGroupPairs", []).extend(p["UserIdGroupPairs"])
            else:
                if not mine:
                    fail("An error occurred (InvalidPermission.NotFound)")
                for k in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"):
                    drop = [json.dumps({x: r[x] for x in r if x != "Description"}, sort_keys=True) for r in p.get(k, [])]
                    mine[0][k] = [r for r in mine[0].get(k, [])
                                  if json.dumps({x: r[x] for x in r if x != "Description"}, sort_keys=True) not in drop]
                if not any(mine[0].get(k) for k in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs")):
                    g["IpPermissions"].remove(mine[0])
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({"Return": True})
if op in ("create-tags", "deregister-image", "import-key-pair",
          "delete-security-group", "delete-key-pair", "delete-snapshot"):
    out({})
fail("unexpected aws call: " + " ".join(argv))
"""


class Stubbed(unittest.TestCase):
    """Stub provider CLIs, a private inventory, no sleeping and no network."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        for name in ["aws", "oci"]:
            (d / name).write_text(STUB.replace("#!/usr/bin/env python3", "#!" + sys.executable))
            (d / name).chmod(0o755)
        self.log, self.state = d / "log", d / "state.json"
        self.set_state({})
        self.env = mock.patch.dict(
            os.environ,
            dict(AVPN_AWS=str(d / "aws"), AVPN_OCI=str(d / "oci"), STUB_LOG=str(self.log), STUB_STATE=str(self.state)),
        )
        self.env.start()
        self.inv = mock.patch.object(cloud, "INVENTORY", d / "config" / "cloud.json")
        self.inv.start()
        self.nosleep = mock.patch.object(cloud.time, "sleep", lambda s: None)
        self.nosleep.start()
        # This machine's public address, as checkip would report it (no network in tests).
        self.me = mock.patch.object(cloud, "egress", lambda: "16.9.9.9")
        self.me.start()

    def tearDown(self):
        self.me.stop()
        self.nosleep.stop()
        self.inv.stop()
        self.env.stop()
        self.tmp.cleanup()

    def set_state(self, value):
        self.state.write_text(json.dumps(value))

    def calls(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def ops(self):
        return [c[1] for c in self.calls() if c and c[0] == "ec2"]

    def run_cli(self, *argv):
        a = cloud.build_parser().parse_args(list(argv))
        return cloud.run(a)

    def call_with(self, op):
        return next(c for c in self.calls() if c[:2] == ["ec2", op])

    def value(self, argv, flag):
        return argv[argv.index(flag) + 1]


class CloudTests(Stubbed):
    def test_status_lists_oci_servers_and_rules_alike(self):
        # Live regression (14 Nov 2026): an OCI server entry (no `source`; this one never
        # got an instance) made `avpn cloud status` fail with KeyError: 'source'.
        inv = cloud.load_inventory()
        inv["resources"]["avpn-a1exit"] = dict(provider="oci", role="exit", port=4444, region="r", subnet="s")
        inv["resources"]["avpn-exit"] = dict(
            provider="oci", rule="advanced-vpn:avpn-exit", source="9.9.9.9/32", port=4444
        )
        cloud.save_inventory(inv)
        rows = {r["label"]: r["value"] for r in self.run_cli("status")["rows"]}
        self.assertEqual(rows["avpn-exit"], "oci advanced-vpn:avpn-exit 9.9.9.9/32:4444")
        self.assertEqual(rows["avpn-a1exit"], "oci exit (no instance):4444")

    def test_status_marks_servers_whose_keys_could_not_be_sealed(self):
        # Bug 9a: a host that fell back to plain keys says so wherever it is listed.
        inv = cloud.load_inventory()
        inv["resources"]["avpn-relay"] = dict(
            provider="aws", role="relay", instance="i-1", public_ip="16.0.0.9", key_protection="none"
        )
        inv["resources"]["avpn-exit"] = dict(
            provider="oci", rule="advanced-vpn:avpn-exit", source="9.9.9.9/32", port=4444, key_protection="systemd-creds"
        )  # fmt: skip
        cloud.save_inventory(inv)
        rows = {r["label"]: r["value"] for r in self.run_cli("status")["rows"]}
        self.assertIn("[PLAINTEXT KEYS]", rows["avpn-relay"])
        self.assertNotIn("[PLAINTEXT KEYS]", rows["avpn-exit"])

    def test_dry_run_plans_without_creating_anything(self):
        r = self.run_cli("aws", "relay", "--apply", "--dry-run", "--profile", "p", "--allow-from", "16.170.0.7")
        text = json.dumps(r["rows"])
        for expected in [
            "NitroTPM 2.0",
            "IMDSv2 only",
            "standard CPU credits",
            "udp 443 from 16.170.0.7/32",
            "FREE",
        ]:
            self.assertIn(expected, text)
        self.assertTrue(r["dry_run"])
        creating = {"copy-image", "register-image", "run-instances", "create-security-group", "import-key-pair"}
        self.assertFalse(creating & set(self.ops()))

    def test_new_aws_server_is_hardened_at_first_boot(self):
        import retention

        self.run_cli("aws", "relay", "--apply", "--yes", "--profile", "p", "--admin-ip", "18.0.0.4")
        ud = json.loads(self.state.read_text())["user_data"]
        self.assertEqual(ud, retention.cloud_init())
        for must in ("Storage=volatile", "tmpfs /var/log", "systemctl mask", "swapoff -a"):
            self.assertIn(must, ud)
        self.assertFalse(list(cloud.INVENTORY.parent.glob(".first-boot.*")), "user-data file left behind")

    def test_apply_creates_hardened_instance_open_only_to_previous_hop(self):
        r = self.run_cli(
            "aws",
            "relay",
            "--apply",
            "--yes",
            "--profile",
            "p",
            "--allow-from",
            "16.170.0.7",
            "--admin-ip",
            "18.0.0.4",
        )
        self.assertEqual(r["summary"], "created")
        copy = self.call_with("copy-image")
        self.assertEqual(self.value(copy, "--source-image-id"), "ami-new")
        self.assertIn("--encrypted", copy)
        reg = self.call_with("register-image")
        self.assertEqual(
            (self.value(reg, "--boot-mode"), self.value(reg, "--tpm-support"), self.value(reg, "--imds-support")),
            ("uefi", "v2.0", "v2.0"),
        )
        perms = json.loads(self.value(self.call_with("authorize-security-group-ingress"), "--ip-permissions"))
        opened = sorted((p["IpProtocol"], p["FromPort"], [r["CidrIp"] for r in p["IpRanges"]]) for p in perms)
        # A relay can be the first hop: the camouflage's TLS/TCP fallback needs TCP on the
        # same port (a path below 1448 bytes cannot carry its QUIC).
        self.assertEqual(
            opened, [("tcp", 22, ["18.0.0.4/32"]), ("tcp", 443, ["16.170.0.7/32"]), ("udp", 443, ["16.170.0.7/32"])]
        )
        run = self.call_with("run-instances")
        self.assertIn("HttpTokens=required", self.value(run, "--metadata-options"))
        self.assertEqual(self.value(run, "--credit-specification"), "CpuCredits=standard")
        disk = json.loads(self.value(run, "--block-device-mappings"))[0]["Ebs"]
        self.assertEqual((disk["Encrypted"], disk["VolumeType"], disk["DeleteOnTermination"]), (True, "gp3", True))
        for c in self.calls():
            if c[0] == "ec2" and "--tag-specifications" in c:
                for spec in json.loads(self.value(c, "--tag-specifications")):
                    tags = {t["Key"]: t["Value"] for t in spec["Tags"]}
                    self.assertEqual((tags["avpn:managed"], tags["avpn:name"]), ("true", "avpn-relay"), c[1])
        # The intermediate copy is deregistered; every call stays in the project's Region.
        self.assertIn(["ec2", "deregister-image", "--image-id", "ami-copy"], [c[:4] for c in self.calls()])
        self.assertTrue(all(self.value(c, "--region") == "eu-north-1" for c in self.calls() if c[0] == "ec2"))
        inv = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay"]
        self.assertEqual((inv["instance"], inv["public_ip"], inv["image"]), ("i-1", "16.0.0.9", "ami-tpm"))
        self.assertEqual(stat.S_IMODE(cloud.INVENTORY.stat().st_mode), 0o600)
        self.assertNotIn("PRIVATE", cloud.INVENTORY.read_text())

    def test_other_region_is_refused(self):
        with self.assertRaisesRegex(cloud.CloudError, "Region is eu-north-1"):
            self.run_cli(
                "aws",
                "relay",
                "--apply",
                "--dry-run",
                "--profile",
                "p",
                "--region",
                "us-east-1",
                "--allow-from",
                "16.170.0.7",
            )

    def test_apply_refuses_when_the_name_already_exists(self):
        self.set_state(dict(instances=[{"InstanceId": "i-9", "Tags": [{"Key": "Name", "Value": "avpn-relay"}]}]))
        with self.assertRaisesRegex(cloud.CloudError, "already exists"):
            self.run_cli(
                "aws",
                "relay",
                "--apply",
                "--yes",
                "--profile",
                "p",
                "--allow-from",
                "16.170.0.7",
                "--admin-ip",
                "18.0.0.4",
            )
        self.assertNotIn("run-instances", self.ops())

    def test_teardown_deletes_only_tagged_resources(self):
        self.set_state(
            dict(
                instances=[
                    {
                        "InstanceId": "i-1",
                        "Tags": [{"Key": "Name", "Value": "avpn-relay"}],
                        "State": {"Name": "running"},
                    }
                ],
                groups=[{"GroupId": "sg-1", "GroupName": "avpn-relay"}],
                keys=[{"KeyName": "avpn-relay", "KeyPairId": "key-1"}],
                images=[{"ImageId": "ami-tpm", "Name": "avpn-relay-nitrotpm"}],
                snapshots=[{"SnapshotId": "snap-1"}],
            )
        )
        r = self.run_cli("aws", "relay", "--teardown", "--yes", "--profile", "p")
        self.assertEqual(r["summary"], "deleted")
        for c in self.calls():
            if (
                c[0] == "ec2"
                and c[1].startswith("describe-")
                and c[1] not in ("describe-vpcs",)
                and "--instance-ids" not in c
            ):
                self.assertIn("Name=tag:avpn:managed,Values=true", c, c)
                # The server's own resources, or its admin endpoint's (avpn-relay-admin).
                self.assertTrue(
                    {"Name=tag:avpn:name,Values=avpn-relay", "Name=tag:avpn:name,Values=avpn-relay-admin"} & set(c), c
                )
        deleted = [
            c[1:4]
            for c in self.calls()
            if c[0] == "ec2" and c[1].split("-")[0] in ("terminate", "delete", "deregister")
        ]
        self.assertEqual(
            deleted,
            [
                ["terminate-instances", "--instance-ids", "i-1"],
                ["delete-security-group", "--group-id", "sg-1"],
                ["delete-key-pair", "--key-pair-id", "key-1"],
                ["deregister-image", "--image-id", "ami-tpm"],
                ["delete-snapshot", "--snapshot-id", "snap-1"],
            ],
        )

    def test_teardown_refuses_a_tagged_instance_not_named_avpn(self):
        self.set_state(dict(instances=[{"InstanceId": "i-7", "Tags": [{"Key": "Name", "Value": "other-team-worker"}]}]))
        with self.assertRaisesRegex(cloud.CloudError, "not named avpn"):
            self.run_cli("aws", "relay", "--teardown", "--yes", "--profile", "p")
        self.assertNotIn("terminate-instances", self.ops())

    def test_teardown_with_nothing_tagged_changes_nothing(self):
        r = self.run_cli("aws", "relay", "--teardown", "--yes", "--profile", "p")
        self.assertEqual(r["rows"][0]["label"], "nothing")
        self.assertFalse({"terminate-instances", "delete-security-group"} & set(self.ops()))

    def test_addresses_must_be_single_public_ipv4(self):
        for bad in ["10.0.0.1", "192.0.2.0/24", "2001:db8::1", "127.0.0.1", "nonsense"]:
            with self.assertRaises((cloud.CloudError, ValueError), msg=bad):
                cloud.single_ip(bad)
        self.assertEqual(cloud.single_ip("8.8.8.8"), "8.8.8.8/32")

    def test_names_are_constrained(self):
        for bad in ["relay", "avpn-", "avpn-Relay", "avpn-x;rm", "avpn-" + "x" * 40]:
            with self.assertRaises(cloud.CloudError, msg=bad):
                cloud.valid_name(bad)

    def test_expired_sign_in_says_how_to_fix_it(self):
        self.set_state(dict(expired=True))
        with self.assertRaisesRegex(cloud.CloudError, "aws login"):
            self.run_cli("aws", "relay", "--apply", "--dry-run", "--profile", "p", "--allow-from", "16.170.0.7")

    def test_json_mode_never_prompts(self):
        a = cloud.build_parser().parse_args(["--json", "aws", "relay", "--teardown", "--profile", "p"])
        with self.assertRaisesRegex(cloud.CloudError, "--yes"):
            cloud.confirm(a, "x")

    def test_root_is_refused(self):
        with mock.patch.object(cloud.os, "geteuid", lambda: 0), mock.patch("builtins.print") as p:
            self.assertEqual(cloud.main(["--json", "status"]), 1)
        self.assertIn("RunAsYourself", p.call_args[0][0])

    def oci_list(self):
        other = {"protocol": "6", "source": "10.0.0.0/16", "description": "ssh from vcn"}
        return {
            "display-name": "default",
            "ingress-security-rules": [other],
            "egress-security-rules": [{"protocol": "all"}],
        }

    def relay_group(self, tunnel=("16.170.0.7/32",), ssh=("18.0.0.4/32",), extra=None):
        perms = [
            dict(IpProtocol="udp", FromPort=41194, ToPort=41194, IpRanges=[dict(CidrIp=c) for c in tunnel]),
            dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[dict(CidrIp=c) for c in ssh]),
            dict(IpProtocol="tcp", FromPort=443, ToPort=443, IpRanges=[dict(CidrIp="16.1.1.1/32")]),
        ]
        if extra:
            perms[0].update(extra)
        return dict(GroupId="sg-r", GroupName="avpn-relay", IpPermissions=perms)

    def opened(self):
        g = json.loads(self.state.read_text())["groups"][0]
        return {
            (p["IpProtocol"], p["FromPort"]): sorted(r["CidrIp"] for r in p.get("IpRanges", []))
            for p in g["IpPermissions"]
        }

    def test_aws_allow_replaces_sources_exactly_and_keeps_other_rules(self):
        self.set_state(dict(groups=[self.relay_group(tunnel=("16.170.0.7/32", "16.170.0.8/32"))]))
        cloud.save_inventory(dict(schema=1, resources={"avpn-relay": dict(provider="aws", instance="i-1")}))
        r = self.run_cli(
            "aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "31.13.0.5", "--admin-ip", "31.13.0.5"
        )
        self.assertEqual(r["summary"], "applied")
        self.assertEqual(
            self.opened(),
            {("udp", 41194): ["31.13.0.5/32"], ("tcp", 22): ["31.13.0.5/32"], ("tcp", 443): ["16.1.1.1/32"]},
        )
        # New sources are opened before old ones are closed, so a live chain never has a gap.
        self.assertEqual(
            [o for o in self.ops() if "security-group-ingress" in o],
            ["authorize-security-group-ingress", "revoke-security-group-ingress"],
        )
        text = json.dumps(r["rows"])
        self.assertIn("udp 41194 from 31.13.0.5/32 (was 16.170.0.7/32, 16.170.0.8/32)", text)
        inv = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay"]
        self.assertEqual((inv["allow_from"], inv["admin_ip"]), (["31.13.0.5/32"], "31.13.0.5/32"))
        # Applying the same addresses again changes nothing.
        before = len(self.ops())
        again = self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "31.13.0.5")
        self.assertEqual(again["rows"][0]["label"], "nothing")
        self.assertEqual([o for o in self.ops()[before:] if "security-group-ingress" in o], [])

    def relay_with_instance(self):
        self.set_state(dict(
            groups=[self.relay_group(tunnel=("0.0.0.0/0",), ssh=("31.13.0.5/32",))],
            instances=[dict(InstanceId="i-1", SubnetId="subnet-1", VpcId="vpc-1", PublicIpAddress="16.0.0.9",
                            Tags=[dict(Key="Name", Value="avpn-relay")])],
        ))  # fmt: skip
        cloud.save_inventory(dict(schema=1, resources={"avpn-relay": dict(
            provider="aws", instance="i-1", profile="p", region="eu-north-1", public_ip="16.0.0.9",
            admin_ip="31.13.0.5/32", role="relay", first_hop=True)}))  # fmt: skip

    def test_admin_endpoint_replaces_every_ssh_address_with_the_endpoint_group(self):
        self.relay_with_instance()
        r = self.run_cli("aws", "admin-endpoint", "--apply", "--yes", "--profile", "p")
        self.assertEqual(r["summary"], "applied")
        state = json.loads(self.state.read_text())
        ssh = [q for q in state["groups"][0]["IpPermissions"] if q["FromPort"] == 22]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0]["IpRanges"], [])  # no address at all
        self.assertEqual([p["GroupId"] for p in ssh[0]["UserIdGroupPairs"]], ["sg-admin"])
        # The endpoint's group: no inbound, outbound SSH to the server's group only.
        admin = state["admin_groups"][0]
        self.assertEqual(admin["IpPermissions"], [])
        self.assertEqual(admin["IpPermissionsEgress"],
                         [dict(IpProtocol="tcp", FromPort=22, ToPort=22, UserIdGroupPairs=[dict(GroupId="sg-r")])])  # fmt: skip
        self.assertEqual(state["endpoint"]["SubnetId"], "subnet-1")
        # The endpoint is admitted before the address is closed: no window without SSH.
        ops = [o for o in self.ops() if "security-group-ingress" in o]
        self.assertEqual(ops, ["authorize-security-group-ingress", "revoke-security-group-ingress"])
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay"]
        self.assertEqual(rec["admin"], dict(via="eice", endpoint="eice-1", group="sg-admin", instance="i-1"))
        self.assertNotIn("admin_ip", rec)
        # SSH from this tool now goes through the endpoint, keyed to the instance.
        base = cloud.ssh_base("avpn-relay", rec)
        self.assertIn("HostKeyAlias=16.0.0.9", base)
        proxy = next(o for o in base if o.startswith("ProxyCommand="))
        self.assertIn("ec2-instance-connect open-tunnel --instance-id i-1 --profile p --region eu-north-1", proxy)
        self.assertEqual(cloud.ssh_target(rec), "admin@i-1")
        # chain's firewall step leaves the endpoint's SSH rule alone ...
        cloud.set_firewall("avpn-relay", rec, 41194, ["0.0.0.0/0"], ["9.9.9.9/32"])
        ssh = [q for q in json.loads(self.state.read_text())["groups"][0]["IpPermissions"] if q["FromPort"] == 22]
        self.assertEqual((ssh[0]["IpRanges"], [p["GroupId"] for p in ssh[0]["UserIdGroupPairs"]]), ([], ["sg-admin"]))
        # ... and aws allow refuses to pin an address again.
        with self.assertRaisesRegex(cloud.CloudError, "Instance Connect Endpoint"):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--admin-ip", "31.13.0.6")
        # A second run reuses the endpoint and changes nothing.
        before = [o for o in self.ops() if o.startswith("create-")]
        self.run_cli("aws", "admin-endpoint", "--apply", "--yes", "--profile", "p")
        self.assertEqual([o for o in self.ops() if o.startswith("create-")], before)

    def test_teardown_removes_the_endpoint_and_its_group_in_an_order_aws_accepts(self):
        self.relay_with_instance()
        self.run_cli("aws", "admin-endpoint", "--apply", "--yes", "--profile", "p")
        self.run_cli("aws", "relay", "--teardown", "--yes", "--profile", "p")
        ops = self.ops()
        tail = ops[ops.index("terminate-instances") :]
        order = [
            o
            for o in tail
            if o in ("delete-instance-connect-endpoint", "revoke-security-group-egress", "delete-security-group")
        ]
        self.assertEqual(order[0], "delete-instance-connect-endpoint")
        self.assertLess(order.index("revoke-security-group-egress"), order.index("delete-security-group"))
        self.assertEqual(order.count("delete-security-group"), 2)  # the server's group, then the endpoint's

    def test_aws_allow_changes_only_what_is_asked(self):
        self.set_state(dict(groups=[self.relay_group()]))
        self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--admin-ip", "31.13.0.6")
        self.assertEqual(self.opened()[("udp", 41194)], ["16.170.0.7/32"])
        self.assertEqual(self.opened()[("tcp", 22)], ["31.13.0.6/32"])

    def test_aws_allow_removes_ipv6_and_other_sources_on_the_tunnel(self):
        extra = dict(Ipv6Ranges=[dict(CidrIpv6="::/0")], PrefixListIds=[dict(PrefixListId="pl-1")])
        self.set_state(dict(groups=[self.relay_group(extra=extra)]))
        r = self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "16.170.0.7")
        tunnel = next(
            p for p in json.loads(self.state.read_text())["groups"][0]["IpPermissions"] if p["FromPort"] == 41194
        )
        self.assertEqual((tunnel.get("Ipv6Ranges"), tunnel.get("PrefixListIds")), ([], []))
        self.assertIn("2 non-IPv4 source(s)", json.dumps(r["rows"]))

    def tunnel_rule(self, perms):
        return next(p for p in perms if p["IpProtocol"] == "udp")

    def test_first_hop_is_open_to_any_by_default_and_names_no_client(self):
        r = self.run_cli("aws", "relay", "--apply", "--yes", "--profile", "p", "--admin-ip", "18.0.0.4")
        perms = json.loads(self.value(self.call_with("authorize-security-group-ingress"), "--ip-permissions"))
        self.assertEqual([x["CidrIp"] for x in self.tunnel_rule(perms)["IpRanges"]], ["0.0.0.0/0"])
        # The only address in the provider's configuration is the admin one asked for.
        sources = {x["CidrIp"] for p in perms for x in p["IpRanges"]}
        self.assertEqual(sources, {"0.0.0.0/0", "18.0.0.4/32"})
        self.assertEqual(r["summary"], "created")

    def test_only_a_first_hop_may_be_open_to_any(self):
        with self.assertRaisesRegex(cloud.CloudError, "only the first hop"):
            self.run_cli(
                "aws", "relay", "--apply", "--dry-run", "--profile", "p", "--role", "exit", "--allow-from", "any"
            )
        with self.assertRaisesRegex(cloud.CloudError, "previous server"):
            self.run_cli("aws", "relay", "--apply", "--dry-run", "--profile", "p", "--role", "exit")
        with self.assertRaisesRegex(cloud.CloudError, "give it alone"):
            self.run_cli(
                "aws",
                "relay",
                "--apply",
                "--dry-run",
                "--profile",
                "p",
                "--allow-from",
                "any",
                "--allow-from",
                "16.1.1.1",
            )

    def test_aws_allow_any_only_on_a_relay(self):
        relay = dict(
            InstanceId="i-1", Tags=[dict(Key="avpn:role", Value="relay"), dict(Key="Name", Value="avpn-relay")]
        )
        self.set_state(dict(groups=[self.relay_group()], instances=[relay]))
        self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "any")
        self.assertEqual(self.opened()[("udp", 41194)], ["0.0.0.0/0"])
        relay["Tags"][0]["Value"] = "exit"
        self.set_state(dict(groups=[self.relay_group()], instances=[relay]))
        with self.assertRaisesRegex(cloud.CloudError, "only the first hop"):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "any")

    def test_plans_say_which_address_the_provider_records(self):
        r = self.run_cli("aws", "relay", "--apply", "--dry-run", "--profile", "p", "--admin-ip", "18.0.0.4")
        note = next(x["value"] for x in r["rows"] if x["label"] == "caller")
        self.assertIn("16.9.9.9, this machine's address", note)
        self.assertIn("CloudTrail", note)
        cloud.save_inventory(dict(schema=1, resources={"avpn-exit": dict(provider="ssh", public_ip="16.9.9.9")}))
        r = self.run_cli("aws", "relay", "--apply", "--dry-run", "--profile", "p", "--admin-ip", "18.0.0.4")
        note = next(x["value"] for x in r["rows"] if x["label"] == "caller")
        self.assertIn("avpn-exit, through your chain", note)

    def test_aws_allow_dry_run_and_refusals(self):
        self.set_state(dict(groups=[self.relay_group()]))
        r = self.run_cli("aws", "allow", "--apply", "--dry-run", "--profile", "p", "--allow-from", "31.13.0.5")
        self.assertTrue(r["dry_run"])
        self.assertEqual([o for o in self.ops() if "security-group-ingress" in o], [])
        with self.assertRaisesRegex(cloud.CloudError, "nothing to change"):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p")
        with self.assertRaisesRegex(cloud.CloudError, "not a public IPv4"):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "10.0.0.1")
        with self.assertRaises(ValueError):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--admin-ip", "0.0.0.0/0")
        self.set_state({})
        with self.assertRaisesRegex(cloud.CloudError, "expected one security group"):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "31.13.0.5")
        two = self.relay_group()
        two["IpPermissions"].append(dict(IpProtocol="udp", FromPort=53, ToPort=53, IpRanges=[]))
        self.set_state(dict(groups=[two]))
        with self.assertRaisesRegex(cloud.CloudError, "cannot tell which is the tunnel"):
            self.run_cli("aws", "allow", "--apply", "--yes", "--profile", "p", "--allow-from", "31.13.0.5")
        self.assertEqual([o for o in self.ops() if "security-group-ingress" in o], [])

    def test_oci_allow_adds_one_tagged_rule_and_keeps_the_rest(self):
        self.set_state(dict(security_list=self.oci_list()))
        self.run_cli(
            "oci",
            "allow",
            "--apply",
            "--yes",
            "--name",
            "avpn-exit",
            "--security-list",
            "ocid1.x",
            "--allow-from",
            "16.0.0.9",
        )
        ingress = json.loads(self.state.read_text())["security_list"]["ingress-security-rules"]
        self.assertEqual(ingress[0]["description"], "ssh from vcn")
        self.assertEqual(
            (ingress[1]["source"], ingress[1]["protocol"], ingress[1]["udpOptions"]["destinationPortRange"]),
            ("16.0.0.9/32", "17", {"min": 4444, "max": 4444}),
        )
        # Re-applying replaces, never duplicates; teardown removes only the tagged rule.
        self.run_cli(
            "oci",
            "allow",
            "--apply",
            "--yes",
            "--name",
            "avpn-exit",
            "--security-list",
            "ocid1.x",
            "--allow-from",
            "16.0.0.10",
        )
        ingress = json.loads(self.state.read_text())["security_list"]["ingress-security-rules"]
        self.assertEqual([r["source"] for r in ingress], ["10.0.0.0/16", "16.0.0.10/32"])
        self.run_cli("oci", "allow", "--teardown", "--yes", "--name", "avpn-exit", "--security-list", "ocid1.x")
        ingress = json.loads(self.state.read_text())["security_list"]["ingress-security-rules"]
        self.assertEqual([r["description"] for r in ingress], ["ssh from vcn"])


class OciServerTests(Stubbed):
    def setUp(self):
        super().setUp()
        cfg = Path(self.tmp.name) / "oci-config"
        cfg.write_text("[DEFAULT]\ntenancy=ocid1.tenancy.oc1..t\nregion=eu-stockholm-1\nuser=u\n")
        self.cfg = mock.patch.dict(os.environ, OCI_CLI_CONFIG_FILE=str(cfg))
        self.cfg.start()
        self.keygen = mock.patch.object(cloud.subprocess, "run", self.fake_keygen)
        self.keygen.start()

    def tearDown(self):
        self.keygen.stop()
        self.cfg.stop()
        super().tearDown()

    real_run = staticmethod(cloud.subprocess.run)

    def fake_keygen(self, argv, *k, **kw):
        if "ssh-keygen" in str(argv[0]):
            key = Path(argv[argv.index("-f") + 1])
            key.write_text("PRIVATE")
            Path(str(key) + ".pub").write_text("ssh-ed25519 AAAA test")
            return None
        return self.real_run(argv, *k, **kw)

    def oci_calls(self):
        return [c for c in self.calls() if c and c[0] in ("iam", "compute", "network")]

    def oci_call(self, *prefix):
        return next(c for c in self.oci_calls() if c[: len(prefix)] == list(prefix))

    def test_plan_uses_the_home_region_a_shape_offering_ad_and_a_full_ubuntu(self):
        r = self.run_cli("oci", "server", "--apply", "--dry-run", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")
        text = json.dumps(r["rows"])
        for expected in ["home region eu-stockholm-1", "VM.Standard.E2.1.Micro", "AD-2", "Canonical-Ubuntu-24.04-2026",
                         "udp 4444 from 16.0.0.9/32", "Always Free", "OCI Audit"]:  # fmt: skip
            self.assertIn(expected, text)
        self.assertFalse([c for c in self.oci_calls() if c[2:3] in (["create"], ["launch"])])

    def test_other_region_is_refused(self):
        Path(os.environ["OCI_CLI_CONFIG_FILE"]).write_text(
            "[DEFAULT]\ntenancy=ocid1.tenancy.oc1..t\nregion=eu-frankfurt-1\n"
        )
        with self.assertRaisesRegex(cloud.CloudError, "only in the home region eu-stockholm-1"):
            self.run_cli("oci", "server", "--apply", "--dry-run", "--allow-from", "16.0.0.9")

    def test_an_a1_server_beyond_always_free_is_refused(self):
        with self.assertRaisesRegex(cloud.CloudError, "at most 2 OCPU and 12 GB"):
            self.run_cli("oci", "server", "--apply", "--dry-run", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4",
                         "--shape", "arm", "--ocpus", "4", "--memory-gib", "24")  # fmt: skip
        r = self.run_cli("oci", "server", "--apply", "--dry-run", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4",
                         "--shape", "arm", "--ocpus", "2", "--memory-gib", "12")  # fmt: skip
        self.assertIn("2 OCPU / 12 GB", json.dumps(r))

    def test_new_oci_server_is_hardened_at_first_boot(self):
        import retention

        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")
        ud = json.loads(self.state.read_text())["oci_user_data"]
        self.assertEqual(ud, retention.cloud_init())
        self.assertFalse(list(cloud.INVENTORY.parent.glob(".first-boot.*")), "user-data file left behind")

    def test_apply_creates_a_tagged_network_and_server_open_only_as_asked(self):
        r = self.run_cli("oci", "server", "--apply", "--yes", "--role", "relay", "--name", "avpn-relay2",
                         "--admin-ip", "18.0.0.4")  # fmt: skip
        self.assertEqual(r["summary"], "created")
        for c in self.oci_calls():
            if c[2] in ("create", "launch"):
                tags = json.loads(c[c.index("--freeform-tags") + 1])
                self.assertEqual(tags, {"avpn-managed": "true", "avpn-name": "avpn-relay2"}, c[:3])
                self.assertEqual(c[c.index("--compartment-id") + 1], "ocid1.tenancy.oc1..t")
            self.assertEqual(c[c.index("--region") + 1], "eu-stockholm-1")
        sl = self.oci_call("network", "security-list", "create")
        ingress = json.loads(sl[sl.index("--ingress-security-rules") + 1])
        self.assertEqual(
            # A relay is a first hop: its port also on TCP (the camouflage's TLS fallback).
            sorted((x["protocol"], x["source"]) for x in ingress),
            [("17", "0.0.0.0/0"), ("6", "0.0.0.0/0"), ("6", "18.0.0.4/32")],
        )
        launch = self.oci_call("compute", "instance", "launch")
        self.assertEqual(launch[launch.index("--image-id") + 1], "ocid1.image.full")
        self.assertEqual(launch[launch.index("--availability-domain") + 1], "AD-2")
        self.assertTrue(json.loads(launch[launch.index("--instance-options") + 1])["areLegacyImdsEndpointsDisabled"])
        route = self.oci_call("network", "route-table", "update")
        self.assertEqual(json.loads(route[route.index("--route-rules") + 1])[0]["networkEntityId"], "ocid1.igw.1")
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay2"]
        self.assertEqual(
            (rec["public_ip"], rec["instance"], rec["ssh_user"]), ("16.20.0.5", "ocid1.instance.1", "ubuntu")
        )
        self.assertTrue(rec["managed_list"] and rec["first_hop"])
        self.assertNotIn("PRIVATE", cloud.INVENTORY.read_text())

    def test_a_server_in_a_shared_vcn_creates_and_removes_only_its_own_parts(self):
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4",
                     "--vcn", "ocid1.vcn.shared")  # fmt: skip
        made = [c[:3] for c in self.oci_calls() if c[2] == "create"]
        self.assertNotIn(["network", "vcn", "create"], made)
        self.assertNotIn(["network", "internet-gateway", "create"], made)
        subnet = self.oci_call("network", "subnet", "create")
        self.assertEqual(subnet[subnet.index("--cidr-block") + 1], "10.0.254.0/24")  # free, inside, no overlap
        self.assertEqual(subnet[subnet.index("--route-table-id") + 1], "ocid1.rt.own")
        rt = self.oci_call("network", "route-table", "create")
        self.assertEqual(json.loads(rt[rt.index("--route-rules") + 1])[0]["networkEntityId"], "ocid1.igw.shared")
        state = json.loads(self.state.read_text())
        state["oci_ops"] = []
        self.state.write_text(json.dumps(state))
        self.run_cli("oci", "server", "--teardown", "--yes")
        deleting = [c[:3] for c in self.oci_calls() if c[2] in ("delete", "terminate")]
        self.assertEqual(
            deleting,
            [["compute", "instance", "terminate"], ["network", "subnet", "delete"], ["network", "route-table", "delete"],
             ["network", "security-list", "delete"]],
        )  # fmt: skip

    def test_a_server_behind_the_bastion_has_no_ssh_address_rule(self):
        # Owner, 20 Nov 2026: an SSH rule for one address breaks behind a VPN. With --bastion
        # the server goes in the bastion's VCN, admits SSH only from its private endpoint,
        # runs the Bastion plugin, and is reached through renewed sessions.
        state = json.loads(self.state.read_text())
        state["oci_bastions"] = {"c": [{"id": "ocid1.bastion.b", "target-vcn-id": "ocid1.vcn.shared",
                                        "private-endpoint-ip-address": "10.0.0.159"}]}  # fmt: skip
        self.state.write_text(json.dumps(state))
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--bastion", "ocid1.bastion.b")
        subnet = self.oci_call("network", "subnet", "create")
        self.assertEqual(subnet[subnet.index("--vcn-id") + 1], "ocid1.vcn.shared")  # the bastion's VCN
        sl = self.oci_call("network", "security-list", "create")
        ingress = json.loads(sl[sl.index("--ingress-security-rules") + 1])
        ssh = [r["source"] for r in ingress if r.get("tcpOptions", {}).get("destinationPortRange", {}).get("min") == 22]
        self.assertEqual(ssh, ["10.0.0.159/32"])
        launch = self.oci_call("compute", "instance", "launch")
        plugins = json.loads(launch[launch.index("--agent-config") + 1])["pluginsConfig"]
        self.assertIn({"name": "Bastion", "desiredState": "ENABLED"}, plugins)
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]
        self.assertEqual(rec["bastion"]["id"], "ocid1.bastion.b")
        self.assertEqual(rec["bastion"]["host"], "avpn-exit-bastion")
        self.assertEqual(rec["ssh"], "ubuntu@avpn-exit")
        config = Path(rec["ssh_config"]).read_text()
        self.assertIn("ProxyJump avpn-exit-bastion", config)
        self.assertEqual(cloud.ssh_config_user(rec["ssh_config"], "avpn-exit-bastion"), "PENDING")
        self.assertEqual(oct(Path(rec["ssh_config"]).stat().st_mode & 0o777), "0o600")
        with self.assertRaisesRegex(cloud.CloudError, "bastion's VCN"):
            self.run_cli("oci", "server", "--apply", "--yes", "--name", "avpn-other", "--allow-from", "16.0.0.9",
                         "--bastion", "ocid1.bastion.b", "--vcn", "ocid1.vcn.elsewhere")  # fmt: skip

    def capacity(self, fails):
        state = json.loads(self.state.read_text())
        state["capacity_fail"] = fails
        self.state.write_text(json.dumps(state))

    def test_a_launch_without_capacity_keeps_its_network_and_a_second_apply_resumes(self):
        # Live, 20 Nov 2026: Always Free A1 in me-dubai-1 answered "Out of host capacity".
        self.capacity(1)
        with self.assertRaisesRegex(cloud.CloudError, "no free capacity .* network is kept"):
            self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]
        self.assertTrue(rec.get("subnet") and not rec.get("instance"))
        made_before = [c[:3] for c in self.oci_calls() if c[2] == "create"]
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")
        made_after = [c[:3] for c in self.oci_calls() if c[2] == "create"]
        self.assertEqual(made_after, made_before)  # no second network
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]
        self.assertEqual(rec["instance"], "ocid1.instance.1")
        self.assertEqual(rec["public_ip"], "16.20.0.5")
        with self.assertRaisesRegex(cloud.CloudError, "already recorded"):  # a complete server is not relaunched
            self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")

    def test_rate_limiting_is_waited_out_too(self):
        state = json.loads(self.state.read_text())
        state.update(capacity_fail=1, rate_limited=True)
        self.state.write_text(json.dumps(state))
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4",
                     "--wait-capacity", "10")  # fmt: skip
        self.assertEqual(len(json.loads(self.state.read_text())["launch_attempts"]), 2)

    def test_wait_capacity_retries_across_fault_domains(self):
        self.capacity(2)
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4",
                     "--wait-capacity", "10")  # fmt: skip
        attempts = json.loads(self.state.read_text())["launch_attempts"]
        self.assertEqual(len(attempts), 3)
        domains = [a[a.index("--fault-domain") + 1] if "--fault-domain" in a else None for a in attempts]
        self.assertEqual(domains, [None, "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"])
        self.assertTrue(json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]["instance"])

    def test_teardown_deletes_recorded_parts_in_order_and_checks_tags(self):
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")
        state = json.loads(self.state.read_text())
        state["oci_ops"] = []
        self.state.write_text(json.dumps(state))
        self.run_cli("oci", "server", "--teardown", "--yes")
        deleting = [c[:3] for c in self.oci_calls() if c[2] in ("delete", "terminate")]
        self.assertEqual(
            deleting,
            [["compute", "instance", "terminate"], ["network", "subnet", "delete"], ["network", "security-list", "delete"],
             ["network", "internet-gateway", "delete"], ["network", "vcn", "delete"]],
        )  # fmt: skip
        self.assertNotIn("avpn-exit", json.loads(cloud.INVENTORY.read_text())["resources"])

    def test_teardown_refuses_resources_without_its_tags(self):
        self.run_cli("oci", "server", "--apply", "--yes", "--allow-from", "16.0.0.9", "--admin-ip", "18.0.0.4")
        state = json.loads(self.state.read_text())
        state["oci_tags"] = {"avpn-managed": "true", "avpn-name": "someone-else"}
        self.state.write_text(json.dumps(state))
        with self.assertRaisesRegex(cloud.CloudError, "not tagged avpn-name=avpn-exit"):
            self.run_cli("oci", "server", "--teardown", "--yes")
        self.assertFalse([c for c in self.oci_calls() if c[2] in ("delete", "terminate")])


class AuditTests(Stubbed):
    def setUp(self):
        super().setUp()
        cfg = Path(self.tmp.name) / "oci-config"
        cfg.write_text("[DEFAULT]\ntenancy=ocid1.tenancy.oc1..t\nregion=eu-stockholm-1\nuser=u\n")
        self.cfg = mock.patch.dict(os.environ, OCI_CLI_CONFIG_FILE=str(cfg))
        self.cfg.start()
        cloud.save_inventory(
            dict(schema=1, resources={
                "avpn-relay": dict(provider="aws", profile="p", region="eu-north-1", public_ip="13.0.0.1", ssh_key="k"),
                "avpn-exit": dict(provider="ssh", catalog="oci", public_ip="16.40.0.2", ssh="u@16.40.0.2", ssh_key="k"),
            })
        )  # fmt: skip
        sg = dict(GroupId="sg-r", GroupName="avpn-relay", IpPermissions=[
            dict(IpProtocol="udp", FromPort=41194, ToPort=41194, IpRanges=[dict(CidrIp="0.0.0.0/0")]),
            dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[dict(CidrIp="16.40.0.2/32")])])  # fmt: skip
        self.base = dict(groups=[sg], oci_bastions={"ocid1.tenancy.oc1..t": [
            dict(id="b1", name="bastion", **{"client-cidr-block-allow-list": ["13.0.0.1/32", "16.40.0.2/32"]})]})  # fmt: skip

    def tearDown(self):
        self.cfg.stop()
        super().tearDown()

    def audit(self, **state):
        self.set_state(dict(self.base, **state))
        r = self.run_cli("audit")
        return r, {row["label"]: row["value"] for row in r["rows"]}

    def test_a_clean_account_has_no_findings_but_states_the_always_on_logs(self):
        events = [
            dict(CloudTrailEvent=json.dumps(dict(sourceIPAddress=ip)))
            for ip in ("31.13.0.5", "31.13.0.5", "ec2.amazonaws.com")
        ]
        r, rows = self.audit(audit={"cloudtrail lookup-events": {"Events": events}})
        self.assertEqual((r["findings"], r["summary"]), (0, "no opt-in logging found"))
        self.assertIn("90 days", rows["aws always on"])
        self.assertIn("1 caller addresses", rows["aws always on"])
        self.assertIn("365 days", rows["oci always on"])
        self.assertEqual(rows["aws firewall avpn-relay"], "only any-address and your servers")
        self.assertFalse([v for v in rows.values() if v.startswith("FOUND")])

    def test_opt_in_logging_and_foreign_addresses_are_found(self):
        sg = json.loads(json.dumps(self.base["groups"][0]))
        sg["IpPermissions"][1]["IpRanges"].append(dict(CidrIp="31.13.0.5/32"))
        bastion = dict(id="b1", name="bastion", **{"client-cidr-block-allow-list": ["31.13.0.5/32"]})
        r, rows = self.audit(
            groups=[sg],
            audit={
                "ec2 describe-flow-logs": {"FlowLogs": [dict(FlowLogId="fl-1", ResourceId="vpc-1")]},
                "cloudtrail describe-trails": {"trailList": [dict(Name="org-trail")]},
                "logs describe-log-groups us-east-1": {"logGroups": [dict(logGroupName="/aws/x")]},
                "configservice describe-configuration-recorder-status": {"ConfigurationRecordersStatus": [dict(name="default", recording=True)]},
            },
            oci_bastions={"ocid1.tenancy.oc1..t": [bastion]},
            oci_log_groups={"ocid1.tenancy.oc1..t": [dict(id="g1", **{"display-name": "net"})]},
            oci_logs={"g1": [{"display-name": "vcn-flows", "configuration": {"source": {"service": "flowlogs"}}}]},
        )  # fmt: skip
        for label in ("aws vpc flow logs", "aws trails", "aws log groups", "aws config recording",
                      "aws firewall avpn-relay", "oci bastions", "oci flow logs"):  # fmt: skip
            self.assertTrue(rows[label].startswith("FOUND"), (label, rows[label]))
        self.assertIn("31.13.0.5/32", rows["aws firewall avpn-relay"])
        self.assertEqual(r["findings"], 7)
        self.assertEqual(r["summary"], "7 finding(s)")

    def test_a_shared_security_list_is_judged_only_by_its_own_rule(self):
        inv = cloud.load_inventory()
        inv["resources"]["avpn-oci-rule"] = dict(
            provider="oci", security_list="ocid1.sl", rule="advanced-vpn:avpn-oci-rule"
        )
        cloud.save_inventory(inv)
        others = [
            dict(source="10.0.0.0/16", description="ssh from vcn"),
            dict(source="31.13.0.9/32", description="someone's"),
        ]
        ours = dict(source="13.0.0.1/32", description="advanced-vpn:avpn-oci-rule")
        r, rows = self.audit(security_list={"ingress-security-rules": others + [ours]})
        self.assertEqual(rows["oci firewall avpn-oci-rule"], "only any-address and your servers")
        r, rows = self.audit(security_list={"ingress-security-rules": others + [dict(ours, source="31.13.0.5/32")]})
        self.assertIn("31.13.0.5/32", rows["oci firewall avpn-oci-rule"])
        self.assertNotIn("10.0.0.0/16", rows["oci firewall avpn-oci-rule"])

    def test_what_cannot_be_read_is_reported_not_counted_clean(self):
        r, rows = self.audit(audit={"guardduty list-detectors": "DENIED"})
        self.assertIn("cannot check", rows["aws guardduty"])
        self.assertEqual(r["findings"], 0)
        r, rows = self.audit(audit={"guardduty list-detectors": {"DetectorIds": ["d1"]}})
        self.assertTrue(rows["aws guardduty"].startswith("FOUND"))


class BastionTests(Stubbed):
    """An OCI bastion session lasts at most 3 hours; a server behind one must stay reachable
    (`cloud unlock` after a reboot), so the session is renewed when it is gone or ending."""

    def setUp(self):
        super().setUp()
        d = Path(self.tmp.name)
        cfg = d / "oci-config"
        cfg.write_text("[DEFAULT]\ntenancy=ocid1.tenancy.t\nregion=me-dubai-1\n")
        self.cfg = mock.patch.dict(os.environ, OCI_CLI_CONFIG_FILE=str(cfg), AVPN_SSH=str(d / "ssh"), STUB_DIR=str(d))
        self.cfg.start()
        (d / "ssh").write_text(SSH_STUB)
        (d / "ssh").chmod(0o755)
        self.ssh_config = d / "exit.conf"
        self.ssh_config.write_text(
            "Host avpn-bastion\n  HostName host.bastion.example\n  User ocid1.bastionsession.old\n"
            "Host avpn-exit\n  HostName 10.0.1.88\n  User ubuntu\n  ProxyJump avpn-bastion\n"
        )
        (d / "k.pub").write_text("ssh-ed25519 AAAA")
        cloud._bastion_fresh.clear()
        cloud.save_inventory(dict(schema=1, resources={"avpn-exit": dict(
            provider="ssh", public_ip="16.40.0.2", ssh="ubuntu@avpn-exit", ssh_config=str(self.ssh_config),
            ssh_key=str(d / "k"), role="exit",
            bastion=dict(id="ocid1.bastion.b", instance="ocid1.instance.i", user="ubuntu", host="avpn-bastion",
                         public_key=str(d / "k.pub"), oci_profile="DEFAULT"))}))  # fmt: skip
        self.now = 1_800_000_000

    def tearDown(self):
        self.cfg.stop()
        super().tearDown()

    def session(self, age_minutes, state="ACTIVE"):
        created = datetime.datetime.fromtimestamp(self.now - age_minutes * 60, datetime.timezone.utc)
        self.set_state(dict(oci_sessions={"ocid1.bastionsession.old": {
            "lifecycle-state": state, "time-created": created.isoformat(), "session-ttl-in-seconds": 10800}}))  # fmt: skip

    def ensure(self):
        rec = cloud.load_inventory()["resources"]["avpn-exit"]
        cloud.ensure_bastion("avpn-exit", rec, now=self.now)
        return json.loads(self.state.read_text()).get("oci_created_sessions", [])

    def test_a_fresh_session_is_kept(self):
        self.session(age_minutes=30)
        self.assertEqual(self.ensure(), [])
        self.assertEqual(cloud.ssh_config_user(self.ssh_config, "avpn-bastion"), "ocid1.bastionsession.old")

    def test_an_expired_or_ending_or_deleted_session_is_replaced_and_the_config_updated(self):
        for age, state in ((181, "ACTIVE"), (170, "ACTIVE"), (30, "DELETED")):
            with self.subTest(age=age, state=state):
                cloud._bastion_fresh.clear()
                cloud.set_ssh_config_user(self.ssh_config, "avpn-bastion", "ocid1.bastionsession.old")
                self.session(age_minutes=age, state=state)
                made = self.ensure()
                self.assertEqual(len(made), 1)
                argv = made[0]
                for flag, value in (("--bastion-id", "ocid1.bastion.b"), ("--target-resource-id", "ocid1.instance.i"),
                                    ("--target-os-username", "ubuntu"), ("--session-ttl", "10800")):  # fmt: skip
                    self.assertEqual(argv[argv.index(flag) + 1], value)
                self.assertEqual(cloud.ssh_config_user(self.ssh_config, "avpn-bastion"), "ocid1.bastionsession.new1")
                self.assertEqual(cloud.ssh_config_user(self.ssh_config, "avpn-exit"), "ubuntu")  # untouched
                self.assertEqual(oct(self.ssh_config.stat().st_mode & 0o777), "0o600")
        # Cached connections for the old session are closed.
        self.assertIn("-O exit avpn-bastion", (Path(self.tmp.name) / "log.ssh").read_text())

    def test_it_runs_once_per_command_and_through_remote(self):
        self.session(age_minutes=200)
        rec = cloud.load_inventory()["resources"]["avpn-exit"]
        with mock.patch.object(cloud.time, "time", lambda: self.now):
            cloud.remote("avpn-exit", rec)
            cloud.remote("avpn-exit", rec)
        self.assertEqual(len(json.loads(self.state.read_text())["oci_created_sessions"]), 1)

    def test_host_bastion_checks_what_it_records(self):
        d = Path(self.tmp.name)
        self.session(age_minutes=30)
        base = ["host", "bastion", "--name", "avpn-exit", "--host", "avpn-bastion", "--public-key", str(d / "k.pub")]
        with self.assertRaisesRegex(cloud.CloudError, "bastion OCID"):
            self.run_cli(*base, "--bastion-id", "ocid1.instance.x", "--instance-id", "ocid1.instance.i")
        with self.assertRaisesRegex(cloud.CloudError, "no Host nope"):
            self.run_cli("host", "bastion", "--name", "avpn-exit", "--host", "nope", "--public-key", str(d / "k.pub"),
                         "--bastion-id", "ocid1.bastion.b", "--instance-id", "ocid1.instance.i")  # fmt: skip
        r = self.run_cli(*base, "--bastion-id", "ocid1.bastion.b", "--instance-id", "ocid1.instance.i")
        self.assertEqual(r["summary"], "recorded")


class HealthTests(unittest.TestCase):
    """`avpn cloud health` (owner, 20 Nov 2026): a stopped, reclaimed, locked or unreachable
    server, and an account running out, must be obvious, with the fix."""

    def run_health(self, ssh_line="active=active mode=operator unlocked=1", oci_state="RUNNING", plan=None,
                   ssh_error=None):  # fmt: skip
        inv = dict(schema=1, chain=dict(hops=["avpn-relay", "avpn-exit"]), resources={
            "avpn-relay": dict(provider="aws", profile="p", region="eu-north-1", instance="i-1", role="relay"),
            "avpn-exit": dict(provider="ssh", role="exit", key_protection="operator",
                              bastion=dict(instance="ocid1.instance.x", oci_profile="DEFAULT"))})  # fmt: skip
        plan = plan or {"accountPlanType": "FREE", "accountPlanStatus": "ACTIVE",
                        "accountPlanRemainingCredits": {"amount": 106.3}, "accountPlanExpirationDate": "2099-01-01T00:00:00+00:00"}  # fmt: skip

        class FakeAws:
            def __init__(self, profile, region=None):
                pass

            def __call__(self, *args, parse=True):
                return plan

            def ec2(self, *args, parse=True):
                return {"Reservations": [{"Instances": [{"State": {"Name": "running"}}]}]}

        class FakeOci:
            region, tenancy = "me-dubai-1", "ocid1.tenancy.t"

            def __init__(self, profile="DEFAULT"):
                pass

            def __call__(self, *args):
                if args[:3] == ("compute", "instance", "get"):
                    return {"data": {"lifecycle-state": oci_state}}
                return {"data": {"items": [{"plan-type": "FREE_TIER", "upgrade-state": "PROMO"}]}}

        def fake_call(argv, parse=True, stdin=None):
            if ssh_error:
                raise cloud.CloudError(ssh_error)
            return ("active=active mode=systemd-creds unlocked=0" if "relay" in " ".join(argv) else ssh_line) + "\n"

        notes = []
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(cloud, "INVENTORY", Path(d) / "cloud.json"), \
                mock.patch.object(cloud, "Aws", FakeAws), mock.patch.object(cloud, "Oci", FakeOci), \
                mock.patch.object(cloud, "remote", lambda n, r: ("ssh", "scp", [], n)), \
                mock.patch.object(cloud, "call", fake_call), \
                mock.patch.object(cloud, "notify_user", lambda t, b: notes.append((t, b))):  # fmt: skip
            cloud.save_inventory(inv)
            r = cloud.run(cloud.build_parser().parse_args(["health", "--notify"]))
            saved = json.loads((Path(d) / "health.json").read_text())
        return (
            r,
            {x["label"]: x["value"] for x in r["rows"] if x["label"]},
            [x["value"] for x in r["rows"]],
            saved,
            notes,
        )

    def test_all_well_raises_nothing(self):
        r, rows, _, saved, notes = self.run_health()
        self.assertEqual(r["summary"], "healthy")
        self.assertEqual(saved["problems"], [])
        self.assertEqual(notes, [])
        self.assertIn("106.3 USD credits left", rows["aws p"])
        self.assertIn("FREE_TIER", rows["oci DEFAULT"])

    def test_a_locked_exit_says_how_to_unlock_it(self):
        r, rows, values, saved, notes = self.run_health(ssh_line="active=activating mode=operator unlocked=0")
        self.assertEqual(r["summary"], "problems found")
        self.assertIn("LOCKED", rows["avpn-exit"])
        self.assertIn("fix: avpn cloud unlock avpn-exit", values)
        self.assertEqual(len(notes), 1)
        self.assertIn("avpn-exit: locked", notes[0][1])

    def test_a_stopped_or_deleted_server_says_so_with_the_start_command(self):
        _, rows, values, saved, _ = self.run_health(oci_state="STOPPED")
        self.assertIn("stopped by its provider", rows["avpn-exit"])
        fix = next(v for v in values if v.startswith("fix: oci compute instance action --action START"))
        self.assertIn("then: avpn cloud unlock avpn-exit", fix)
        _, rows, _, _, _ = self.run_health(oci_state="TERMINATED")
        self.assertIn("no longer exists", rows["avpn-exit"])

    def test_unreachable_and_accounts_running_out_are_problems(self):
        _, rows, _, saved, _ = self.run_health(ssh_error="ssh: connect timed out")
        self.assertIn("not reachable over SSH", rows["avpn-exit"])
        low = {"accountPlanType": "FREE", "accountPlanStatus": "ACTIVE", "accountPlanRemainingCredits": {"amount": 4.0},
               "accountPlanExpirationDate": "2026-11-25T00:00:00+00:00"}  # fmt: skip
        _, _, _, saved, notes = self.run_health(plan=low)
        self.assertTrue(any("only 4.0 USD" in x for x in saved["problems"]))
        self.assertTrue(any("free plan ends in" in x for x in saved["problems"]))
        self.assertEqual(len(notes), 1)


class ChainTests(Stubbed):
    def setUp(self):
        super().setUp()
        d = Path(self.tmp.name)
        for name, body in [("ssh", SSH_STUB), ("scp", SCP_STUB)]:
            (d / name).write_text(body)
            (d / name).chmod(0o755)
        ctl = d / "avpnctl"
        ctl.write_text(
            "#!" + sys.executable + "\nimport json, os, sys\na = sys.argv[1:]\n"
            "if 'unlock-key' in a:\n"
            "    v = a[a.index('--vault') + 1]\n    os.makedirs(v, exist_ok=True)\n"
            "    open(os.path.join(v, 'operator-unlock.pub'), 'wb').write(b'U' * 1216)\n"
            "    print(json.dumps({'ok': True}))\n    sys.exit(0)\n"
            "if 'unwrap' in a:\n"
            "    open(os.environ['STUB_LOG'] + '.unwrap', 'w').write(json.dumps(a))\n"
            "    name = a[a.index('--request') + 1].split('=')[0]\n"
            "    print(json.dumps({'ok': True, 'unlock': {name: 'cd' * 32}}))\n    sys.exit(0)\n"
            "open(os.environ['STUB_LOG'] + '.ctl', 'w').write(json.dumps(a))\n"
            "out = a[a.index('--out') + 1]\nos.makedirs(out)\n"
            "for r in ['client', 'relay', 'middle', 'exit']:\n    open(os.path.join(out, r + '.avpn'), 'w').write(r)\n"
            "open(os.path.join(out, 'operator.pub'), 'w').write('pub')\n"
            "print(json.dumps({'ok': True, 'unlock': json.loads(os.environ.get('STUB_UNLOCK', '{}'))}))\n"
        )
        ctl.chmod(0o755)
        self.extra = mock.patch.dict(
            os.environ, AVPN_SSH=str(d / "ssh"), AVPN_SCP=str(d / "scp"), AVPN_CTL=str(ctl), STUB_DIR=str(d)
        )
        self.extra.start()
        self.src = self.checkout(d / "checkout")
        key = d / "key"
        key.write_text("k")
        key.chmod(0o600)
        self.key = key
        (d / "client.req").write_text("{}")
        relay_sg = dict(
            GroupId="sg-r",
            GroupName="avpn-relay",
            IpPermissions=[
                dict(IpProtocol="udp", FromPort=41194, ToPort=41194, IpRanges=[dict(CidrIp="16.9.9.9/32")]),
                dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[dict(CidrIp="16.9.9.9/32")]),
            ],
        )
        self.set_state(dict(groups=[relay_sg]))
        cloud.save_inventory(
            dict(
                schema=1,
                resources={
                    "avpn-relay": dict(
                        provider="aws",
                        profile="p",
                        region="eu-north-1",
                        role="relay",
                        port=41194,
                        public_ip="13.0.0.1",
                        ssh_key=str(key),
                    ),  # fmt: skip
                },
            )
        )

    def tearDown(self):
        self.extra.stop()
        super().tearDown()

    @staticmethod
    def checkout(root):
        import install

        for name in install.SOURCES:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if "." in Path(name).name:
                target.write_text("x")
            else:
                target.mkdir(exist_ok=True)
                (target / "file").write_text("x")
        (root / "target/release").mkdir(parents=True)
        for b in install.BINARIES:
            (root / "target/release" / b).write_text("bin")
        return root

    def add_exit(self, name="avpn-exit", provider="oci", ip="16.40.0.2"):
        self.run_cli(
            "host", "add", "--name", name, "--ssh", "ubuntu@" + ip, "--key", str(self.key), "--provider", provider
        )

    def chain(self, *extra):
        d = Path(self.tmp.name)
        return self.run_cli("chain", "--apply", "--yes", "--client-request", str(d / "client.req"),
                            "--vault", str(d / "vault"), "--source", str(self.src), *extra)  # fmt: skip

    def final_sg(self):
        g = json.loads(self.state.read_text())["groups"][0]
        return {
            (p["IpProtocol"], p["FromPort"]): sorted(r["CidrIp"] for r in p.get("IpRanges", []))
            for p in g["IpPermissions"]
        }

    def test_two_servers_make_a_two_hop_chain_that_never_names_you(self):
        self.add_exit()
        r = self.chain()
        self.assertEqual(r["summary"], "built")
        # The exit is the larger allowance (OCI), the relay the AWS server.
        text = json.dumps(r["rows"])
        self.assertIn("client -> relay(avpn-relay) -> exit(avpn-exit)", text)
        init = json.loads(Path(os.environ["STUB_LOG"] + ".ctl").read_text())
        self.assertEqual(init[init.index("--hops") + 1], "2")
        self.assertEqual(init[init.index("--relay") + 1], "13.0.0.1:443")
        self.assertNotIn("--cover-name", init)  # no provider DNS name recorded: no server name sent
        self.assertEqual(init[init.index("--exit") + 1], "16.40.0.2:4444")
        reqs = [init[i + 1] for i, x in enumerate(init) if x == "--request"]
        self.assertEqual(sorted(x.split("=")[0] for x in reqs), ["client", "exit", "relay"])
        # Final firewall: the first hop open to any address, SSH only from the exit.
        # The old WireGuard port is closed; only the camouflage's 443 stays open.
        self.assertEqual(
            self.final_sg(),
            {("udp", 443): ["0.0.0.0/0"], ("tcp", 443): ["0.0.0.0/0"], ("tcp", 22): ["16.40.0.2/32"]},
        )
        self.assertNotIn("16.9.9.9/32", sum(self.final_sg().values(), []))
        # Servers are enrolled exit first.
        log = (Path(self.tmp.name) / "log.ssh").read_text().splitlines()
        enrolls = [line for line in log if line.endswith("bash -s")]
        self.assertTrue(enrolls[0].count("16.40.0.2") and enrolls[1].count("13.0.0.1"), enrolls)
        # Afterwards: the relay from the exit's address, the exit at its tunnel address.
        self.assertIn("ssh admin@13.0.0.1 (while connected)", text)
        self.assertIn("ssh ubuntu@10.77.0.1 (while connected)", text)
        inv = json.loads(cloud.INVENTORY.read_text())
        self.assertEqual(inv["chain"]["hops"], ["avpn-relay", "avpn-exit"])
        self.assertTrue(inv["resources"]["avpn-relay"]["first_hop"])
        self.assertFalse(inv["resources"]["avpn-exit"]["first_hop"])

    def operator_exit_chain(self, data_key):
        self.add_exit()
        env = dict(STUB_PROTECT="operator tpm2=no creds_key=None", STUB_UNLOCK=json.dumps({"exit": data_key}))
        with mock.patch.dict(os.environ, env):
            return self.chain()

    def test_an_exit_without_a_tpm_gets_its_data_key_on_stdin_only_before_it_starts(self):
        data_key = "ab" * 32
        r = self.operator_exit_chain(data_key)
        self.assertEqual(r["summary"], "built")
        d = Path(self.tmp.name)
        # The signing call asked for the unwrap (same touch), and the key came back on its pipe.
        init = json.loads(Path(os.environ["STUB_LOG"] + ".ctl").read_text())
        self.assertIn("--emit-unlock", init)
        self.assertEqual((d / "unlock-stdin").read_text().strip(), data_key)  # only the exit's
        log = (d / "log.ssh").read_text()
        self.assertNotIn(data_key, log)  # never in a command line
        self.assertNotIn(data_key, json.dumps(json.loads(cloud.INVENTORY.read_text())))
        self.assertFalse(any(data_key in p.read_text(errors="ignore") for p in d.rglob("*") if p.is_file()
                             and p.name != "unlock-stdin"))  # fmt: skip
        # Unlocked before it was enrolled and started.
        lines = log.splitlines()
        unlocked = next(i for i, x in enumerate(lines) if x.endswith("server-unlock") and "16.40.0.2" in x)
        enrolled = next(i for i, x in enumerate(lines) if x.endswith("bash -s") and "16.40.0.2" in x)
        self.assertLess(unlocked, enrolled)
        self.assertIn("locked to the operator's Nitrokey", json.dumps(r["rows"]))
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]
        self.assertEqual(rec["key_protection"], "operator")
        self.assertTrue(Path(rec["request"]).is_file())

    def test_unlock_binds_to_your_copy_of_the_request_and_restarts_the_server(self):
        self.operator_exit_chain("ab" * 32)
        d = Path(self.tmp.name)
        (d / "unlock-stdin").unlink()
        r = self.run_cli("unlock", "avpn-exit")
        self.assertEqual(r["summary"], "unlocked")
        unwrap = json.loads(Path(os.environ["STUB_LOG"] + ".unwrap").read_text())
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]
        # Role and identities come from your own copy of the request; only the wrapped key
        # (ciphertext) comes from the server.
        self.assertIn("avpn-exit=" + rec["request"], unwrap)
        self.assertTrue(any(x.startswith("avpn-exit=") for x in unwrap[unwrap.index("--wrapped") + 1 :][:1]))
        self.assertEqual(unwrap[unwrap.index("--vault") + 1], str((d / "vault").resolve()))
        self.assertEqual((d / "unlock-stdin").read_text().strip(), "cd" * 32)
        self.assertIn("systemctl restart advanced-vpn.service", (d / "enroll-script.sh").read_text())
        # A server that does not lock to the operator (here: a TPM-sealed relay) is not "unlocked".
        inv = cloud.load_inventory()
        inv["resources"]["avpn-relay"]["key_protection"] = "systemd-creds"
        cloud.save_inventory(inv)
        with self.assertRaisesRegex(cloud.CloudError, "does not lock its keys"):
            self.run_cli("unlock", "avpn-relay")

    def test_setup_ssh_from_here_is_opened_then_removed(self):
        self.add_exit()
        self.chain()
        auth = [
            json.loads(c[c.index("--ip-permissions") + 1])
            for c in self.calls()
            if c[1:2] == ["authorize-security-group-ingress"]
        ]
        opened = {r["CidrIp"] for perms in auth for p in perms for r in p["IpRanges"] if p["FromPort"] == 22}
        self.assertIn("16.40.0.2/32", opened)
        self.assertNotIn("16.9.9.9/32", self.final_sg()[("tcp", 22)])

    def test_the_first_hop_admits_the_tls_fallback_on_tcp_and_later_hops_do_not(self):
        # Live-chain regression (14 Nov 2026): a client behind a 1420-byte path falls back
        # to TLS over TCP 443, which the security group dropped (only UDP 443 was open).
        self.add_exit()
        self.chain()
        sg = self.final_sg()
        self.assertEqual(sg[("udp", 443)], ["0.0.0.0/0"])
        self.assertEqual(sg[("tcp", 443)], ["0.0.0.0/0"])
        # Each apply works in its own per-second chains/ directory (sleep is stubbed here).
        chains = cloud.INVENTORY.parent / "chains"
        chains.rename(chains.with_name("chains.first"))
        self.chain()  # re-applying keeps the rule exact, never duplicated
        sg = self.final_sg()
        self.assertEqual(sg[("tcp", 443)], ["0.0.0.0/0"])
        self.assertEqual(sorted(k for k in sg if k[0] == "tcp"), [("tcp", 22), ("tcp", 443)])

    def test_an_apply_reports_each_step_as_it_starts(self):
        # Live regression (14 Nov 2026): a chain apply printed nothing for ~6 minutes, which
        # looked like a hang. With progress on, every step says it has started.
        import contextlib
        import io

        self.add_exit()
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"AVPN_PROGRESS": "1"}), contextlib.redirect_stderr(err):
            self.chain()
        lines = err.getvalue().splitlines()
        for step in [
            "Open the firewalls",
            "Check the operator's unlock key",
            "Install avpn-relay as the relay",
            "Install avpn-exit as the exit",
            "Sign the chain",
            "Start avpn-exit",
            "Start avpn-relay",
            "Close SSH from here",
        ]:
            self.assertTrue(any(step in line for line in lines), (step, lines))
        self.assertTrue(all(re.search(r"\[\s*\d+s\]", line) for line in lines), lines)
        # Off by default (scripts, tests, --json consumers): nothing on stderr.
        err = io.StringIO()
        chains = cloud.INVENTORY.parent / "chains"
        chains.rename(chains.with_name("chains.progress"))
        with mock.patch.dict(os.environ, {}, clear=False), contextlib.redirect_stderr(err):
            os.environ.pop("AVPN_PROGRESS", None)
            self.chain()
        self.assertEqual(err.getvalue(), "")

    def events(self, text):
        mark = cloud.PROGRESS_MARK
        # Split on "\n" only: str.splitlines() also breaks at the marker's \x1e.
        return [json.loads(line[len(mark) :]) for line in text.split("\n") if line.startswith(mark)]

    def test_the_front_end_gets_the_whole_list_then_each_change(self):
        # Owner request (15 Nov 2026): a checklist like Claude's task panel; the plan
        # first, then run / wait / done per step, so nothing is a silent hang.
        import contextlib
        import io

        self.add_exit()
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"AVPN_PROGRESS": "events"}), contextlib.redirect_stderr(err):
            self.chain()
        ev = self.events(err.getvalue())
        self.assertEqual(
            ev[0]["plan"],
            [
                "Open the firewalls",
                "Check the operator's unlock key",
                "Install avpn-relay as the relay",
                "Install avpn-exit as the exit",
                "Sign the chain",
                "Start avpn-exit",
                "Start avpn-relay",
                "Close SSH from here",
            ],
        )
        states = [(e["step"], e["state"]) for e in ev[1:]]
        self.assertEqual([i for i, st in states if st == "done"], list(range(8)), states)
        self.assertIn((1, "wait"), states)  # the unlock key, made once (PIN + touch)
        self.assertIn((4, "wait"), states)  # the signature
        self.assertTrue(all(i == j for (i, st), (j, _) in zip(states, states[1:], strict=False) if st == "run"), states)
        self.assertEqual(err.getvalue().count("\n"), len(ev))  # nothing else on stderr

    def test_a_failure_is_reported_on_the_step_that_failed(self):
        import contextlib
        import io

        self.add_exit()
        err = io.StringIO()
        boom = cloud.CloudError("avpn-exit did not install")
        with (
            mock.patch.dict(os.environ, {"AVPN_PROGRESS": "events"}),
            contextlib.redirect_stderr(err),
            mock.patch.object(cloud, "setup_server", side_effect=[("kept", "systemd-creds", "tpm2=yes"), boom]),
        ):
            with self.assertRaises(cloud.CloudError):
                self.chain()
        ev = self.events(err.getvalue())
        self.assertEqual(ev[-1], {"step": 3, "state": "fail", "note": "avpn-exit did not install"})

    def test_the_plan_names_tcp_for_the_first_hop_only(self):
        self.add_exit()
        d = Path(self.tmp.name)
        r = self.run_cli(
            "chain", "--apply", "--dry-run", "--client-request", str(d / "client.req"), "--vault", str(d / "v")
        )
        values = [row["value"] for row in r["rows"]]
        self.assertIn("udp+tcp 443 from 0.0.0.0/0; firewall managed", values)
        self.assertTrue(any(v.startswith("udp 4444 from ") for v in values), values)

    def test_oci_ingress_adds_tcp_only_for_the_first_hop_port(self):
        rules = cloud.oci_ingress(443, ["0.0.0.0/0"], ["1.2.3.4/32"], tcp=True)
        tunnel_tcp = [
            r for r in rules if r["protocol"] == "6" and r["tcpOptions"]["destinationPortRange"]["min"] == 443
        ]
        self.assertEqual([r["source"] for r in tunnel_tcp], ["0.0.0.0/0"])
        plain = cloud.oci_ingress(4444, ["9.9.9.9/32"], [])
        self.assertEqual([r["protocol"] for r in plain], ["17"])

    def test_plan_changes_nothing_and_flags_unmanaged_firewalls(self):
        self.add_exit()
        before = len(self.calls())
        d = Path(self.tmp.name)
        r = self.run_cli(
            "chain", "--apply", "--dry-run", "--client-request", str(d / "client.req"), "--vault", str(d / "v")
        )
        text = json.dumps(r["rows"])
        self.assertIn("NOT managed", text)
        self.assertIn("about 100 GiB/month", text)
        self.assertFalse([c for c in self.calls()[before:] if "security-group-ingress" in (c[1:2] or [""])[0]])
        self.assertFalse(Path(os.environ["STUB_LOG"] + ".ctl").exists())

    def test_one_server_is_a_one_hop_exit_on_the_camouflage_port(self):
        r = self.chain()
        init = json.loads(Path(os.environ["STUB_LOG"] + ".ctl").read_text())
        self.assertEqual((init[init.index("--hops") + 1], init[init.index("--exit") + 1]), ("1", "13.0.0.1:443"))
        self.assertNotIn("--relay", init)
        self.assertIn("client -> exit(avpn-relay)", json.dumps(r["rows"]))
        self.assertEqual(self.final_sg()[("udp", 443)], ["0.0.0.0/0"])

    def test_the_first_hop_presents_its_provider_dns_name(self):
        inv = cloud.load_inventory()
        inv["resources"]["avpn-relay"]["public_dns"] = "ec2-13-0-0-1.eu-north-1.compute.amazonaws.com"
        cloud.save_inventory(inv)
        self.add_exit()
        self.chain()
        init = json.loads(Path(os.environ["STUB_LOG"] + ".ctl").read_text())
        self.assertEqual(init[init.index("--cover-name") + 1], "ec2-13-0-0-1.eu-north-1.compute.amazonaws.com")

    def test_three_servers_put_a_different_provider_at_the_entry(self):
        self.add_exit("avpn-exit", "oci", "16.40.0.2")
        self.add_exit("avpn-oci2", "oci", "16.40.0.3")
        names = cloud.chain_order(cloud.servers())
        self.assertEqual(names[-1], "avpn-exit")
        self.assertEqual(names[0], "avpn-relay")
        layout = cloud.chain_layout(names, json.loads(cloud.INVENTORY.read_text())["resources"])
        self.assertEqual([h["role"] for h in layout], ["relay", "middle", "exit"])
        self.assertEqual(layout[1]["sources"], ["13.0.0.1/32"])
        self.assertEqual(layout[2]["sources"], ["16.40.0.3/32"])
        self.assertEqual([h["ssh"] for h in layout], [["16.40.0.2/32"], ["16.40.0.2/32"], []])

    def test_one_provider_at_both_ends_is_refused_unless_allowed(self):
        self.add_exit("avpn-exit", "aws", "16.40.0.2")  # the relay is on AWS too
        with self.assertRaisesRegex(cloud.CloudError, "entry and the exit are both on aws"):
            self.chain()
        self.chain("--allow-same-provider")  # an explicit choice goes through

    def test_a_provider_with_two_inner_hops_is_named_in_the_plan(self):
        self.add_exit("avpn-exit", "oci", "16.40.0.2")
        self.add_exit("avpn-oci2", "oci", "16.40.0.3")
        d = Path(self.tmp.name)
        a = cloud.build_parser().parse_args(["chain", "--apply", "--client-request", str(d / "client.req"),
                                             "--vault", str(d / "vault"), "--source", str(self.src)])  # fmt: skip
        self.assertIn("oci hosts 2 of 3 hops", json.dumps(cloud.chain_plan(a)["rows"]))

    def test_order_must_name_recorded_servers(self):
        with self.assertRaisesRegex(cloud.CloudError, "not recorded as servers: avpn-nope"):
            self.chain("--order", "avpn-relay,avpn-nope")

    def test_host_add_checks_key_address_and_provider(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(cloud.CloudError, "readable by others"):
            self.add_exit()
        self.key.chmod(0o600)
        with self.assertRaisesRegex(cloud.CloudError, "not a public IPv4"):
            self.add_exit(ip="10.0.0.5")
        with self.assertRaisesRegex(cloud.CloudError, "--provider must be one of"):
            self.add_exit(provider="nowhere")
        self.add_exit()
        with self.assertRaisesRegex(cloud.CloudError, "already recorded"):
            self.add_exit()
        rec = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-exit"]
        self.assertEqual((rec["catalog"], rec["public_ip"], rec["ssh"]), ("oci", "16.40.0.2", "ubuntu@16.40.0.2"))
        self.run_cli("host", "forget", "--name", "avpn-exit")
        self.assertNotIn("avpn-exit", json.loads(cloud.INVENTORY.read_text())["resources"])


SSH_STUB = r"""#!/bin/sh
echo "$(basename "$0") $*" >> "$STUB_LOG.ssh"
case "$*" in
  *" true") exit 0 ;;
  *"getconf GNU_LIBC_VERSION") echo "glibc ${STUB_GLIBC:-2.41}" ;;
  *"bash -s -- "*) cat > "$STUB_DIR/remote-script.sh"; echo "keys=new"; echo "protection=${STUB_PROTECT:-systemd-creds tpm2=yes creds_key=host+tpm2}" ;;
  *"bash -s") cat > "$STUB_DIR/enroll-script.sh"; echo "$(basename "$0") enrolled" >> "$STUB_LOG.ssh"; echo active ;;
  *"server-unlock") cat >> "$STUB_DIR/unlock-stdin"; echo '{"ok": true, "unlocked": ["inner"]}' ;;
  *"cat /etc/advanced-vpn/enrolled/protection.json") echo '{"mode": "operator", "unlock": {"from": "server"}}' ;;
esac
"""
SCP_STUB = r"""#!/bin/sh
echo "scp $*" >> "$STUB_LOG.ssh"
for last in "$@"; do :; done
case "$last" in
  *@*:*) for a in "$@"; do case "$a" in *.tgz) if [ -f "$a" ]; then cp "$a" "$STUB_DIR/sent.tgz"; fi ;; esac; done ;;
  */requests/*.req) r=$(basename "$last" .req); printf '{"schema": 1, "role": "%s", "certificates": {}}' "$r" > "$last" ;;
  *) printf '{"schema": 1, "role": "%s", "certificates": {}}' "$STUB_ROLE" > "$last" ;;
esac
"""


class HostSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        for name, body in [("ssh", SSH_STUB), ("scp", SCP_STUB)]:
            (d / name).write_text(body)
            (d / name).chmod(0o755)
        # A minimal built checkout: every source entry and binary the installer needs.
        self.src = d / "checkout"
        import install

        for name in install.SOURCES:
            target = self.src / name
            if "." in Path(name).name:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("x")
            else:
                (target / "__pycache__").mkdir(parents=True)
                (target / "__pycache__" / "junk.pyc").write_text("x")
                (target / "file").write_text("x")
        (self.src / "target/release").mkdir(parents=True)
        for b in install.BINARIES:
            (self.src / "target/release" / b).write_text("bin")
        self.env = mock.patch.dict(
            os.environ,
            dict(
                AVPN_SSH=str(d / "ssh"),
                AVPN_SCP=str(d / "scp"),
                STUB_LOG=str(d / "log"),
                STUB_DIR=str(d),
                STUB_ROLE="relay",
            ),
        )
        self.env.start()
        self.inv = mock.patch.object(cloud, "INVENTORY", d / "config" / "cloud.json")
        self.inv.start()
        cloud.save_inventory(
            dict(
                schema=1,
                resources={
                    "avpn-relay": dict(provider="aws", role="relay", public_ip="16.0.0.9", ssh_key=str(d / "key"))
                },
            )
        )
        self.d = d

    def tearDown(self):
        self.inv.stop()
        self.env.stop()
        self.tmp.cleanup()

    def setup_host(self, name="avpn-relay"):
        a = cloud.build_parser().parse_args(
            ["host", "setup", "--name", name, "--source", str(self.src), "--out", str(self.d / "relay.req")]
        )
        return cloud.run(a)

    def test_installs_exactly_the_package_and_fetches_the_request(self):
        import install
        import tarfile

        r = self.setup_host()
        self.assertEqual(r["summary"], "installed")
        names = set(tarfile.open(self.d / "sent.tgz").getnames())
        for b in install.BINARIES:
            self.assertIn("target/release/" + b, names)
        self.assertFalse([n for n in names if "__pycache__" in n])
        self.assertTrue({n.split("/")[0] for n in names} <= {s.split("/")[0] for s in install.SOURCES} | {"target"})
        script = (self.d / "remote-script.sh").read_text()
        self.assertIn("libtss2", script)
        # The protection is chosen by a live probe of TPM2 sealing, not hard-coded: a host
        # without one locks its keys to the operator's Nitrokey, never to plain files or
        # the host key alone (owner decision, 20 Nov 2026).
        self.assertIn("PROTECT=systemd-creds", script)
        self.assertIn("PROTECT=operator", script)
        self.assertIn("--with-key=host+tpm2", script)
        self.assertNotIn("--with-key=host ", script)
        self.assertIn('request --role "$ROLE" --protect "$PROTECT"', script)
        self.assertNotIn("--insecure-plaintext-keys", script)
        self.assertNotIn("PROTECT=none", script)
        self.assertIn("replace them to make it a", script)
        # Root-run Python must not leave root-owned caches behind in the user's temp tree.
        self.assertIn("python3 -B /tmp/avpn-src/tools/install.py", script)
        # The system journal (sshd logs the admin's address) lives in RAM only.
        self.assertIn("Storage=volatile", script)
        self.assertIn("rm -rf /var/log/journal", script)
        log = (self.d / "log.ssh").read_text()
        self.assertIn("StrictHostKeyChecking=accept-new", log)
        self.assertIn("IdentityAgent=none", log)
        self.assertIn("bash -s -- relay 443 no no", log)
        self.assertIn("protection=systemd-creds tpm2=yes creds_key=host+tpm2", json.dumps(r["rows"]))
        inv = json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay"]
        self.assertEqual(inv["request"], str(self.d / "relay.req"))
        self.assertEqual(inv["key_protection"], "systemd-creds")

    def test_binaries_too_new_for_the_servers_c_library_are_refused_before_upload(self):
        (self.src / "target/release/advanced-vpn").write_bytes(b"\0GLIBC_2.17\0GLIBC_2.38\0GLIBC_2.4\0")
        with mock.patch.dict(os.environ, STUB_GLIBC="2.35"):
            with self.assertRaisesRegex(cloud.CloudError, "has glibc 2.35 but this package needs 2.38"):
                self.setup_host()
        self.assertFalse((self.d / "sent.tgz").exists())
        with mock.patch.dict(os.environ, STUB_GLIBC="2.39"):
            self.assertEqual(self.setup_host()["summary"], "installed")

    def test_request_for_another_role_is_refused(self):
        with mock.patch.dict(os.environ, STUB_ROLE="exit"):
            with self.assertRaisesRegex(cloud.CloudError, "not for role relay"):
                self.setup_host()

    def test_unbuilt_checkout_and_unknown_hosts_are_refused(self):
        with self.assertRaisesRegex(cloud.CloudError, "not a recorded host"):
            self.setup_host("avpn-other")
        (self.src / "target/release/avpn").unlink()
        with self.assertRaisesRegex(cloud.CloudError, "build first"):
            self.setup_host()


HOST_STUBS = {
    "sudo": '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n',
    "apt-get": '#!/bin/sh\necho "apt-get $*" >> "$ROOT/log"\n',
    "apt-cache": "#!/bin/sh\necho libtss2-esys-3.0.2-0t64\n",
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$ROOT/log"\n',
    "systemd-analyze": "#!/bin/sh\nexit 1\n",
    "netfilter-persistent": '#!/bin/sh\necho "netfilter-persistent $*" >> "$ROOT/log"\n',
    "iptables": '#!/bin/sh\necho "iptables $*" >> "$ROOT/log"\n'
    'case "$1" in -S) cat "$ROOT/iptables" 2>/dev/null ;; -C) exit 1 ;; esac\n',
}
FAKE_AVPNCTL = r"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
root = os.environ["ROOT"]
open(root + "/log", "a").write("avpnctl " + " ".join(a) + "\n")
role = a[a.index("--role") + 1]
protect = a[a.index("--protect") + 1]
e = root + "/etc/advanced-vpn/enrolled"
os.makedirs(e, exist_ok=True)
req = {"schema": 1, "role": role, "certificates": {}, "kem_public": "k"}
if role in ("client", "relay", "exit"):
    req["wireguard_public_hex"] = "00"
if role in ("relay", "exit"):
    req.update(cloak_spki_sha256="00", i2p_destination="d")
json.dump(req, open(e + "/request.json", "w"))
if protect == "operator":
    import hashlib
    pub = open(a[a.index("--unlock-key") + 1], "rb").read()
    prot = {"mode": "operator", "unlock": {"operator_unlock_sha256": hashlib.sha256(pub).hexdigest()}}
else:
    prot = {"mode": protect, "creds_key": "host+tpm2" if protect == "systemd-creds" else None}
json.dump(prot, open(e + "/protection.json", "w"))
"""


class HostScriptTests(unittest.TestCase):
    """Run the real HOST_SETUP script against stub system commands, with its absolute
    paths moved under a temporary root."""

    def setUp(self):
        import tarfile

        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        stubs = self.root / "bin"
        stubs.mkdir()
        for name, body in HOST_STUBS.items():
            (stubs / name).write_text(body)
            (stubs / name).chmod(0o755)
        ctl = self.root / "opt/advanced-vpn/bin/avpnctl"
        ctl.parent.mkdir(parents=True)
        ctl.write_text(FAKE_AVPNCTL.replace("/usr/bin/env python3", sys.executable))
        ctl.chmod(0o755)
        pkg = self.root / "pkg/tools"
        pkg.mkdir(parents=True)
        (pkg / "install.py").write_text(
            'import os, sys\nopen(os.environ["ROOT"] + "/log", "a").write(" ".join(["install"] + sys.argv[1:]) + "\\n")\n'
        )
        (self.root / "root").mkdir()
        (self.root / "etc/systemd").mkdir(parents=True)
        (self.root / "var/log/journal").mkdir(parents=True)
        self.tgz = self.root / "tmp/avpn-src.tgz"
        self.tgz.parent.mkdir()
        with tarfile.open(self.root / "keep.tgz", "w:gz") as tf:
            tf.add(self.root / "pkg/tools", arcname="tools")
        # Never run the real hardening here: it masks services, mounts over /var/log and
        # edits /etc/fstab on whatever machine runs the tests. The VM proof covers it.
        import retention

        self.script = cloud.HOST_SETUP.replace(retention.HARDEN.rstrip("\n"), 'echo harden >> "$ROOT/log"')
        assert "systemctl mask" not in self.script and "swapoff" not in self.script, "real hardening left in"
        for path in [
            "/etc/advanced-vpn",
            "/etc/systemd",
            "/var/log/journal",
            "/opt/advanced-vpn",
            "/tmp/avpn-",
            "/root/",
        ]:
            self.script = self.script.replace(path, str(self.root) + path)
        self.env = dict(os.environ, ROOT=str(self.root), PATH="%s:%s" % (stubs, os.environ["PATH"]))
        self.systemd_creds_stub(self.PIPE_ONLY_CREDS)  # a host whose TPM2 seals, unless a test says not

    def tearDown(self):
        self.tmp.cleanup()

    def setup(self, role, replace="no", shared="no", port="41194", unlock=None):
        import shutil
        import subprocess

        shutil.copy(self.root / "keep.tgz", self.tgz)  # the script deletes it when done
        if unlock is not None:  # the operator's unlock public key, uploaded by setup_server
            (self.root / "tmp/avpn-unlock.pub").write_bytes(unlock)

        return subprocess.run(
            ["bash", "-s", "--", role, port, replace, shared, "yes" if unlock is not None else "no"],
            input=self.script,
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )

    def log(self):
        return (self.root / "log").read_text()

    def requested(self):
        return self.log().count("avpnctl request")

    def test_fresh_server_gets_keys_and_a_ram_only_journal(self):
        r = self.setup("relay")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("keys=new", r.stdout)
        self.assertEqual(json.loads((self.root / "tmp/avpn-request.json").read_text())["role"], "relay")
        self.assertIn("install", self.log())
        # The hardening runs first, before packages are installed.
        log = self.log()
        self.assertLess(log.index("harden"), log.index("apt-get"))
        self.assertFalse((self.root / "etc/advanced-vpn/shared-host").exists())
        self.assertFalse((self.root / "tmp/avpn-src.tgz").exists())

    def test_a_flat_installation_is_stopped_and_adopted_and_a_slotted_one_is_not(self):
        # Found rebuilding the live chain (20 Nov 2026): a server installed before release
        # slots refused the upgrade ("legacy system application detected").
        r = self.setup("relay")
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.log()
        self.assertIn("systemctl stop advanced-vpn.service", log)
        self.assertIn("systemctl stop advanced-vpn-guard.service", log)
        self.assertIn("install --apply --adopt-legacy", log)
        self.assertLess(log.index("systemctl stop advanced-vpn.service"), log.index("install --apply"))
        # A slotted installation (bin is a link into the current slot) is upgraded in place.
        import shutil

        (self.root / "log").write_text("")
        app = self.root / "opt/advanced-vpn"
        shutil.move(app / "bin", app / "current-bin")
        (app / "bin").symlink_to("current-bin")
        r = self.setup("relay")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("systemctl stop", self.log())
        self.assertIn("install --apply\n", self.log())

    def systemd_creds_stub(self, body):
        stub = self.root / "bin/systemd-creds"
        stub.write_text(body)
        stub.chmod(0o755)

    def test_a_host_without_a_tpm_locks_its_keys_to_the_operator(self):
        # Bug 9a, then the owner's decision (20 Nov 2026): a host that cannot seal to a TPM2
        # (the free OCI exit: Ubuntu 22.04, systemd 249, no vTPM) locks its keys to the
        # operator's Nitrokey; it never stores them as plain files.
        self.systemd_creds_stub("#!/bin/sh\nexit 1\n")
        r = self.setup("exit", unlock=b"U" * 1216)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("keys=new", r.stdout)
        self.assertIn("--protect operator --unlock-key", self.log())
        self.assertNotIn("--protect none", self.log())
        self.assertIn("avpn cloud unlock", r.stderr)
        self.assertTrue(r.stdout.strip().splitlines()[-1].startswith("protection=operator "), r.stdout)
        self.assertFalse((self.root / "tmp/avpn-unlock.pub").exists())

    def test_a_host_without_a_tpm_and_no_unlock_key_is_refused(self):
        self.systemd_creds_stub("#!/bin/sh\nexit 1\n")
        r = self.setup("exit")
        self.assertEqual(r.returncode, 4, r.stdout)
        self.assertIn("--vault", r.stderr)
        self.assertEqual(self.requested(), 0)

    def test_weak_keys_are_replaced_not_kept(self):
        # Owner (20 Nov 2026): keys that were plain, sealed with the host key alone, or locked
        # to another operator are replaced; copies may survive on the disk or its backups.
        unlock = b"U" * 1216
        prot = self.root / "etc/advanced-vpn/enrolled/protection.json"
        self.assertEqual(self.setup("exit", unlock=unlock).returncode, 0)
        for weak in (
            {"mode": "none"},
            {"mode": "systemd-creds", "creds_key": "host"},
            {"mode": "operator", "unlock": {"operator_unlock_sha256": "0" * 64}},
        ):
            with self.subTest(weak=weak):
                prot.write_text(json.dumps(weak))
                before = self.requested()
                r = self.setup("exit", unlock=unlock)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("keys=renewed", r.stdout)
                self.assertEqual(self.requested(), before + 1)
        # Strong keys are kept: TPM-sealed, or locked to this operator's unlock key.
        self.assertIn("keys=kept", self.setup("exit", unlock=unlock).stdout)
        self.systemd_creds_stub("#!/bin/sh\nexit 1\n")
        self.setup("exit", replace="yes", unlock=unlock)
        prot.write_text(
            json.dumps(
                {
                    "mode": "operator",
                    "unlock": {"operator_unlock_sha256": __import__("hashlib").sha256(unlock).hexdigest()},
                }
            )
        )
        self.assertIn("keys=kept", self.setup("exit", unlock=unlock).stdout)

    # A systemd-creds that works like the real one through a pipe, and refuses any file
    # argument: the probe must never write a file. (A root-written file in the sticky /tmp
    # cannot be removed by the unprivileged script, and under `set -e` that aborted the
    # setup on exactly the hosts where sealing works.)
    PIPE_ONLY_CREDS = (
        "#!/bin/sh\n"
        'case "$*" in *" - -") ;; *) echo "file argument: $*" >&2; exit 9 ;; esac\n'
        'case "$1" in encrypt) printf sealed: ; cat ;; decrypt) sed "s/^sealed://" ;; *) exit 1 ;; esac\n'
    )

    def test_a_host_that_can_seal_uses_systemd_creds(self):
        self.systemd_creds_stub(self.PIPE_ONLY_CREDS)
        r = self.setup("relay")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("keys=new", r.stdout)
        self.assertIn("--protect systemd-creds", self.log())
        self.assertNotIn("--insecure-plaintext-keys", self.log())
        self.assertNotIn("PLAIN FILES", r.stderr)
        self.assertNotIn("file argument", r.stderr)
        self.assertTrue(r.stdout.strip().splitlines()[-1].startswith("protection=systemd-creds "), r.stdout)
        self.assertFalse(list((self.root / "tmp").glob("avpn-creds-probe*")))

    def test_a_probe_that_does_not_round_trip_falls_back(self):
        # Exit codes alone are not proof: a credential must decrypt to what was sealed.
        self.systemd_creds_stub('#!/bin/sh\n[ "$1" = encrypt ] && cat >/dev/null\necho garbage\nexit 0\n')
        r = self.setup("relay", unlock=b"U" * 1216)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--protect operator", self.log())
        self.assertNotIn("--protect systemd-creds", self.log())

    def test_same_role_keeps_keys_and_another_role_needs_replace(self):
        self.assertEqual(self.setup("relay").returncode, 0)
        again = self.setup("relay")
        self.assertIn("keys=kept", again.stdout)
        self.assertEqual(self.requested(), 1)
        refused = self.setup("exit")
        self.assertEqual(refused.returncode, 3)
        self.assertIn("has keys for role relay", refused.stderr)
        self.assertEqual(self.requested(), 1)
        replaced = self.setup("exit", replace="yes")
        self.assertIn("keys=new", replaced.stdout)
        self.assertIn("systemctl stop advanced-vpn.service", self.log())
        self.assertEqual(json.loads((self.root / "tmp/avpn-request.json").read_text())["role"], "exit")

    def test_same_role_keys_older_than_this_release_are_renewed(self):
        # Live-chain regression (14 Nov 2026): a relay's keys from before the HTTP/3
        # camouflage were kept because the role matched; signing then refused them.
        self.assertEqual(self.setup("relay").returncode, 0)
        req = self.root / "etc/advanced-vpn/enrolled/request.json"
        old = json.loads(req.read_text())
        del old["cloak_spki_sha256"]
        req.write_text(json.dumps(old))
        r = self.setup("relay")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("keys=renewed", r.stdout)
        self.assertEqual(self.requested(), 2)
        self.assertIn("systemctl stop advanced-vpn.service", self.log())
        self.assertIn("cloak_spki_sha256", json.loads((self.root / "tmp/avpn-request.json").read_text()))
        # Current keys are still kept.
        self.assertIn("keys=kept", self.setup("relay").stdout)
        self.assertEqual(self.requested(), 2)

    def test_shared_host_is_marked_not_hardened(self):
        self.setup("exit", shared="yes")
        self.assertNotIn("harden", self.log())
        self.assertTrue((self.root / "etc/advanced-vpn/shared-host").exists())
        # Setting it up again as a dedicated host hardens it and clears the mark.
        self.setup("exit")
        self.assertIn("harden", self.log())
        self.assertFalse((self.root / "etc/advanced-vpn/shared-host").exists())

    def test_reject_by_default_hosts_get_the_tunnel_port_accepted(self):
        self.setup("exit", port="4444")
        self.assertNotIn("iptables -I", self.log())
        (self.root / "iptables").write_text("-A INPUT -j REJECT --reject-with icmp-host-prohibited\n")
        self.setup("exit", port="4444")
        self.assertIn("iptables -I INPUT 1 -p udp --dport 4444 -j ACCEPT", self.log())
        self.assertIn("netfilter-persistent save", self.log())
        # A shared host gets the runtime rule, but its other rules are not persisted.
        (self.root / "log").write_text("")
        self.setup("exit", port="4444", shared="yes")
        self.assertIn("iptables -I INPUT 1 -p udp --dport 4444 -j ACCEPT", self.log())
        self.assertNotIn("netfilter-persistent", self.log())
        self.assertNotIn("--dport 8443", self.log())
        # A first hop's public 443 is redirected to the cloak's 8443 before INPUT sees it.
        (self.root / "log").write_text("")
        self.setup("relay", port="443")
        self.assertIn("iptables -I INPUT 1 -p udp --dport 443 -j ACCEPT", self.log())
        self.assertIn("iptables -I INPUT 1 -p udp --dport 8443 -j ACCEPT", self.log())


if __name__ == "__main__":
    unittest.main()


class SystemPythonTests(unittest.TestCase):
    def test_the_cloud_tool_plans_rates_without_the_locked_dependencies(self):
        # avpn-cloud runs under the system Python (Debian's cryptography may be too old
        # for ML-DSA). Importing cloud and choosing a rate must not need cryptography.
        import subprocess

        code = (
            "import sys\n"
            "class Block:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name == 'cryptography' or name.startswith('cryptography.'):\n"
            "            raise ImportError('blocked: ' + name)\n"
            "sys.meta_path.insert(0, Block())\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import cloud\n"
            "print(cloud.rate_row(10240, 8, False, 2)['value'].split()[0])\n"
        )
        tools = str(Path(__file__).resolve().parent)
        r = subprocess.run([sys.executable, "-I", "-c", code, tools], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "fast")

    def test_signing_uses_the_installed_controller_not_the_system_python(self):
        # Live-chain regression (14 Nov 2026): signing ran avpnctl under the system
        # Python that avpn-cloud uses, whose cryptography had no ML-DSA. An installed
        # copy has bin/avpnctl beside tools/ (the hash-locked venv): signing must use it.
        with tempfile.TemporaryDirectory() as d:
            app = Path(d)
            (app / "tools").mkdir()
            (app / "bin").mkdir()
            launcher = app / "bin/avpnctl"
            launcher.write_text("#!/bin/sh\n")
            launcher.chmod(0o755)
            env = {k: v for k, v in os.environ.items() if k != "AVPN_CTL"}
            with (
                mock.patch.object(cloud, "__file__", str(app / "tools/cloud.py")),
                mock.patch.dict(os.environ, env, clear=True),
            ):
                self.assertEqual(cloud.controller(), [str(launcher)])
                launcher.unlink()  # a source checkout has no bin/: the interpreter running it
                self.assertEqual(cloud.controller(), [sys.executable, str(app / "tools/avpnctl.py")])
            with mock.patch.dict(os.environ, {"AVPN_CTL": "/x/ctl"}):
                self.assertEqual(cloud.controller(), ["/x/ctl"])

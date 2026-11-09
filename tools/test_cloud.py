"""`avpn cloud` against recorded provider CLIs: exact calls, safety rules, teardown scope."""

import json
import os
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
    if argv[:3] == ["network", "security-list", "get"]:
        out({"data": state["security_list"]})
    if argv[:3] == ["network", "security-list", "update"]:
        ingress = json.load(open(argv[argv.index("--ingress-security-rules") + 1][7:]))
        state["security_list"]["ingress-security-rules"] = ingress
        json.dump(state, open(os.environ["STUB_STATE"], "w"))
        out({"data": {"lifecycle-state": "AVAILABLE"}})
    fail("unexpected oci call")
if argv[:2] == ["configure", "get"]:
    out(state.get("region", "eu-north-1"))
if argv[:2] == ["sts", "get-caller-identity"]:
    out({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root"})
if argv[:1] == ["freetier"]:
    out({"accountPlanType": "FREE"})
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
    out({"SecurityGroups": state.get("groups", []) if tagged else []})
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
    out({"GroupId": "sg-1"})
if op == "run-instances":
    out({"Instances": [{"InstanceId": "i-1"}]})
if op == "terminate-instances":
    state["terminated"] = True
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
    out({})
if op in ("create-tags", "deregister-image", "import-key-pair", "authorize-security-group-ingress",
          "delete-security-group", "delete-key-pair", "delete-snapshot"):
    out({})
fail("unexpected aws call: " + " ".join(argv))
"""


class CloudTests(unittest.TestCase):
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

    def tearDown(self):
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

    def test_dry_run_plans_without_creating_anything(self):
        r = self.run_cli("aws", "relay", "--apply", "--dry-run", "--profile", "p", "--allow-from", "16.170.0.7")
        text = json.dumps(r["rows"])
        for expected in [
            "NitroTPM 2.0",
            "IMDSv2 only",
            "standard CPU credits",
            "udp 41194 from 16.170.0.7/32",
            "FREE",
        ]:
            self.assertIn(expected, text)
        self.assertTrue(r["dry_run"])
        creating = {"copy-image", "register-image", "run-instances", "create-security-group", "import-key-pair"}
        self.assertFalse(creating & set(self.ops()))

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
        self.assertEqual(opened, [("tcp", 22, ["18.0.0.4/32"]), ("udp", 41194, ["16.170.0.7/32"])])
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
                self.assertIn("Name=tag:avpn:name,Values=avpn-relay", c, c)
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


SSH_STUB = r"""#!/bin/sh
echo "$(basename "$0") $*" >> "$STUB_LOG.ssh"
case "$*" in
  *" true") exit 0 ;;
  *"bash -s -- "*) cat > "$STUB_DIR/remote-script.sh"; echo "tpm2=yes creds_key=host+tpm2" ;;
esac
"""
SCP_STUB = r"""#!/bin/sh
echo "scp $*" >> "$STUB_LOG.ssh"
for last in "$@"; do :; done
case "$last" in
  admin@*) for a in "$@"; do case "$a" in *.tgz) if [ -f "$a" ]; then cp "$a" "$STUB_DIR/sent.tgz"; fi ;; esac; done ;;
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
        self.assertIn("--protect systemd-creds", script)
        self.assertIn("already enrolled; not regenerating keys", script)
        # Root-run Python must not leave root-owned caches behind in the user's temp tree.
        self.assertIn("python3 -B /tmp/avpn-src/tools/install.py", script)
        # The system journal (sshd logs the admin's address) lives in RAM only.
        self.assertIn("Storage=volatile", script)
        self.assertIn("rm -rf /var/log/journal", script)
        log = (self.d / "log.ssh").read_text()
        self.assertIn("StrictHostKeyChecking=accept-new", log)
        self.assertIn("IdentityAgent=none", log)
        self.assertIn("bash -s -- relay", log)
        self.assertIn("tpm2=yes creds_key=host+tpm2", json.dumps(r["rows"]))
        self.assertEqual(
            json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay"]["request"], str(self.d / "relay.req")
        )

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


if __name__ == "__main__":
    unittest.main()

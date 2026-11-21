"""`avpn cloud rotate` against a recorded EC2 state machine: order, recovery, refusals.

The tests run the real module over a real subprocess boundary (the same
pattern test_cloud.py uses): a stub `aws` executable implements the EC2
address operations honestly — tag-filtered describes, allocation
ownership, association state, failure injection — so the refusals and
the recovery paths below are the code's real behavior, not a mock's.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cloud  # noqa: E402
import ip_rotation  # noqa: E402

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
def save():
    json.dump(state, open(os.environ["STUB_STATE"], "w"))
def flag(f):
    return argv[argv.index(f) + 1] if f in argv else None
def tagvals(i, k):
    return [t["Value"] for t in i.get("Tags", []) if t["Key"] == k]
if argv[:2] == ["configure", "get"]:
    out(state.get("region", "eu-north-1"))
if argv[:2] == ["sts", "get-caller-identity"]:
    out({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root"})
if argv[:1] == ["freetier"]:
    out({"accountPlanType": "FREE"})
op = argv[1] if len(argv) > 1 else ""
failmap = state.get("fail", {})
if op in failmap:
    fail("injected failure: " + str(failmap[op]))
once = state.get("fail_once", [])
if op in once:
    once.remove(op); save()
    fail("injected one-shot failure: " + op)
def matches(i):
    for a in argv:
        if not a.startswith("Name="):
            continue
        k, _, v = a[len("Name="):].partition(",Values=")
        if k == "instance-state-name":
            if i["State"]["Name"] not in v.split(","):
                return False
        elif k.startswith("tag:") and v not in tagvals(i, k[len("tag:"):]):
            return False
    return True
def instance_view(i):
    return i
if op == "describe-instances":
    if flag("--instance-ids"):
        ids = flag("--instance-ids").split()
        found = [i for i in state.get("instances", []) if i["InstanceId"] in ids]
        out({"Reservations": [{"Instances": found}]})
    out({"Reservations": [{"Instances": [i for i in state.get("instances", []) if matches(i)]}]})
if op == "describe-security-groups":
    out({"SecurityGroups": state.get("groups", [])})
if op == "describe-images" and flag("--owners") == "self":
    out({"Images": state.get("images", [])})
if op == "describe-snapshots":
    out({"Snapshots": state.get("snapshots", [])})
if op == "describe-key-pairs":
    out({"KeyPairs": state.get("keys", [])})
if op == "describe-instance-connect-endpoints":
    out({"InstanceConnectEndpoints": state.get("endpoints", [])})
if op == "describe-addresses":
    out({"Addresses": state.get("addresses", [])})
if op == "allocate-address":
    ips = state.setdefault("next_ips", [])
    ip = ips.pop(0) if ips else state.get("same_ip", None) or "16.0.0.10"
    n = state.get("alloc_seq", 1) + 1
    state["alloc_seq"] = n
    a = {"AllocationId": "eipalloc-%d" % n, "PublicIp": ip, "Domain": "vpc", "AssociationId": None, "InstanceId": None, "Tags": []}
    state.setdefault("addresses", []).append(a)
    save()
    out({"AllocationId": a["AllocationId"], "PublicIp": ip, "Domain": "vpc"})
def find_address(**kw):
    for a in state.get("addresses", []):
        if all(a.get(k) == v for k, v in kw.items()):
            return a
    return None
def set_assoc(a, iid):
    n = state.get("assoc_seq", 1) + 1
    state["assoc_seq"] = n
    a["AssociationId"] = "eipassoc-%d" % n
    a["InstanceId"] = iid
    for i in state.get("instances", []):
        if i["InstanceId"] == iid:
            i["PublicIpAddress"] = a["PublicIp"]
            i.setdefault("NetworkInterfaces", [{}])[0]["Association"] = {
                "AssociationId": a["AssociationId"], "AllocationId": a["AllocationId"], "IpOwnerId": "amazon"}
def clear_assoc(a):
    for i in state.get("instances", []):
        if i["InstanceId"] == a.get("InstanceId") and i.get("PublicIpAddress") == a["PublicIp"]:
            i.pop("PublicIpAddress", None)
            i.get("NetworkInterfaces", [{}])[0].pop("Association", None)
    a["AssociationId"] = None
    a["InstanceId"] = None
if op == "disassociate-address":
    a = find_address(AssociationId=flag("--association-id"))
    if not a:
        fail("An error occurred (InvalidAssociationID.NotFound)")
    clear_assoc(a); save(); out({"Return": True})
if op == "associate-address":
    a = find_address(AllocationId=flag("--allocation-id"))
    if not a:
        fail("An error occurred (InvalidAllocationID.NotFound)")
    set_assoc(a, flag("--instance-id")); save()
    out({"AssociationId": a["AssociationId"]})
if op == "release-address":
    a = find_address(AllocationId=flag("--allocation-id"))
    if not a:
        fail("An error occurred (InvalidAllocationID.NotFound)")
    if a.get("InstanceId"):
        fail("An error occurred (InvalidAddress.InUse)")
    state["addresses"].remove(a); save(); out({"Return": True})
if op == "create-tags":
    tags = []
    for part in argv[argv.index("--tags") + 1:]:
        k, _, v = part[len("Key="):].partition(",Value=")
        tags.append({"Key": k, "Value": v})
    for r in flag("--resources").split():
        a = find_address(AllocationId=r)
        if a:
            a["Tags"] += tags
    save(); out({"Return": True})
if op == "stop-instances":
    for i in state.get("instances", []):
        if i["InstanceId"] in flag("--instance-ids").split():
            i["State"]["Name"] = "stopped"
            i.pop("PublicIpAddress", None)
            i.get("NetworkInterfaces", [{}])[0].pop("Association", None)
    save(); out({"StoppingInstances": []})
if op == "start-instances":
    ips = state.setdefault("next_ips", [])
    for i in state.get("instances", []):
        if i["InstanceId"] in flag("--instance-ids").split():
            i["State"]["Name"] = "running"
            if not i.get("PublicIpAddress"):
                i["PublicIpAddress"] = ips.pop(0) if ips else "16.9.9.9"
                i.setdefault("NetworkInterfaces", [{}])[0]["Association"] = {"IpOwnerId": "amazon"}
    save(); out({"StartingInstances": []})
fail("unexpected aws call: " + " ".join(argv))
"""


def instance(
    ip="16.0.0.9",
    alloc="eipalloc-1",
    iid="i-1",
    name="avpn-exit",
    role="exit",
    state="running",
    managed=True,
    auto=False,
):
    tags = [dict(Key="Name", Value=name)]
    if managed:
        tags.append(dict(Key="avpn:managed", Value="true"))
    tags.append(dict(Key="avpn:name", Value=name))
    tags.append(dict(Key="avpn:role", Value=role))
    i = dict(InstanceId=iid, State=dict(Name=state), Tags=tags, SubnetId="subnet-1", VpcId="vpc-1")
    ni = (
        dict(Association=dict(AssociationId="eipassoc-1", AllocationId=alloc, IpOwnerId="amazon"))
        if (alloc and not auto)
        else {}
    )
    if ni:
        i["NetworkInterfaces"] = [ni]
        i["PublicIpAddress"] = ip
    elif auto:
        i["NetworkInterfaces"] = [dict(Association=dict(IpOwnerId="amazon"))]
        i["PublicIpAddress"] = ip
    return i


def address(ip="16.0.0.9", alloc="eipalloc-1", iid="i-1", name="avpn-exit", managed=True):
    tags = []
    if managed:
        tags.append(dict(Key="avpn:managed", Value="true"))
    tags.append(dict(Key="avpn:name", Value=name))
    return dict(
        AllocationId=alloc,
        PublicIp=ip,
        Domain="vpc",
        AssociationId="eipassoc-1" if iid else None,
        InstanceId=iid,
        Tags=tags,
    )


class Stubbed(unittest.TestCase):
    """One stubbed EC2, one inventory, no network, no sleeping."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        exe = d / "aws"
        exe.write_text(STUB.replace("#!/usr/bin/env python3", "#!" + sys.executable))
        exe.chmod(0o755)
        self.log, self.state = d / "log", d / "state.json"
        self.env = mock.patch.dict(
            os.environ, dict(AVPN_AWS=str(exe), STUB_LOG=str(self.log), STUB_STATE=str(self.state))
        )
        self.env.start()
        cfg = d / "config"
        self.inv = mock.patch.object(cloud, "INVENTORY", cfg / "cloud.json")
        self.inv.start()
        self.journal = mock.patch.object(ip_rotation, "journal_path", lambda: cfg / "rotation.jsonl")
        self.journal.start()
        self.nosleep = mock.patch.object(cloud.time, "sleep", lambda s: None)
        self.nosleep.start()
        self.set_state(dict(instances=[instance()], addresses=[address()], next_ips=["16.0.0.10"]))

    def tearDown(self):
        self.nosleep.stop()
        self.journal.stop()
        self.inv.stop()
        self.env.stop()
        self.tmp.cleanup()

    def set_state(self, value):
        self.state.write_text(json.dumps(value))

    def snapshot(self):
        return json.loads(self.state.read_text())

    def calls(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def ops(self):
        return [c[1] for c in self.calls() if c and c[0] == "ec2"]

    def eip_ops(self):
        wanted = (
            "disassociate-address",
            "allocate-address",
            "associate-address",
            "release-address",
            "stop-instances",
            "start-instances",
        )
        return [c[1] for c in self.calls() if c and c[0] == "ec2" and c[1] in wanted]

    def run_cli(self, *argv, **kw):
        a = cloud.build_parser().parse_args(["rotate", *argv])
        try:
            return cloud.run(a)
        except cloud.CloudError as e:
            if kw.get("fails"):
                return e
            raise

    def last_journal(self):
        return ip_rotation.load_journal()[-1]

    def apply(self, *extra, **kw):
        return self.run_cli("--name", "avpn-exit", "--tunnel-down", "--yes", *extra, **kw)


class Plans(Stubbed):
    def test_dry_run_changes_nothing_and_journals_the_plan(self):
        result = self.run_cli("--name", "avpn-exit", "--dry-run", "--reason", "netflix-blocked")
        rows = {r["label"]: r["value"] for r in result["rows"]}
        self.assertTrue(result["dry_run"])
        self.assertIn("Elastic IP", rows["step 1"])
        self.assertEqual(rows["address"], "16.0.0.9 (elastic)")
        self.assertIn("stream-check", rows["then 4"])
        self.assertEqual(self.eip_ops(), [], "a dry run must make no address calls")
        self.assertEqual(len(self.snapshot()["addresses"]), 1)
        self.assertEqual(self.last_journal()["outcome"], "planned")
        self.assertEqual(self.last_journal()["reason"], "netflix-blocked")

    def test_post_rotation_steps_name_the_re_enrollment(self):
        steps = {r["label"]: r["value"] for r in ip_rotation.post_rotation_steps("avpn-exit")}
        self.assertEqual(sorted(steps), ["then 1", "then 2", "then 3", "then 4"])
        self.assertIn("allow", steps["then 1"])
        self.assertIn("host setup", steps["then 2"])
        self.assertIn("chain --apply", steps["then 3"])


class Refusals(Stubbed):
    def test_apply_without_tunnel_down_attestation_is_refused(self):
        err = self.run_cli("--name", "avpn-exit", "--yes", fails=True)
        self.assertIn("tunnel", str(err))
        self.assertEqual(self.eip_ops(), [], "the refusal must come before any address call")
        self.assertEqual(self.last_journal()["outcome"], "refused")
        self.assertEqual(self.last_journal()["detail"], "tunnel not attested down")

    def test_instance_this_tool_did_not_tag_is_refused(self):
        self.set_state(dict(instances=[instance(managed=False)], addresses=[], next_ips=[]))
        err = self.run_cli("--name", "avpn-exit", "--tunnel-down", "--yes", fails=True)
        # Either refusal is correct: the provider-side tag filter, or the module's own
        # managed check on what came back; both are fail-closed and neither moves an IP.
        self.assertTrue("no instance tagged" in str(err) or "avpn:managed=true" in str(err), str(err))
        self.assertEqual(self.eip_ops(), [])

    def test_instance_with_another_name_is_not_found(self):
        self.set_state(dict(instances=[instance(name="avpn-relay", role="relay")], addresses=[], next_ips=[]))
        err = self.run_cli("--name", "avpn-exit", "--tunnel-down", "--yes", fails=True)
        self.assertIn("no instance tagged", str(err))

    def test_two_instances_under_one_name_is_refused(self):
        two = [instance(), instance(iid="i-2", alloc="eipalloc-2", ip="16.0.0.8")]
        self.set_state(dict(instances=two, addresses=[address()], next_ips=[]))
        err = self.run_cli("--name", "avpn-exit", "--tunnel-down", "--yes", fails=True)
        self.assertIn("2 instances", str(err))

    def test_stopped_instance_is_refused(self):
        self.set_state(dict(instances=[instance(state="stopped")], addresses=[address()], next_ips=[]))
        err = self.run_cli("--name", "avpn-exit", "--tunnel-down", "--yes", fails=True)
        self.assertIn("not running", str(err))


class EipRotate(Stubbed):
    def test_reallocate_trades_the_address_and_journals_it(self):
        result = self.apply("--reason", "netflix-blocked")
        rows = {r["label"]: r["value"] for r in result["rows"]}
        self.assertEqual(rows["was"], "16.0.0.9")
        self.assertEqual(rows["now"], "16.0.0.10")
        st = self.snapshot()
        self.assertEqual(len(st["addresses"]), 1, "the old allocation must be released")
        a = st["addresses"][0]
        self.assertEqual(a["PublicIp"], "16.0.0.10")
        self.assertEqual(a["InstanceId"], "i-1")
        self.assertIn(dict(Key="avpn:managed", Value="true"), a["Tags"], "the new allocation is tagged like the rest")
        entry = self.last_journal()
        self.assertEqual(entry["outcome"], "rotated")
        self.assertEqual(entry["old_ip"], "16.0.0.9")
        self.assertEqual(entry["new_ip"], "16.0.0.10")

    def test_the_order_is_disassociate_allocate_associate_release(self):
        self.apply()
        order = self.eip_ops()
        self.assertEqual(order, ["disassociate-address", "allocate-address", "associate-address", "release-address"])
        release = next(c for c in self.calls() if c[1] == "release-address")
        self.assertEqual(
            release[release.index("--allocation-id") + 1], "eipalloc-1", "the OLD allocation is released, and only last"
        )

    def test_allocate_failure_puts_the_old_address_back(self):
        st = self.snapshot()
        st["fail"] = {"allocate-address": "address pool exhausted"}
        self.set_state(st)
        err = self.apply(fails=True)
        self.assertIn("rotation failed", str(err))
        self.assertIn("16.0.0.9 is back", str(err))
        st = self.snapshot()
        ips = [a["PublicIp"] for a in st["addresses"]]
        self.assertEqual(ips, ["16.0.0.9"], "the old address is still owned")
        self.assertEqual(st["instances"][0].get("PublicIpAddress"), "16.0.0.9", "and re-attached")
        self.assertNotIn("release-address", self.ops())
        self.assertEqual(self.last_journal()["outcome"], "recovered")

    def test_associate_failure_recovers_and_releases_the_new_allocation(self):
        st = self.snapshot()
        st["fail_once"] = ["associate-address"]  # the first associate fails; recovery's succeeds
        self.set_state(st)
        err = self.apply(fails=True)
        self.assertIn("rotation failed", str(err))
        st = self.snapshot()
        self.assertEqual([a["PublicIp"] for a in st["addresses"]], ["16.0.0.9"])
        self.assertEqual(st["instances"][0].get("PublicIpAddress"), "16.0.0.9")
        release = [c for c in self.calls() if c[1] == "release-address"]
        self.assertEqual(len(release), 1)
        self.assertEqual(
            release[0][release[0].index("--allocation-id") + 1],
            "eipalloc-2",
            "the unusable NEW allocation is released, not the old one",
        )
        self.assertEqual(self.last_journal()["outcome"], "recovered")

    def test_unrecoverable_failure_is_the_loudest_possible_stop(self):
        st = self.snapshot()
        st["fail"] = {"associate-address": "association refused"}  # every associate fails
        self.set_state(st)
        err = self.apply(fails=True)
        self.assertIn("address-less", str(err))
        self.assertIn("re-attach an address by hand", str(err))
        entry = self.last_journal()
        self.assertEqual(entry["outcome"], "failed")
        self.assertIn("recovery both failed", entry["detail"])

    def test_the_same_address_back_is_an_honest_failure(self):
        st = self.snapshot()
        st["same_ip"] = "16.0.0.9"
        st["next_ips"] = []
        self.set_state(st)
        err = self.apply(fails=True)
        self.assertIn("same address", str(err))
        st = self.snapshot()
        self.assertEqual(st["instances"][0].get("PublicIpAddress"), "16.0.0.9", "the old address is re-attached")
        self.assertEqual(self.last_journal()["outcome"], "same-ip")
        self.assertIn("reprovision", self.last_journal()["detail"])


class AutoRotate(Stubbed):
    def setUp(self):
        super().setUp()
        self.set_state(dict(instances=[instance(auto=True, alloc=None)], addresses=[], next_ips=["16.20.0.7"]))

    def test_auto_assigned_ip_trades_on_stop_start(self):
        result = self.apply()
        rows = {r["label"]: r["value"] for r in result["rows"]}
        self.assertEqual(rows["was"], "16.0.0.9")
        self.assertEqual(rows["now"], "16.20.0.7")
        self.assertEqual(self.eip_ops(), ["stop-instances", "start-instances"])
        st = self.snapshot()
        self.assertEqual(st["instances"][0]["State"]["Name"], "running")
        self.assertEqual(self.last_journal()["outcome"], "rotated")

    def test_a_failed_start_is_retried_once_and_can_succeed(self):
        st = self.snapshot()
        st["fail_once"] = ["start-instances"]
        self.set_state(st)
        result = self.apply()
        rows = {r["label"]: r["value"] for r in result["rows"]}
        self.assertEqual(rows["now"], "16.20.0.7")
        self.assertEqual(self.ops().count("start-instances"), 2)
        self.assertEqual(self.last_journal()["outcome"], "rotated")

    def test_two_failed_starts_leave_a_loud_stopped_exit(self):
        st = self.snapshot()
        st["fail"] = {"start-instances": "capacity unavailable"}
        self.set_state(st)
        err = self.apply(fails=True)
        self.assertIn("left STOPPED", str(err))
        self.assertEqual(self.snapshot()["instances"][0]["State"]["Name"], "stopped")
        entry = self.last_journal()
        self.assertEqual(entry["outcome"], "failed")
        self.assertIn("STOPPED", entry["detail"])


class Reprovision(Stubbed):
    def test_reprovision_plans_the_two_existing_commands(self):
        result = self.run_cli("--name", "avpn-exit", "--strategy", "reprovision")
        rows = {r["label"]: r["value"] for r in result["rows"]}
        self.assertIn("--teardown", rows["step 1"])
        self.assertIn("--apply", rows["step 2"])
        self.assertIn("stream-check", rows["then 4"])
        self.assertEqual(self.eip_ops(), [], "reprovision is planned, never improvised here")
        self.assertEqual(self.last_journal()["outcome"], "planned")
        self.assertEqual(self.last_journal()["strategy"], "reprovision")

    def test_a_new_region_hits_the_one_region_guard(self):
        err = self.run_cli("--name", "avpn-exit", "--strategy", "reprovision", "--region", "us-east-1", fails=True)
        self.assertIn("resources cannot be created in us-east-1", str(err))


class OciAndJournal(Stubbed):
    def test_oci_gets_the_manual_stop_start_plan(self):
        inv = cloud.load_inventory()
        inv["resources"]["avpn-exit"] = dict(provider="oci", role="exit", port=4444)
        cloud.save_inventory(inv)
        result = self.run_cli("--name", "avpn-exit", "--reason", "netflix-blocked")
        rows = {r["label"]: r["value"] for r in result["rows"]}
        self.assertEqual(rows["provider"], "oci")
        self.assertIn("--action STOP", rows["step 1"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.eip_ops(), [])
        self.assertEqual(self.last_journal()["outcome"], "planned")

    def test_the_journal_is_append_only_across_runs(self):
        self.run_cli("--name", "avpn-exit", "--dry-run")
        self.apply()
        self.run_cli("--name", "avpn-exit", "--yes", fails=True)  # refused: no attestation
        entries = ip_rotation.load_journal()
        self.assertEqual([e["outcome"] for e in entries], ["planned", "rotated", "refused"])
        self.assertTrue(all(e["schema"] == 1 for e in entries))
        self.assertTrue(all("at" in e for e in entries), "every entry is dated")


if __name__ == "__main__":
    unittest.main()

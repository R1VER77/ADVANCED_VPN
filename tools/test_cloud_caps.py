"""`avpn cloud cap` and the usage rows of `avpn cloud health` (tools/cloud.py): caps planned
per account before any change, written where the server reads them, and every server's
month shown against its cap."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cloud  # noqa: E402
import fee_guard  # noqa: E402

GB = fee_guard.GB
NOW = fee_guard.datetime.datetime(2026, 11, 11, tzinfo=fee_guard.datetime.timezone.utc).timestamp()


def inventory(**extra):
    resources = {
        "avpn-relay": dict(provider="aws", profile="p1", region="eu-north-1", role="relay"),
        "avpn-exit": dict(provider="ssh", catalog="oci", bastion=dict(oci_profile="DEFAULT"), role="exit"),
        "avpn-old": dict(provider="aws", profile="p1", role="exit"),  # recorded, not in the chain
    }
    resources.update(extra)
    return dict(schema=1, chain=dict(hops=["avpn-relay", "avpn-exit"]), resources=resources)


class Planning(unittest.TestCase):
    def test_caps_come_from_the_catalog_provider_and_ignore_idle_records(self):
        caps = cloud.plan_caps(inventory(), ["avpn-relay", "avpn-exit"])
        self.assertEqual(caps["avpn-relay"][0], 90 * GB)  # avpn-old is not in the chain
        self.assertEqual(caps["avpn-exit"][0], 9000 * GB)

    def test_a_standby_in_the_same_account_shares_the_allowance(self):
        inv = inventory(**{"avpn-standby": dict(provider="aws", profile="p1", role="exit", standby=True)})
        self.assertEqual(cloud.plan_caps(inv, ["avpn-relay"])["avpn-relay"][0], 45 * GB)

    def test_a_server_with_no_allowance_on_record_stops_the_build(self):
        inv = inventory(**{"avpn-home": dict(provider="own", role="middle")})
        inv["chain"]["hops"].append("avpn-home")
        with self.assertRaisesRegex(cloud.CloudError, "no monthly cap for avpn-home"):
            cloud.require_caps(inv, inv["chain"]["hops"])
        inv["resources"]["avpn-home"]["unlimited"] = True
        self.assertIsNone(cloud.require_caps(inv, inv["chain"]["hops"])["avpn-home"][0])

    def test_two_fly_machines_in_one_organization_are_refused(self):
        inv = inventory(**{n: dict(provider="fly", account="me", region="fra", role="exit") for n in ("f1", "f2")})
        with self.assertRaisesRegex(cloud.CloudError, "waiver"):
            cloud.plan_caps(inv, ["f1", "f2"])

    def test_the_chain_build_decides_caps_before_it_changes_anything(self):
        import inspect

        src = inspect.getsource(cloud.chain_steps)
        self.assertLess(src.index("require_caps("), src.index("set_firewall("))
        self.assertLess(src.index("push_cap("), src.index("stdin=HOST_ENROLL"))


class FlyInTheChain(unittest.TestCase):
    def test_the_rate_allowance_divides_each_cap_by_the_streams_its_hop_sends(self):
        hops = [dict(name="r", role="relay"), dict(name="f", role="exit")]
        caps = {"r": (90 * GB, ""), "f": (55 * GB, "")}
        # The relay sends two streams: 45 GB each, tighter than the exit's 55 GB.
        self.assertEqual(cloud.per_link_allowance_gib(hops, caps), int(90 * GB) >> 30)
        caps["f"] = (30 * GB, "")  # now the exit binds: 30 GB for its one stream
        self.assertEqual(cloud.per_link_allowance_gib(hops, caps), int(60 * GB) >> 30)

    def test_a_fly_server_is_a_hop_and_ipv6_sources_are_slash_128(self):
        inv = dict(schema=1, resources={
            "avpn-relay": dict(provider="aws", public_ip="198.51.100.1", ssh_key="k"),
            "avpn-fly": dict(provider="fly", catalog="fly", public_ip="2001:db8::4", app="a", machine="m"),
        })  # fmt: skip
        with mock.patch.object(cloud, "load_inventory", lambda: inv):
            self.assertIn("avpn-fly", cloud.servers())
        hops = cloud.chain_layout(["avpn-fly", "avpn-relay"], inv["resources"])
        self.assertEqual(hops[1]["sources"], ["2001:db8::4/128"])
        self.assertEqual(cloud.hostport("2001:db8::4", 4444), "[2001:db8::4]:4444")
        self.assertEqual(cloud.remote("avpn-fly", inv["resources"]["avpn-fly"])[2:], (["--app", "a"], "m"))


class Command(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name) / "cloud.json"
        path.write_text(json.dumps(inventory()))
        patch = mock.patch.object(cloud, "INVENTORY", path)
        patch.start()
        self.addCleanup(patch.stop)
        self.pushed = []
        p2 = mock.patch.object(cloud, "push_cap", lambda n, r, c, w: self.pushed.append((n, c)))
        p2.start()
        self.addCleanup(p2.stop)

    def args(self, **kw):
        base = dict(name=None, gb=None, unlimited=False, auto=False, apply=False)
        base.update(kw)
        import argparse

        return argparse.Namespace(**base)

    def test_plan_writes_nothing_and_apply_writes_every_hop(self):
        cloud.cap(self.args())
        self.assertEqual(self.pushed, [])
        cloud.cap(self.args(apply=True))
        self.assertEqual(dict(self.pushed), {"avpn-relay": 90 * GB, "avpn-exit": 9000 * GB})

    def test_an_owner_cap_is_recorded_and_auto_restores_the_allowance(self):
        cloud.cap(self.args(name="avpn-relay", gb=20, apply=True))
        self.assertEqual(self.pushed[-1], ("avpn-relay", 20 * GB))
        self.assertEqual(json.loads(cloud.INVENTORY.read_text())["resources"]["avpn-relay"]["cap_gb"], 20)
        cloud.cap(self.args(name="avpn-relay", auto=True, apply=True))
        self.assertEqual(self.pushed[-1], ("avpn-relay", 90 * GB))

    def test_push_writes_root_only_beside_the_enrolled_state(self):
        mock.patch.stopall()  # this test calls the real push_cap
        sent = {}

        def fake_call(argv, parse=True, stdin=None):
            sent.update(argv=argv, stdin=stdin)

        with (
            mock.patch.object(cloud, "remote", lambda n, r: ("ssh", "scp", [], "host")),
            mock.patch.object(cloud, "call", fake_call),
        ):
            cloud.push_cap("avpn-relay", {}, 5 * GB, "why")
        self.assertIn("/etc/advanced-vpn/metering/enrolled/cap.json", sent["argv"][-1])
        self.assertIn("umask 077", sent["argv"][-1])
        self.assertEqual(json.loads(sent["stdin"])["cap_bytes"], 5 * GB)


class Health(unittest.TestCase):
    def setUp(self):
        cloud.LAST_MONTHLY.clear()

    def test_a_running_server_reports_its_live_month(self):
        live = dict(month="2026-11", used_bytes=50 * GB, cap_bytes=90 * GB, capped=False, resumes="2026-12-01")
        lines = ["active=active mode=x unlocked=0", "status=" + json.dumps(dict(state="supervising", monthly=live))]
        self.assertEqual(cloud.monthly_row("r", lines, NOW)["used_bytes"], 50 * GB)
        rows, problems = cloud.usage_rows(["r"])
        self.assertIn("50.0 of 90 GB", rows[0]["value"])
        self.assertEqual(problems, [])

    def test_a_stopped_server_is_read_from_its_files_and_a_new_month_starts_at_zero(self):
        files = dict(usage=dict(month="2026-10", bytes=80 * GB), cap=dict(cap_bytes=90 * GB))
        lines = ["active=inactive", "status={}", "metering=" + json.dumps(files)]
        self.assertEqual(cloud.monthly_row("r", lines, NOW)["used_bytes"], 0)

    def test_near_the_cap_or_on_pace_to_reach_it_is_a_problem(self):
        files = dict(usage=dict(month="2026-11", bytes=75 * GB), cap=dict(cap_bytes=90 * GB))
        cloud.monthly_row("r", ["active=inactive", "metering=" + json.dumps(files)], NOW)
        rows, problems = cloud.usage_rows(["r"])
        self.assertTrue(problems and "at this pace" in problems[0], problems)

    def test_a_missing_cap_is_a_problem(self):
        files = dict(usage=dict(month="2026-11", bytes=GB), cap=None)
        cloud.monthly_row("r", ["active=active", "metering=" + json.dumps(files)], NOW)
        rows, problems = cloud.usage_rows(["r"])
        self.assertIn("NO CAP SET", rows[0]["value"])
        self.assertIn("could be billed", problems[0])

    def test_a_capped_server_is_named_as_such(self):
        live = dict(month="2026-11", used_bytes=90 * GB, cap_bytes=90 * GB, capped=True, resumes="2026-12-01T00:00:00")
        rec = dict(provider="aws", profile="p", instance="i-1")
        out = json.dumps(dict(Reservations=[dict(Instances=[dict(State=dict(Name="running"))])]))
        lines = "active=active mode=systemd-creds unlocked=0\nstatus=%s\n" % json.dumps(
            dict(state="capped", monthly=live)
        )
        with (
            mock.patch.object(cloud.Aws, "ec2", lambda self, *a: json.loads(out)),
            mock.patch.object(cloud, "remote", lambda n, r: ("ssh", "scp", [], "h")),
            mock.patch.object(cloud, "call", lambda *a, **k: lines),
        ):
            state, problem, fix = cloud.server_health("r", rec)
        self.assertIn("CAPPED", state)
        self.assertIn("never billed", problem)
        self.assertIn("2026-12-01", fix)


class Updates(unittest.TestCase):
    def row(self, line, rec=None):
        cloud.updates_row("s", rec or {}, ["active=active", line], NOW)
        return cloud.LAST_UPDATES.get("s")

    def test_fresh_overdue_and_never_applied(self):
        self.assertIsNone(self.row("updates=%d image=no shared=no" % (NOW - 86400))[1])
        text, problem = self.row("updates=%d image=no shared=no" % (NOW - 5 * 86400))
        self.assertIn("overdue", problem)
        self.assertIn("host update --name s", problem)
        self.assertIn("never applied", self.row("updates=0 image=no shared=no")[0])

    def test_a_shared_host_is_its_owners_and_an_image_host_is_judged_by_its_image(self):
        self.assertIsNone(self.row("updates=0 image=no shared=yes")[1])
        new = self.row("updates=0 image=yes shared=no", dict(image="registry.fly.io/a:20261110T000000Z"))
        self.assertIsNone(new[1])
        old = self.row("updates=0 image=yes shared=no", dict(image="registry.fly.io/a:20261001T000000Z"))
        self.assertIn("rebuild", old[1])


if __name__ == "__main__":
    unittest.main()

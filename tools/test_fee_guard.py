"""The fee guard (tools/fee_guard.py): caps that keep a free account free, and a meter that
survives restarts, reboots and the turn of the month without ever undercounting."""

import datetime
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fee_guard as fg  # noqa: E402

GB = fg.GB


def ts(*args):
    return datetime.datetime(*args, tzinfo=datetime.timezone.utc).timestamp()


class Host:
    """A fake /sys/class/net and boot id."""

    def __init__(self, root):
        self.root = Path(root)
        self.net = self.root / "net"
        self.net.mkdir()
        self.boot = self.root / "boot_id"
        self.boot.write_text("boot-1\n")
        self.t = ts(2026, 11, 10)

    def iface(self, name, tx, tun=False):
        d = self.net / name / "statistics"
        d.mkdir(parents=True, exist_ok=True)
        (d / "tx_bytes").write_text(str(tx))
        if tun:
            (self.net / name / "tun_flags").write_text("0x1001")

    def meter(self):
        return fg.Meter(self.root / "usage.json", sysfs=self.net, boot_id=self.boot, now=lambda: self.t)


class MeterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Host(self.tmp.name)

    def test_counts_every_interface_but_loopback_and_tun(self):
        self.h.iface("lo", 10 * GB)
        self.h.iface("eth0", 3 * GB)
        self.h.iface("docker0", 1 * GB)
        self.h.iface("avpn0", 7 * GB, tun=True)
        self.assertEqual(self.h.meter().sample(), 4 * GB)

    def test_a_restart_on_the_same_boot_never_undercounts(self):
        self.h.iface("eth0", 1 * GB)
        m = self.h.meter()
        m.sample()
        self.h.iface("eth0", 2 * GB)
        m.sample()
        # The supervisor restarts: the saved counters were rounded down, the total up.
        self.h.iface("eth0", 3 * GB)
        again = self.h.meter().sample()
        self.assertGreaterEqual(again, 3 * GB)
        self.assertLess(again, 3 * GB + 2 * fg.STEP)

    def test_a_reboot_keeps_the_month_and_adds_what_was_sent_since(self):
        self.h.iface("eth0", 5 * GB)
        self.h.meter().sample()
        self.h.boot.write_text("boot-2\n")
        self.h.iface("eth0", 1 * GB)  # counters restart at boot
        self.assertGreaterEqual(self.h.meter().sample(), 6 * GB)

    def test_the_month_turns_over_at_utc_midnight_on_the_first(self):
        self.h.iface("eth0", 5 * GB)
        m = self.h.meter()
        m.sample()
        self.h.t = ts(2026, 12, 1, 0, 0, 1)
        self.h.iface("eth0", 5 * GB + 100)
        self.assertEqual(m.sample(), 100)
        self.assertEqual(json.loads((self.h.root / "usage.json").read_text())["month"], "2026-12")

    def test_a_clock_set_back_never_reopens_an_earlier_month(self):
        self.h.iface("eth0", 5 * GB)
        m = self.h.meter()
        self.h.t = ts(2026, 12, 2)
        m.sample()
        self.h.t = ts(2026, 11, 30)
        self.h.iface("eth0", 6 * GB)
        self.assertEqual(m.sample(), 6 * GB)
        self.assertEqual(m.month, "2026-12")

    def test_a_counter_source_replaces_the_interfaces_and_survives_a_reset(self):
        counts = {"vpn": 1000}
        m = fg.Meter(self.h.root / "u.json", sysfs=self.h.net, boot_id=self.h.boot, now=lambda: self.h.t,
                     source=lambda: dict(counts))  # fmt: skip
        self.h.iface("eth0", 9 * GB)  # other workloads: not counted
        self.assertEqual(m.sample(), 1000)
        counts["vpn"] = 300  # the table was reinstalled: its counter restarted
        self.assertEqual(m.sample(), 1300)

    def test_an_interface_that_vanishes_does_not_inflate_the_count(self):
        self.h.iface("eth0", 9 * GB)
        self.h.iface("veth1", 1 * GB)
        m = self.h.meter()
        m.sample()
        import shutil

        shutil.rmtree(self.h.net / "veth1")
        self.h.iface("eth0", 9 * GB + 5)
        self.assertEqual(m.sample(), 10 * GB + 5)

    def test_the_file_holds_one_rounded_number_and_nothing_per_session(self):
        self.h.iface("eth0", 12345)
        self.h.meter().sample()
        saved = json.loads((self.h.root / "usage.json").read_text())
        self.assertEqual(saved["bytes"] % fg.STEP, 0)
        self.assertGreaterEqual(saved["bytes"], 12345)
        self.assertEqual(set(saved), {"schema", "month", "bytes", "boot", "counters"})
        self.assertEqual(oct((self.h.root / "usage.json").stat().st_mode & 0o777), "0o600")


class CapTests(unittest.TestCase):
    def test_an_account_allowance_is_shared_by_its_servers(self):
        caps = fg.plan_caps({
            "relay-a": dict(provider="aws", account="p1"),
            "relay-b": dict(provider="aws", account="p1"),
            "relay-c": dict(provider="aws", account="p2"),
            "exit": dict(provider="oci", account="t1"),
        })  # fmt: skip
        self.assertEqual(caps["relay-a"][0], 45 * GB)  # 90% of 100 GB, halved
        self.assertEqual(caps["relay-c"][0], 90 * GB)
        self.assertEqual(caps["exit"][0], 9000 * GB)
        self.assertIn("shared by 2", caps["relay-a"][1])

    def test_fly_keeps_the_whole_bill_under_the_waiver(self):
        ((cap, why),) = fg.plan_caps({"x": dict(provider="fly", region="fra", memory_mb=256, volume_gb=1)}).values()
        fixed = 2.19 * fg.FLY_REGION_FACTOR + 0.15
        bill = fixed + cap / GB * 0.02
        self.assertLess(bill, 5.0 - 0.99)
        self.assertIn("waiver", why)
        # Two machines in one organization already cost more than the waiver leaves
        # (2 x $2.78): only one Fly.io server per personal organization can stay free.
        with self.assertRaisesRegex(fg.FeeGuardError, "2 machine"):
            fg.plan_caps({n: dict(provider="fly", region="fra") for n in ("a", "b")})
        # A machine too dear for the waiver is refused, not capped at zero.
        with self.assertRaisesRegex(fg.FeeGuardError, "nothing under"):
            fg.plan_caps({"big": dict(provider="fly", region="fra", memory_mb=1024)})

    def test_an_unknown_region_is_priced_at_the_dearest_rate(self):
        self.assertEqual(fg.fly_region_group("xyz"), "africa_india")

    def test_no_allowance_on_record_means_no_cap_and_says_how_to_set_one(self):
        cap, why = fg.plan_caps({"home": dict(provider="own")})["home"]
        self.assertIsNone(cap)
        self.assertIn("--gb", why)
        self.assertEqual(fg.plan_caps({"home": dict(provider="own", unlimited=True)})["home"][0], None)
        self.assertEqual(fg.plan_caps({"home": dict(provider="own", cap_gb=50)})["home"][0], 50 * GB)

    def test_cap_files_round_trip_and_malformed_ones_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m" / "cap.json"
            self.assertEqual(fg.read_cap(p), ("missing", None))
            fg.write_cap(p, 5 * GB, "test")
            self.assertEqual(fg.read_cap(p), ("bytes", 5 * GB))
            fg.write_cap(p, None, "own box")
            self.assertEqual(fg.read_cap(p), ("unlimited", None))
            p.write_text('{"cap_bytes": -1}')
            with self.assertRaises(fg.FeeGuardError):
                fg.read_cap(p)

    def test_the_verdict_projects_when_the_cap_is_reached(self):
        t = ts(2026, 11, 11)  # a third of November
        row = fg.verdict(50 * GB, 100 * GB, t)
        self.assertFalse(row["capped"])
        self.assertEqual(row["resumes"][:10], "2026-12-01")
        self.assertTrue(row["runs_out"].startswith("2026-11-2"))  # 150 GB/month pace: ~21 Nov
        self.assertTrue(fg.verdict(100 * GB, 100 * GB, t)["capped"])
        self.assertIn("CAPPED", fg.describe(fg.verdict(100 * GB, 100 * GB, t)))
        self.assertNotIn("runs_out", fg.verdict(10 * GB, 100 * GB, t))
        self.assertEqual(fg.verdict(10, None, t)["capped"], False)

    def test_metering_lives_beside_the_enrolled_state(self):
        cap, usage = fg.paths("/etc/advanced-vpn/enrolled")
        self.assertEqual(str(cap), "/etc/advanced-vpn/metering/enrolled/cap.json")
        self.assertEqual(str(usage), "/etc/advanced-vpn/metering/enrolled/usage.json")


if __name__ == "__main__":
    unittest.main()

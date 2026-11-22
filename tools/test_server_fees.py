"""The supervisor's daily security update (avpnctl.ServerFees.security_update): when it runs,
when it does not, and that it opens the counted maintenance window while it runs."""

import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import avpnctl  # noqa: E402


class SecurityUpdate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        self.calls = d / "calls"
        fake = d / "bin" / "unattended-upgrade"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\necho ran >> %s\n" % self.calls)
        fake.chmod(0o755)
        for name in ("apt-get", "sleep", "systemctl"):
            (d / "bin" / name).write_text("#!/bin/sh\nexit 0\n")
            (d / "bin" / name).chmod(0o755)
        # systemd-run: record its arguments, then run what follows "--" (the real one would
        # start a unit on this machine).
        self.unit_args = d / "unit-args"
        (d / "bin" / "systemd-run").write_text(
            '#!/bin/sh\nprintf "%%s\\n" "$@" > %s\nwhile [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n'
            % self.unit_args
        )
        (d / "bin" / "systemd-run").chmod(0o755)
        patch = mock.patch.dict(os.environ, PATH=str(d / "bin") + ":" + os.environ["PATH"])
        patch.start()
        self.addCleanup(patch.stop)
        f = avpnctl.ServerFees.__new__(avpnctl.ServerFees)
        f.lab = f.shared = f.image = False
        f.cap = 100
        f.last_update_path = d / "last-update"
        f.maintenance_path = d / "maintenance-until"
        f.update_proc, f.update_started, f.update_retry_at = None, 0.0, 0.0
        self.f = f

    def finish(self):
        self.f.update_proc.wait(timeout=10)
        self.f.security_update(time.time(), 0)

    def test_due_runs_once_opens_the_window_and_records_success(self):
        self.f.security_update(time.time(), 0)
        self.assertIsNotNone(self.f.update_proc)
        self.assertTrue(self.f.in_maintenance(time.time()))
        self.finish()
        self.assertEqual(self.calls.read_text(), "ran\n")
        self.assertTrue(self.f.last_update_path.exists())
        self.assertFalse(self.f.in_maintenance(time.time()))
        self.f.security_update(time.time(), 0)  # done today: not again
        self.assertIsNone(self.f.update_proc)

    def test_not_on_a_capped_shared_image_or_lab_host(self):
        for attr, value, used in (("cap", 100, 100), ("shared", True, 0), ("image", True, 0), ("lab", True, 0)):
            with self.subTest(attr):
                old = getattr(self.f, attr)
                setattr(self.f, attr, value)
                self.f.security_update(time.time(), used)
                self.assertIsNone(self.f.update_proc)
                setattr(self.f, attr, old)

    def test_the_update_runs_in_its_own_unit_with_download_timeouts(self):
        """The supervisor's sandbox (RestrictSUIDSGID) stopped dpkg installing sudo's update:
        the update runs as a transient unit, ended by its own limit before the window closes."""
        self.f.security_update(time.time(), 0)
        self.finish()
        args = self.unit_args.read_text().splitlines()
        self.assertEqual(args[:3], ["--wait", "--collect", "--quiet"])
        self.assertIn("--unit=" + avpnctl.ServerFees.UPDATE_UNIT, args)
        limit = int(next(a for a in args if a.startswith("--property=RuntimeMaxSec=")).split("=")[-1])
        self.assertLess(limit, avpnctl.ServerFees.UPDATE_TIMEOUT)
        script = args[args.index("--") + 3]
        self.assertIn("Acquire::https::Timeout=30", script)
        self.assertEqual(self.calls.read_text(), "ran\n")

    def test_a_failed_update_waits_an_hour_before_trying_again(self):
        (Path(self.tmp.name) / "bin" / "apt-get").write_text("#!/bin/sh\nexit 100\n")
        now = time.time()
        self.f.security_update(now, 0)
        self.f.update_proc.wait(timeout=10)
        self.f.security_update(now + 5, 0)  # collected: failed
        self.assertFalse(self.f.last_update_path.exists())
        self.f.security_update(now + 10, 0)  # not straight away: it held apt's lock and the window
        self.assertIsNone(self.f.update_proc)
        self.assertFalse(self.f.in_maintenance(now + 10))
        self.f.security_update(now + 10 + avpnctl.ServerFees.UPDATE_RETRY, 0)
        self.assertIsNotNone(self.f.update_proc)
        self.f.update_proc.wait(timeout=10)

    def test_a_hung_update_is_killed_and_retried_next_day(self):
        (Path(self.tmp.name) / "bin" / "unattended-upgrade").write_text("#!/bin/sh\nexec sleep 60\n")
        (Path(self.tmp.name) / "bin" / "sleep").unlink()  # the real sleep
        now = time.time()
        self.f.security_update(now, 0)
        self.f.security_update(now + avpnctl.ServerFees.UPDATE_TIMEOUT + 1, 0)
        self.assertIsNone(self.f.update_proc)
        self.assertFalse(self.f.last_update_path.exists())


class FrontRouterEgress(unittest.TestCase):
    """A server's I2P front runs i2pd under its own user: the egress lock must let it out,
    and only it (and the data plane), or the router never reaches the I2P network."""

    def lock(self, front_uid):
        import server_egress

        f = avpnctl.ServerFees.__new__(avpnctl.ServerFees)
        f.se, f.uid, f.front_uid, f.maintenance, f.lab = server_egress, 1001, front_uid, False, False
        f.profile = dict(role="relay", network=dict(relay_endpoint="198.51.100.1:443"))
        f.cfg = dict(core=dict(listen="10.78.0.1:4444"), cloak=dict(listen="0.0.0.0:8443"))
        return f.egress_text()

    def test_the_front_router_may_send_and_no_other_user_may(self):
        text = self.lock(1002)
        self.assertIn("meta skuid 1001 accept", text)
        self.assertIn("meta skuid 1002 accept", text)
        self.assertNotIn("skuid 0 accept", text)

    def test_an_update_window_lets_out_root_and_the_users_its_updates_need(self):
        """apt downloads as _apt and names resolve through the resolver's own user: a window
        admitting root alone left both shut, and every update hung holding apt's lock."""
        import server_egress

        f = avpnctl.ServerFees.__new__(avpnctl.ServerFees)
        f.se, f.uid, f.front_uid, f.maintenance, f.lab = server_egress, 1001, None, True, False
        f.profile = dict(role="relay", network=dict(relay_endpoint="198.51.100.1:443"))
        f.cfg = dict(core=dict(listen="10.78.0.1:4444"), cloak=dict(listen="0.0.0.0:8443"))
        with mock.patch.object(avpnctl.ServerFees, "update_helper_uids", return_value=[42, 990]):
            text = f.egress_text()
            self.assertIn("meta skuid 0 accept", text)
            self.assertIn("meta skuid 42 accept", text)
            self.assertIn("meta skuid 990 accept", text)
            f.maintenance = False
            closed = f.egress_text()
        for uid in (0, 42, 990):
            self.assertNotIn("meta skuid %d accept" % uid, closed)

    def test_the_window_users_are_looked_up_on_the_host_and_missing_ones_skipped(self):
        import pwd

        users = {"_apt": 42, "systemd-resolve": 990}

        def getpwnam(name):
            if name not in users:
                raise KeyError(name)
            return mock.Mock(pw_uid=users[name])

        with mock.patch.object(pwd, "getpwnam", side_effect=getpwnam):
            self.assertEqual(avpnctl.ServerFees.__new__(avpnctl.ServerFees).update_helper_uids(), [42, 990])

    def test_without_a_front_only_the_data_plane_may_send(self):
        text = self.lock(None)
        self.assertIn("meta skuid 1001 accept", text)
        self.assertEqual(text.count("meta skuid"), 1)


if __name__ == "__main__":
    unittest.main()

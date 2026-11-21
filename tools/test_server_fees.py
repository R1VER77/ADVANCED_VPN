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
        for name in ("apt-get", "sleep"):
            (d / "bin" / name).write_text("#!/bin/sh\nexit 0\n")
            (d / "bin" / name).chmod(0o755)
        patch = mock.patch.dict(os.environ, PATH=str(d / "bin") + ":" + os.environ["PATH"])
        patch.start()
        self.addCleanup(patch.stop)
        f = avpnctl.ServerFees.__new__(avpnctl.ServerFees)
        f.lab = f.shared = f.image = False
        f.cap = 100
        f.last_update_path = d / "last-update"
        f.maintenance_path = d / "maintenance-until"
        f.update_proc, f.update_started = None, 0.0
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

    def test_a_hung_update_is_killed_and_retried_next_day(self):
        (Path(self.tmp.name) / "bin" / "unattended-upgrade").write_text("#!/bin/sh\nexec sleep 60\n")
        (Path(self.tmp.name) / "bin" / "sleep").unlink()  # the real sleep
        now = time.time()
        self.f.security_update(now, 0)
        self.f.security_update(now + avpnctl.ServerFees.UPDATE_TIMEOUT + 1, 0)
        self.assertIsNone(self.f.update_proc)
        self.assertFalse(self.f.last_update_path.exists())


if __name__ == "__main__":
    unittest.main()

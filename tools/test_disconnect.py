"""`disconnect` stops whatever is actually running (bug 8), and reports honestly.

Two levels: the controller's stop_supervisor (SIGTERM, then confirm the exit), and
the Rust front end, which must ask the controller even when `systemctl stop` has
already succeeded — an inactive unit stops nothing, and a `connect --foreground`
supervisor is invisible to systemctl.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import cypherpunkctl

ROOT = Path(__file__).resolve().parents[1]
CYPHERPUNK = ROOT / "target/release/cypherpunk"

IGNORES_SIGTERM = (
    "import signal, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "print('ready', flush=True)\n"
    "while True:\n"
    "    time.sleep(1)\n"
)


@unittest.skipIf(os.geteuid() == 0, "CPVPN_RUNTIME_ROOT is ignored by root by design")
class StopSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.state = self.d / "state"
        self.state.mkdir(mode=0o700)
        self.rt_env = mock.patch.dict(os.environ, {"CPVPN_RUNTIME_ROOT": str(self.d / "run")})
        self.rt_env.start()

    def tearDown(self):
        self.rt_env.stop()
        self.tmp.cleanup()

    def record(self, pid, identity):
        cypherpunkctl.save(cypherpunkctl.runtime_dir(self.state) / "controller.json", dict(pid=pid, identity=identity))

    def test_a_live_supervisor_is_signalled_and_confirmed_stopped(self):
        p = subprocess.Popen(["sleep", "30"])
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        self.record(p.pid, cypherpunkctl.identity_of(p.pid))
        self.assertTrue(cypherpunkctl.stop_supervisor(self.state))
        deadline = time.monotonic() + 5
        while p.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertIsNotNone(p.poll(), "the supervisor must actually exit, not just be signalled")

    def test_no_record_or_a_stale_pid_means_nothing_was_running(self):
        self.assertFalse(cypherpunkctl.stop_supervisor(self.state))
        self.record(999999, "not-a-real-identity")
        self.assertFalse(cypherpunkctl.stop_supervisor(self.state))

    def test_a_supervisor_that_ignores_sigterm_is_an_error_not_a_success(self):
        # Wait for the child's own readiness line, so the SIGTERM cannot land during
        # interpreter startup, before the ignore handler is installed.
        p = subprocess.Popen([sys.executable, "-c", IGNORES_SIGTERM], stdout=subprocess.PIPE, text=True)
        self.addCleanup(p.wait)
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), "ready")
        self.record(p.pid, cypherpunkctl.identity_of(p.pid))
        with self.assertRaisesRegex(RuntimeError, "did not stop"):
            cypherpunkctl.stop_supervisor(self.state, timeout=1)


@unittest.skipUnless(CYPHERPUNK.exists(), "build the release cypherpunk binary first")
@unittest.skipIf(os.geteuid() == 0, "root ignores CPVPN_CONTROLLER and CPVPN_SYSTEMCTL by design")
class DisconnectActionTests(unittest.TestCase):
    """The front end asks the controller to stop a foreground supervisor even when
    `systemctl stop` succeeds (the bug-8 case: an inactive unit, a running terminal)."""

    def run_cypherpunk(self, systemctl_body, controller_body):
        with tempfile.TemporaryDirectory() as d:
            calls = Path(d) / "calls"
            ctl = Path(d) / "cypherpunkctl"
            ctl.write_text("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s\n%s\n" % (json.dumps(str(calls)), controller_body))
            sc = Path(d) / "systemctl"
            sc.write_text("#!/bin/sh\n%s\n" % systemctl_body)
            for f in (ctl, sc):
                f.chmod(0o755)
                os.chown(f, os.getuid(), os.getgid())
                m = f.stat()
                assert stat.S_ISREG(m.st_mode) and not m.st_mode & 0o022
            env = dict(os.environ, CPVPN_CONTROLLER=str(ctl), CPVPN_SYSTEMCTL=str(sc), TERM="xterm-256color")
            r = subprocess.run([str(CYPHERPUNK), "disconnect"], capture_output=True, text=True, env=env, timeout=30)
            seen = calls.read_text() if calls.exists() else ""
            return r, seen

    def test_the_controller_is_asked_even_when_systemctl_succeeds(self):
        ok = 'echo \'{"ok": true, "message": "Supervisor stopped; the kill switch stays in place."}\''
        r, seen = self.run_cypherpunk("exit 0", ok)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("disconnect", seen, "a successful systemctl stop must not skip the controller")
        self.assertIn("Disconnected", r.stdout)
        self.assertIn("Supervisor stopped", r.stdout)

    def test_without_systemd_a_stopped_foreground_supervisor_is_still_success(self):
        ok = 'echo \'{"ok": true, "message": "Supervisor stopped; the kill switch stays in place."}\''
        r, seen = self.run_cypherpunk("echo 'not booted' >&2; exit 1", ok)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("disconnect", seen)
        self.assertIn("Disconnected", r.stdout)

    def test_both_paths_failing_is_failure(self):
        refusing = 'echo \'{"ok": false, "error": "RuntimeError", "message": "no root"}\'; exit 1'
        r, seen = self.run_cypherpunk("exit 1", refusing)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("disconnect", seen)

    def test_a_refused_controller_is_fine_when_the_service_stopped(self):
        # A user without root: polkit stopped the service, the controller cannot run.
        refusing = 'echo \'{"ok": false, "error": "RuntimeError", "message": "no root"}\'; exit 1'
        r, _ = self.run_cypherpunk("exit 0", refusing)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Disconnected", r.stdout)

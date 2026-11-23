#!/usr/bin/env python3
"""The maintenance window `chain --apply` and `host update` open on a server before apt
runs (cloud.APT_WINDOW), executed by the shell against stand-ins for the host's tools.

On 22 November a rebuild failed at "Install cpvpn-relay": the relay's supervisor held
apt's lock with an update that could never finish, because its window let out root but
not apt's download user or the resolver. The window now gives way, waits and recovers.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cloud  # noqa: E402

TOOLS = {
    # sudo -n CMD...: run the stand-in for CMD (never the real one)
    "sudo": '[ "$1" = -n ] && shift\nexec "$@"',
    "timeout": 'shift\nexec "$@"',
    "sleep": "exit 0",
    "install": 'echo "install $*" >> "$LOG"',
    "tee": 'cat > /dev/null\necho "tee $*" >> "$LOG"',
    "rm": 'echo "rm $*" >> "$LOG"',
    "nft": 'echo "nft $*" >> "$LOG"',
    "systemctl": 'echo "systemctl $*" >> "$LOG"\n'
    'if [ "$1" = is-active ]; then [ -f "$STATE/active" ]; exit $?; fi\n'
    'if [ "$1" = stop ] && [ "$2" = cypherpunk-vpn.service ]; then /bin/rm -f "$STATE/active"; fi\n'
    'if [ "$1" = start ]; then : > "$STATE/active"; fi\n'
    "exit 0",
    "getent": '[ -f "$STATE/resolves" ] || [ ! -f "$STATE/active" ]',
    # apt-get: the lock is held for the first $BUSY attempts
    "apt-get": 'echo "apt-get $*" >> "$LOG"\n'
    'n=$(cat "$STATE/tries" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$STATE/tries"\n'
    '[ "$n" -gt "${BUSY:-0}" ]',
}


class AptWindow(unittest.TestCase):
    def run_window(self, restart, active=True, resolves=True, busy=0, then=0):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / "bin").mkdir()
        (d / "state").mkdir()
        for name, body in TOOLS.items():
            (d / "bin" / name).write_text("#!/bin/sh\n" + body + "\n")
            (d / "bin" / name).chmod(0o755)
        if active:
            (d / "state" / "active").write_text("")
        if resolves:
            (d / "state" / "resolves").write_text("")
        script = "set -e\nRESTART=%s\n%s\n%s\nexit %d\n" % (restart, cloud.APT_WINDOW, cloud.APT_UPDATE, then)
        env = dict(os.environ, PATH="%s:/usr/bin:/bin" % (d / "bin"), LOG=str(d / "log"), STATE=str(d / "state"),
                   BUSY=str(busy))  # fmt: skip
        result = subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True, text=True, timeout=30)
        log = (d / "log").read_text().splitlines() if (d / "log").exists() else []
        return result.returncode, log, (d / "state" / "active").exists()

    def test_a_working_window_stops_the_daily_update_and_keeps_the_supervisor(self):
        code, log, active = self.run_window("on-failure")
        self.assertEqual(code, 0)
        self.assertIn("systemctl stop cypherpunk-vpn-security-update.service", log)
        self.assertNotIn("systemctl stop cypherpunk-vpn.service", log)
        self.assertTrue(active)
        update = [x for x in log if x.startswith("apt-get")]
        self.assertEqual(len(update), 1)
        self.assertIn("DPkg::Lock::Timeout=600", update[0])
        self.assertIn("Acquire::https::Timeout=30", update[0])
        self.assertTrue(update[0].endswith("update -qq"))

    def test_apt_waits_for_a_lock_another_update_holds(self):
        code, log, _ = self.run_window("on-failure", busy=3)
        self.assertEqual(code, 0)
        self.assertEqual(len([x for x in log if x.startswith("apt-get")]), 4)

    def test_a_lock_that_never_frees_fails_the_step_after_its_tries(self):
        code, log, _ = self.run_window("on-failure", busy=1000)
        self.assertNotEqual(code, 0)
        self.assertEqual(len([x for x in log if x.startswith("apt-get")]), 30)

    def test_an_old_supervisor_that_blocks_names_is_stopped_and_its_lock_lifted(self):
        code, log, active = self.run_window("on-failure", resolves=False)
        self.assertEqual(code, 0)
        self.assertIn("systemctl stop cypherpunk-vpn.service", log)
        self.assertIn("nft delete table inet cypherpunk_vpn_egress", log)
        self.assertFalse(active)  # setup succeeded: the chain starts the new supervisor

    def test_a_failed_setup_brings_the_old_supervisor_back(self):
        code, log, active = self.run_window("on-failure", resolves=False, then=3)
        self.assertEqual(code, 3)
        self.assertIn("systemctl start cypherpunk-vpn.service", log)
        self.assertTrue(active)

    def test_a_host_update_always_restarts_what_it_stopped(self):
        code, log, active = self.run_window("always", resolves=False)
        self.assertEqual(code, 0)
        self.assertTrue(active)
        # and never starts a supervisor it did not stop
        code, log, active = self.run_window("always", active=False, resolves=True)
        self.assertNotIn("systemctl start cypherpunk-vpn.service", log)
        self.assertFalse(active)

    def test_the_window_is_closed_on_every_exit(self):
        for then in (0, 1):
            with self.subTest(then=then):
                _, log, _ = self.run_window("on-failure", then=then)
                self.assertIn("rm -f /etc/cypherpunk-vpn/metering/enrolled/maintenance-until", log)

    def test_both_server_scripts_open_the_same_window(self):
        for script in (cloud.HOST_SETUP, cloud.HOST_UPDATE):
            self.assertIn(cloud.APT_WINDOW.rstrip("\n"), script)
            self.assertIn(cloud.APT_UPDATE.rstrip("\n"), script)
            self.assertNotIn("@@", script)
        self.assertIn("RESTART=on-failure", cloud.HOST_SETUP)
        self.assertIn("RESTART=always", cloud.HOST_UPDATE)


if __name__ == "__main__":
    unittest.main()

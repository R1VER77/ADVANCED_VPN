"""The interactive `avpn` view in a real pseudo-terminal, driven by key presses."""

import fcntl
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
AVPN = ROOT / "target/release/avpn"
CTL = """#!/bin/sh
case "$*" in
  *info*) echo '{"ok": true, "info": {"enrolled": true, "role": "client", "hops": 2, "protection": "nitrokey", "mode": "applications", "defense": "balanced", "chain": [{"hop": "relay", "endpoint": "16.0.0.8:41194"}, {"hop": "exit", "endpoint": "16.0.0.9:4444"}], "status": {"state": "supervising"}}}' ;;
  *hops*) sleep 0.3; echo '{"ok": true, "hops": 2, "chain": [{"hop": "relay", "endpoint": "16.0.0.8:41194"}, {"hop": "exit", "endpoint": "16.0.0.9:4444"}]}' ;;
  *doctor*) echo '{"ok": true, "healthy": true, "checks": [{"check": "trusted nft", "ok": true, "detail": "/usr/sbin/nft"}]}' ;;
esac
"""
UNENROLLED = """#!/bin/sh
echo '{"ok": true, "info": {"enrolled": false}}'
"""


def screen(stream, rows=30, cols=100):
    """What a terminal shows after `stream`: enough VT100 for ratatui (cursor moves,
    erase, SGR ignored). Returns the alternate screen as it was just before quitting."""
    import re

    grid = [[" "] * cols for _ in range(rows)]
    y = x = 0
    last = None
    for m in re.finditer(r"\x1b\[([?0-9;]*)([A-Za-z])|([^\x1b])", stream):
        params, final, ch = m.groups()
        if ch is not None:
            if ch == "\r":
                x = 0
            elif ch == "\n":
                y = min(y + 1, rows - 1)
            elif 0 <= y < rows and 0 <= x < cols:
                grid[y][x] = ch
                x += 1
        elif final == "H":
            parts = (params or "1;1").split(";")
            y, x = int(parts[0] or 1) - 1, int(parts[1] if len(parts) > 1 else 1) - 1
        elif final == "J":
            grid = [[" "] * cols for _ in range(rows)]
        elif final == "l" and params == "?1049":
            last = ["".join(r).rstrip() for r in grid]
    return last or ["".join(r).rstrip() for r in grid]


class InteractiveView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not AVPN.exists():
            raise RuntimeError("build the release binary before TUI tests")

    def setUp(self):
        if os.geteuid() == 0 and self._testMethodName != "test_root_ignores_the_controller_override":
            self.skipTest("as root, avpn ignores AVPN_CONTROLLER by design (see the root test)")

    def test_root_ignores_the_controller_override(self):
        if os.geteuid() != 0:
            self.skipTest("needs root")
        r = subprocess.run(
            [str(AVPN), "hops"], env=dict(os.environ, AVPN_CONTROLLER="/bin/true"), capture_output=True, text=True
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/opt/advanced-vpn/bin/avpnctl", r.stderr)

    def drive(self, keys, colour=True, controller=CTL):
        with tempfile.TemporaryDirectory() as d:
            ctl = Path(d) / "avpnctl"
            ctl.write_text(controller)
            ctl.chmod(0o755)
            env = dict(os.environ, AVPN_CONTROLLER=str(ctl), TERM="xterm-256color", COLUMNS="100", LINES="30")
            env.pop("NO_COLOR", None)
            if not colour:
                env["NO_COLOR"] = "1"
            pid, fd = pty.fork()
            if pid == 0:
                os.execve(str(AVPN), [str(AVPN), "--reduced-motion"], env)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
            out = b""

            def pump(seconds):
                nonlocal out
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    r, _, _ = select.select([fd], [], [], 0.05)
                    if r:
                        try:
                            out += os.read(fd, 65536)
                        except OSError:
                            return

            pump(1.0)
            for k in keys:
                os.write(fd, k.encode())
                pump(0.8)
            _, status = os.waitpid(pid, 0)
            return out.decode("utf-8", "replace"), os.waitstatus_to_exitcode(status)

    def test_keys_run_actions_and_q_restores_the_terminal(self):
        out, code = self.drive(["h", "o", "q"])
        self.assertEqual(code, 0)
        s = screen(out)
        text = "\n".join(s)
        self.assertTrue(s[0].startswith("╭") and s[6].startswith("╰"), text)
        self.assertIn("│ >_ ADVANCED VPN (v", s[1])
        self.assertIn("│ chain:      client → relay → exit", s[3])
        self.assertIn("│ protection: nitrokey · service supervising", s[5])
        for expected in [
            "$ avpn hops",
            "• Chain  2-hop",
            "  └ client → relay 16.0.0.8:41194 → exit 16.0.0.9:4444",
            "$ avpn doctor",
            "• Doctor  1 passed · 0 failed",
            "  ✓ trusted nft  /usr/sbin/nft",
        ]:
            self.assertIn(expected, s, text)
        self.assertEqual(s[29], " c connect · d disconnect · h hops · s status · i info · o doctor · ? help · q quit")
        self.assertIn("\x1b[?1049h", out, "alternate screen entered")
        self.assertIn("\x1b[?1049l", out, "alternate screen left on quit")

    def test_a_device_that_is_not_enrolled_is_shown_where_to_start(self):
        out, code = self.drive(["q"], controller=UNENROLLED)
        self.assertEqual(code, 0)
        text = "\n".join(screen(out))
        for expected in [
            "chain:      not enrolled",
            "• Get started  this device is not enrolled yet",
            "Oracle Cloud: no expiry   10 TiB/month out",
            "avpn cloud suggest",
            "avpn cloud chain --apply",
        ]:
            self.assertIn(expected, text)
        # Google's free tier cannot carry a hop, so it is not suggested here.
        self.assertNotIn("Google", text)

    def test_help_key_lists_every_key(self):
        s = screen(self.drive(["?", "q"])[0])
        self.assertIn("• Keys  every action is also a command", s)
        self.assertIn("  └ c          connect", s)

    def test_working_indicator_is_static_with_reduced_motion(self):
        out, _ = self.drive(["h", "q"])
        self.assertIn("Working on hops", out)
        for frame in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏":
            self.assertNotIn(frame, out)

    def test_no_color_drops_colour_codes(self):
        out, _ = self.drive(["h", "q"], colour=False)
        self.assertIn("• Chain  2-hop", screen(out))
        for sgr in ["\x1b[31m", "\x1b[32m", "\x1b[35m", "\x1b[36m", "38;5;", "38;2;"]:
            self.assertNotIn(sgr, out)


if __name__ == "__main__":
    unittest.main()

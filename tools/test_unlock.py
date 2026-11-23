"""The service's Nitrokey PIN prompt: `status` names it, `unlock` waits for it.

Live regression (14 Nov 2026): `sudo cypherpunk connect && sudo cypherpunkctl unlock` showed
"Status: not running" while the service was waiting for the PIN, and `unlock` ran
before the service had posted its request, found none, and exited silently."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import cypherpunkctl

CTL = Path(__file__).resolve().parent / "cypherpunkctl.py"

# The ask file systemd-ask-password writes (systemd's password agent protocol).
ASK = "[Ask]\nPID=1234\nSocket=/run/systemd/ask-password/sck.1\nAcceptCached=0\nEcho=0\nNotAfter=0\nMessage=PIN\nId={id}\n"


class PinPendingTests(unittest.TestCase):
    def test_only_the_services_pin_request_counts(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            self.assertFalse(cypherpunkctl.pin_pending(d))
            (d / "ask.other").write_text(ASK.format(id="cryptsetup:/dev/sda2"))
            self.assertFalse(cypherpunkctl.pin_pending(d))
            (d / "ask.vpn").write_text(ASK.format(id="cypherpunk-vpn:fido2-pin"))
            self.assertTrue(cypherpunkctl.pin_pending(d))
            # A prefix of the id is not the id.
            (d / "ask.vpn").write_text(ASK.format(id="cypherpunk-vpn:fido2-pin-old"))
            self.assertFalse(cypherpunkctl.pin_pending(d))

    def test_a_missing_or_unreadable_directory_is_not_a_request(self):
        self.assertFalse(cypherpunkctl.pin_pending(Path("/nonexistent/ask-password")))
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "ask.vpn"
            f.write_text(ASK.format(id="cypherpunk-vpn:fido2-pin"))
            f.chmod(0)
            if os.geteuid() != 0:  # root reads it anyway
                self.assertFalse(cypherpunkctl.pin_pending(Path(d)))


class UnlockWaitTests(unittest.TestCase):
    def test_unlock_waits_for_the_request_while_the_service_starts(self):
        seen = iter([False, False, False, True, True])
        with (
            mock.patch.object(cypherpunkctl, "pin_pending", lambda: next(seen)),
            mock.patch.object(cypherpunkctl, "service_active", lambda: True),
            mock.patch.object(cypherpunkctl.time, "sleep") as slept,
        ):
            self.assertTrue(cypherpunkctl.wait_for_pin_request(60))
        self.assertGreaterEqual(slept.call_count, 2)

    def test_unlock_does_not_wait_for_a_service_that_is_not_running(self):
        with (
            mock.patch.object(cypherpunkctl, "pin_pending", lambda: False),
            mock.patch.object(cypherpunkctl, "service_active", lambda: False),
            mock.patch.object(cypherpunkctl.time, "sleep") as slept,
        ):
            self.assertFalse(cypherpunkctl.wait_for_pin_request(60))
        slept.assert_not_called()

    def test_unlock_gives_up_after_its_window(self):
        clock = iter(range(0, 1000, 10))
        with (
            mock.patch.object(cypherpunkctl, "pin_pending", lambda: False),
            mock.patch.object(cypherpunkctl, "service_active", lambda: True),
            mock.patch.object(cypherpunkctl.time, "sleep"),
            mock.patch.object(cypherpunkctl.time, "monotonic", lambda: next(clock)),
        ):
            self.assertFalse(cypherpunkctl.wait_for_pin_request(60))


class StatusWordingTests(unittest.TestCase):
    def test_status_says_waiting_while_the_pin_is_pending(self):
        # Through the real --json interface, with the request directory pointed at a
        # temporary one holding the service's request.
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ask = d / "ask"
            ask.mkdir()
            (ask / "ask.vpn").write_text(ASK.format(id="cypherpunk-vpn:fido2-pin"))
            code = (
                "import sys, runpy; from pathlib import Path\n"
                "sys.path.insert(0, %r)\n"
                "import cypherpunkctl; cypherpunkctl.ASK_DIR = Path(%r)\n"
                "cypherpunkctl.runtime_dir = lambda state, create=True: Path(%r)\n"
                "sys.argv = ['cypherpunkctl', '--json', '--state', %r, 'status']\n"
                "cypherpunkctl.main()\n"
            ) % (str(CTL.parent), str(ask), str(d / "rt"), str(d / "state"))
            r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
            status = json.loads(r.stdout.strip().splitlines()[-1])["status"]
            self.assertEqual(status, {"state": "waiting for the Nitrokey PIN", "next": "sudo cypherpunk unlock"})
            (ask / "ask.vpn").unlink()
            r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
            self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["status"], {"state": "not running"})


class AnswerTests(unittest.TestCase):
    """`cypherpunk unlock` answers the service's request itself (systemd's password agent
    protocol), so the PIN prompt is ours: a pop-up or a labelled terminal prompt."""

    def ask(self, d, name, ident, sock, not_after=0):
        (d / name).write_text(
            "[Ask]\nPID=1\nSocket=%s\nAcceptCached=0\nEcho=0\nNotAfter=%d\nMessage=PIN\nId=%s\n"
            % (sock, not_after, ident)
        )

    def test_finds_only_the_services_live_request(self):
        import time

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            self.assertIsNone(cypherpunkctl.pending_pin_request(d))
            self.ask(d, "ask.a", "cryptsetup:/dev/sda2", "/x/other")
            past = int(time.monotonic() * 1e6) - 1_000_000
            self.ask(d, "ask.b", "cypherpunk-vpn:fido2-pin", "/x/expired", not_after=past)
            self.assertIsNone(cypherpunkctl.pending_pin_request(d))
            self.ask(d, "ask.c", "cypherpunk-vpn:fido2-pin", "/x/live", not_after=0)
            sock, f = cypherpunkctl.pending_pin_request(d)
            self.assertEqual((str(sock), f.name), ("/x/live", "ask.c"))

    def test_the_answer_is_one_plus_prefixed_datagram(self):
        import socket

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sck.1"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            server.bind(str(path))
            server.settimeout(3)
            try:
                cypherpunkctl.answer_pin_request((path, None), "123456")
                self.assertEqual(server.recv(64), b"+123456")
            finally:
                server.close()

    def test_status_prefers_a_pending_pin_over_a_stale_file(self):
        # Live regression (15 Nov 2026): connect showed "blocked / disconnected" from the
        # previous run while the service was waiting for the PIN.
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            ask = d / "ask"
            ask.mkdir()
            rt = d / "rt"
            rt.mkdir()
            (rt / "status.json").write_text(json.dumps({"state": "blocked", "reason": "disconnected"}))
            (ask / "ask.vpn").write_text(ASK.format(id="cypherpunk-vpn:fido2-pin"))
            code = (
                "import sys; from pathlib import Path\n"
                "sys.path.insert(0, %r)\n"
                "import cypherpunkctl; cypherpunkctl.ASK_DIR = Path(%r)\n"
                "cypherpunkctl.runtime_dir = lambda state, create=True: Path(%r)\n"
                "cypherpunkctl.read_private = lambda p, *a: Path(p).read_bytes()\n"
                "sys.argv = ['cypherpunkctl', '--json', '--state', %r, 'status']\n"
                "cypherpunkctl.main()\n"
            ) % (str(CTL.parent), str(ask), str(rt), str(d / "state"))
            run = lambda: json.loads(  # noqa: E731
                subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
                .stdout.strip()
                .splitlines()[-1]
            )["status"]
            self.assertEqual(run()["state"], "waiting for the Nitrokey PIN")
            (ask / "ask.vpn").unlink()
            self.assertEqual(run(), {"state": "blocked", "reason": "disconnected"})


if __name__ == "__main__":
    unittest.main()

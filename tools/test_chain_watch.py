"""A chain that stops answering is made obvious (tools/chain_watch.py): one desktop notice
per outage, one when it answers again, and a notice in `cypherpunk status`."""

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chain_watch as cw  # noqa: E402

UP = dict(protection="protected")
DOWN = dict(protection="blocked")


class Watch(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.w = cw.ChainWatch(lambda title, body: self.sent.append((title, body)), started=1000)

    def test_a_chain_that_never_answers_is_announced_once_after_the_start_grace(self):
        self.assertEqual(self.w.observe(1000 + cw.START_GRACE - 1, DOWN), {})
        self.assertEqual(self.sent, [])
        fields = self.w.observe(1000 + cw.START_GRACE, DOWN)
        self.assertIn("no answer through the chain", fields["detail"])
        self.assertIn("cypherpunk cloud health", fields["next"])
        self.w.observe(1000 + cw.START_GRACE + 300, DOWN)
        self.assertEqual(len(self.sent), 1)  # once per outage, not every loop
        self.assertEqual(self.sent[0][0], "VPN chain not answering")
        self.assertIn("locked after a reboot", self.sent[0][1])

    def test_an_outage_after_it_worked_then_recovery(self):
        self.w.observe(1010, UP)
        self.assertEqual(self.w.observe(1020, DOWN), {})
        self.assertEqual(self.w.observe(1020 + cw.DOWN_GRACE - 1, DOWN), {})
        self.assertTrue(self.w.observe(1020 + cw.DOWN_GRACE, DOWN))
        self.assertEqual(self.w.observe(1200, UP), {})
        self.assertEqual([t for t, _ in self.sent], ["VPN chain not answering", "VPN protected again"])
        # A blip shorter than the grace raises nothing.
        self.w.observe(1300, DOWN)
        self.w.observe(1300 + cw.DOWN_GRACE - 5, DOWN)
        self.w.observe(1300 + cw.DOWN_GRACE - 1, UP)
        self.assertEqual(len(self.sent), 2)


class Notify(unittest.TestCase):
    def test_root_notifies_as_the_person_and_nothing_without_a_desktop(self):
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw))
            return mock.Mock(returncode=0)

        with (
            mock.patch("sysexec.trusted_exe", lambda name: "/usr/bin/" + name),
            mock.patch.object(cw.os, "geteuid", lambda: 0),
        ):
            self.assertTrue(cw.desktop_notify("t", "b", target=(1000, 1000, {"X": "1"}), run=run))
            self.assertFalse(cw.desktop_notify("t", "b", target=False, run=run))
        argv, kw = calls[0]
        self.assertEqual(argv[0], "/usr/bin/notify-send")
        self.assertEqual((kw["user"], kw["group"], kw["env"]), (1000, 1000, {"X": "1"}))
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()

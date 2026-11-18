"""A desktop must not manufacture protection from stale or contradictory evidence."""

import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import controller_status as status


class PublicVerdict(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.now = time.time()
        self.value = dict(
            state="supervising",
            scope="whole-device",
            protection="protected",
            kill_switch=True,
            children=dict(carrier=dict(pid=42, identity="child-start", alive=True)),
            evidence=dict(cloak_confirmed_at=self.now, carrier_handshake_at=self.now, path_probe_at=self.now),
        )
        self.controller = dict(pid=41, identity="controller-start")

    def write(self):
        for name, value in (("status.json", self.value), ("controller.json", self.controller)):
            path = self.root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            os.utime(path, (self.now, self.now))

    def read(self, identity=None):
        self.write()
        identity = identity or (lambda pid: {41: "controller-start", 42: "child-start"}.get(pid))
        return status.verified(self.root, self.now, identity)

    def test_fresh_status_requires_all_evidence_and_reports_actual_active_scope(self):
        result = self.read()
        self.assertEqual(
            (result["protection"], result["scope"], result["kill_switch"]), ("protected", "whole-device", "active")
        )

    def test_stale_or_reused_process_is_unknown(self):
        self.assertEqual(self.read(lambda _: "reused")["protection"], "unknown")
        self.write()
        self.assertEqual(
            status.verified(self.root, self.now + 2, lambda _: "controller-start")["protection"], "unknown"
        )

    def test_no_guard_or_missing_scope_is_unknown(self):
        for field in ("scope", "kill_switch"):
            previous = self.value.pop(field)
            self.assertEqual(self.read()["protection"], "unknown")
            self.value[field] = previous

    def test_malformed_or_future_or_old_evidence_cannot_report_connected(self):
        for value in (True, float("nan"), self.now + 5, self.now - 20, None):
            with self.subTest(evidence=value):
                self.value["evidence"]["carrier_handshake_at"] = value
                self.assertEqual(self.read()["protection"], "unknown")

    def test_only_explicit_fresh_guarded_blocked_report_can_say_blocked(self):
        self.value.update(protection="blocked", state="blocked", evidence=None, children={})
        self.assertEqual(self.read()["protection"], "blocked")
        self.value["kill_switch"] = False
        self.assertEqual(self.read()["protection"], "unknown")

    def test_missing_or_private_status_file_is_unknown(self):
        self.assertEqual(status.verified(self.root, self.now)["protection"], "unknown")
        self.write()
        (self.root / "status.json").chmod(0o644)
        self.assertEqual(status.verified(self.root, self.now)["protection"], "unknown")

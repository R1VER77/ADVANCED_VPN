"""Tests for tools/protection.py: the controller's verified-protection verdict."""

import socket
import struct
import threading
import unittest

import protection as p


class Verdict(unittest.TestCase):
    def ev(self, now, cloak=True, carrier=True, probe_age=1.0, cloak_age=0.5, carrier_age=0.5):
        e = p.Evidence()
        e.observe(
            now,
            cloak=dict(connected=cloak), cloak_mtime=now - cloak_age,
            carrier=dict(handshake=carrier), carrier_mtime=now - carrier_age,
            probe_at=None if probe_age is None else now - probe_age,
        )  # fmt: skip
        return e

    def test_all_fresh_evidence_is_protected_with_the_evidence_shown(self):
        v = self.ev(1000).verdict(1000, supervising=True, kill_switch=True)
        self.assertEqual((v["lifecycle"], v["protection"]), ("connected", "protected"))
        self.assertEqual(set(v["evidence"]), {"cloak_confirmed_at", "carrier_handshake_at", "path_probe_at"})

    def test_any_missing_piece_is_blocked_never_protected(self):
        for kw in (dict(cloak=False), dict(carrier=False), dict(probe_age=None), dict(probe_age=16),
                   dict(cloak_age=4), dict(carrier_age=4)):  # fmt: skip
            with self.subTest(**kw):
                v = self.ev(1000, **kw).verdict(1000, supervising=True, kill_switch=True)
                self.assertEqual(v["protection"], "blocked")
                self.assertIsNone(v["evidence"])

    def test_without_the_kill_switch_or_the_supervisor_it_is_never_protected(self):
        for sup, ks in ((False, True), (True, False)):
            v = self.ev(1000).verdict(1000, supervising=sup, kill_switch=ks)
            self.assertEqual((v["lifecycle"], v["protection"]), ("blocked", "blocked"))

    def test_connecting_before_the_first_verdict_reconnecting_after_one_lapses(self):
        e = p.Evidence()
        self.assertEqual(e.verdict(1000, True, True)["lifecycle"], "connecting")
        e.observe(1001, dict(connected=True), 1001, dict(handshake=True), 1001, 1001)
        self.assertEqual(e.verdict(1001, True, True)["lifecycle"], "connected")
        # Nothing new for 20 s: the probe evidence is stale.
        v = e.verdict(1021, True, True)
        self.assertEqual((v["lifecycle"], v["protection"]), ("reconnecting", "blocked"))
        self.assertEqual(v["since"], 1021)

    def test_a_stale_status_file_does_not_count_even_if_it_says_connected(self):
        e = p.Evidence()
        e.observe(1000, dict(connected=True), 990, dict(handshake=True), 999.5, 999)  # cloak file 10 s old
        self.assertEqual(e.verdict(1000, True, True)["protection"], "blocked")


class Dns(unittest.TestCase):
    def test_the_query_is_well_formed(self):
        q = p.dns_query(0x1234)
        qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", q[:12])
        self.assertEqual((qid, flags, qd, an, ns, ar), (0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(q[12:], b"\x05probe\x05cpvpn\x07invalid\x00" + b"\x00\x01\x00\x01")
        with self.assertRaises(ValueError):
            p.dns_query(70000)

    def test_only_a_response_with_our_id_counts(self):
        q = bytearray(p.dns_query(7))
        self.assertFalse(p.is_answer(bytes(q), 7))  # a query, not a response
        q[2] |= 0x80
        q[3] = (q[3] & 0xF0) | 3  # NXDOMAIN: still an answer from the resolver
        self.assertTrue(p.is_answer(bytes(q), 7))
        self.assertFalse(p.is_answer(bytes(q), 8))
        self.assertFalse(p.is_answer(b"\x00\x07\x80", 7))  # truncated

    def test_the_probe_records_an_answer_from_a_resolver_and_ignores_others(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def resolver():
            data, addr = server.recvfrom(512)
            wrong = bytearray(data)
            wrong[2] |= 0x80
            wrong[0] ^= 0xFF  # a reply with another id: must not count
            server.sendto(bytes(wrong), addr)
            stranger.sendto(bytes(wrong[:2]) + b"\x80" + bytes(wrong[3:]), addr)  # from another address
            right = bytearray(data)
            right[2] |= 0x80
            server.sendto(bytes(right), addr)

        t = threading.Thread(target=resolver)
        t.start()
        probe = p.PathProbe(None, server=server.getsockname(), timeout=2, clock=lambda: 42.0)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            self.assertTrue(probe.once(s))
        t.join()
        self.assertEqual(probe.ok_at, 42.0)
        server.close()
        stranger.close()

    def test_no_answer_records_nothing(self):
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        probe = p.PathProbe(None, server=silent.getsockname(), timeout=0.3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            self.assertFalse(probe.once(s))
        self.assertIsNone(probe.ok_at)
        silent.close()


class Retry(unittest.TestCase):
    def test_a_lost_probe_is_retried_after_a_second_not_the_full_interval(self):
        answers = iter([False, False, True, True])
        waits = []

        class Fake(p.PathProbe):
            def once(self, sock):
                return next(answers)

        probe = Fake(None, every=5.0)

        def wait(seconds):
            waits.append(seconds)
            if len(waits) == 4:
                probe.stop.set()
            return probe.stop.is_set()

        probe.stop.wait = wait
        probe.run()
        self.assertEqual(waits, [p.PROBE_RETRY, p.PROBE_RETRY, 5.0, 5.0])


class StatusFields(unittest.TestCase):
    """cypherpunkctl.verdict_fields: the supervisor's status files and probe, read for real."""

    def setUp(self):
        import tempfile
        from pathlib import Path

        self.tmp = tempfile.TemporaryDirectory()
        self.rt = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, body, age=0.0, now=1000.0):
        import json
        import os

        f = self.rt / (name + "-status.json")
        f.write_text(json.dumps(body))
        os.utime(f, (now - age, now - age))

    def test_fresh_files_and_a_recent_probe_are_protected(self):
        import cypherpunkctl

        self.write("cloak", dict(connected=True))
        self.write("carrier", dict(handshake=True))
        probe = type("P", (), {"ok_at": 998.0, "diagnostics": {"consecutive_failures": 0, "last_attempt_ms": 22}})()
        v = cypherpunkctl.verdict_fields(p.Evidence(), probe, self.rt, supervising=True, now=1000.0)
        self.assertEqual((v["lifecycle"], v["protection"]), ("connected", "protected"))
        self.assertEqual(v["path_check"], {"consecutive_failures": 0, "last_attempt_ms": 22})

    def test_a_stale_or_missing_file_or_no_probe_is_blocked(self):
        import cypherpunkctl

        cases = [
            (dict(connected=True), 0, dict(handshake=True), 0, None),  # no probe yet
            (dict(connected=True), 9, dict(handshake=True), 0, 998.0),  # cloak file stale: its writer died
            (None, 0, dict(handshake=True), 0, 998.0),  # no cloak status at all
            (dict(connected=False), 0, dict(handshake=True), 0, 998.0),  # cloak not (yet) confirmed
        ]
        for cloak, cage, carrier, kage, probe_at in cases:
            with self.subTest(cloak=cloak, age=cage, probe=probe_at):
                for f in self.rt.iterdir():
                    f.unlink()
                if cloak is not None:
                    self.write("cloak", cloak, cage)
                self.write("carrier", carrier, kage)
                probe = type("P", (), {"ok_at": probe_at, "diagnostics": None})()
                v = cypherpunkctl.verdict_fields(p.Evidence(), probe, self.rt, supervising=True, now=1000.0)
                self.assertEqual(v["protection"], "blocked")


if __name__ == "__main__":
    unittest.main()

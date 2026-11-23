"""Metadata audit counterexamples and kernel timestamp ABI validation."""

import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest
from unittest import mock

import wf_capture as capture
import wf_observer
import wf_pcap


def frame(dst="192.0.2.1", port=443, fragment=0, payload=b"PRIVATE-PAYLOAD"):
    """A synthetic IPv4/UDP frame with recognizable bytes that must not enter reports."""
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28 + len(payload),
        1,
        fragment,
        64,
        17,
        0,
        socket.inet_aton("192.0.2.2"),
        socket.inet_aton(dst),
    )
    return bytes(12) + b"\x08\x00" + header + struct.pack("!HHHH", 1234, port, 8 + len(payload), 0) + payload


class PacketMetadata(unittest.TestCase):
    def test_header_only_snapshots_preserve_original_wire_length(self):
        raw = frame(payload=b"x" * 1400)
        meta = capture.network_metadata(raw[:96], len(raw))
        self.assertEqual(meta["length"], len(raw) - 14)
        self.assertTrue(capture.permitted_outgoing(meta, "192.0.2.1", 443))
        self.assertEqual(capture.network_metadata(raw[:30], len(raw))["kind"], "other")

    def test_only_bounded_link_local_router_solicitations_are_permitted(self):
        def solicitation(dst="ff02::2", hop=255, code=0):
            ip = struct.pack(
                "!IHBB16s16s",
                6 << 28,
                8,
                58,
                hop,
                socket.inet_pton(socket.AF_INET6, "fe80::1234"),
                socket.inet_pton(socket.AF_INET6, dst),
            )
            return bytes(12) + b"\x86\xdd" + ip + bytes([133, code]) + bytes(6)

        good = capture.network_metadata(solicitation())
        self.assertTrue(capture.permitted_outgoing(good, "192.0.2.1", 51820))
        for raw in (solicitation(dst="2001:db8::1"), solicitation(hop=64), solicitation(code=1)):
            self.assertFalse(capture.permitted_outgoing(capture.network_metadata(raw), "192.0.2.1", 51820))

    def test_only_header_metadata_is_kept_and_wrong_destination_or_port_is_refused(self):
        good = capture.network_metadata(frame())
        self.assertTrue(capture.permitted_outgoing(good, "192.0.2.1", 443))
        self.assertNotIn("PRIVATE", json.dumps(good))
        for raw in [frame(dst="9.9.9.9"), frame(port=53), frame(fragment=0x2000)]:
            self.assertFalse(capture.permitted_outgoing(capture.network_metadata(raw), "192.0.2.1", 443))

    def test_truncated_headers_and_unknown_ether_types_are_not_allowed(self):
        for raw in [b"short", frame()[:35], bytes(14)]:
            meta = capture.network_metadata(raw)
            self.assertFalse(capture.permitted_outgoing(meta, "192.0.2.1", 443))
        arp = capture.network_metadata(bytes(12) + b"\x08\x06" + bytes(28))
        self.assertTrue(capture.permitted_outgoing(arp, "192.0.2.1", 443))

    def test_kernel_time64_is_required_and_invalid_nanoseconds_are_refused(self):
        self.assertEqual(wf_pcap.timestamp(1000, 250_000_000), 1000.25)
        for seconds, nanos in [(0, 0), (1000, -1), (1000, 1_000_000_000)]:
            with self.assertRaises(ValueError):
                wf_pcap.timestamp(seconds, nanos)


class ProtectionSamples(unittest.TestCase):
    def test_stale_or_reused_controller_identity_never_reports_protected(self):
        import cypherpunkctl

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = float(int(time.time()))
            status = dict(
                state="supervising",
                lifecycle="connected",
                protection="protected",
                kill_switch=True,
                children=dict(client=dict(alive=True, pid=2, identity="two")),
                evidence=dict(cloak_confirmed_at=now, carrier_handshake_at=now, path_probe_at=now),
            )
            (root / "status.json").write_text(json.dumps(status))
            (root / "controller.json").write_text(json.dumps(dict(pid=1, identity="one")))
            (root / "status.json").chmod(0o600)
            (root / "controller.json").chmod(0o600)
            for name in ("status.json", "controller.json"):
                os.utime(root / name, (now, now))
            with (
                mock.patch.object(
                    cypherpunkctl, "read_json_private", side_effect=lambda path: json.loads(path.read_text())
                ),
                mock.patch.object(cypherpunkctl, "identity_of", side_effect=lambda pid: {1: "one", 2: "two"}[pid]),
            ):
                self.assertEqual(wf_observer.snapshot(root, now)["protection"], "protected")
                self.assertEqual(wf_observer.snapshot(root, now + 20)["protection"], "unknown")
                with mock.patch.object(cypherpunkctl, "identity_of", return_value="reused"):
                    self.assertEqual(wf_observer.snapshot(root, now)["protection"], "unknown")
                os.utime(root / "status.json", (now + 1, now + 1))
                self.assertEqual(wf_observer.snapshot(root, now)["protection"], "unknown")

    def test_observer_has_samples_before_and_after_the_observed_interval(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "samples.jsonl"
            with wf_observer.Observer(path, interval=0.01):
                time.sleep(0.03)
                end = time.time()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertGreaterEqual(len(rows), 2)
            self.assertGreaterEqual(rows[-1]["time"], end)
            self.assertTrue(all(r["protection"] == "control" for r in rows))

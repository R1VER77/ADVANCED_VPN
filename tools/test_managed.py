"""Enrollment, chains, validation, root file hand-off, hardening and the privacy budget."""

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from managed_profile import create, enroll, runtime, refresh_leaves, canonical
from avpnctl import Allowance
from keyguard import memory_fd


def _requests(root, roles=("client", "relay", "exit"), prefix="dev"):
    from managed_profile import request

    for role in roles:
        request(role, root / prefix / role, "none")
    return {r: (root / prefix / r / "request.json").read_bytes() for r in roles}


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        from managed_profile import SoftwareOperator

        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ops = self.root / "operator"
        (self.root / "dev").mkdir()
        self.signer = SoftwareOperator(self.root / "opkeys")
        create(self.ops, _requests(self.root), "192.0.2.1:41194", "198.51.100.2:4444", self.signer)

    def tearDown(self):
        self.tmp.cleanup()

    def dev(self, role):
        return self.root / "dev" / role

    def test_role_separation_and_relocation(self):
        p = enroll(self.ops / "relay.avpn", self.ops / "operator.pub", self.dev("relay"))
        self.assertIsNone(p["core"]["inner"])
        self.assertIsNone(p["dns"])
        self.assertFalse(any("inner" in f.name for f in self.dev("relay").iterdir()))
        c = runtime(p, self.dev("relay"))
        self.assertTrue(Path(c["core"]["outer"]["key"]).is_absolute())

    def test_bundles_contain_no_private_keys_and_psk_is_device_bound(self):
        from keyguard import kem_open

        for role in ["client", "relay", "exit"]:
            names = zipfile.ZipFile(self.ops / (role + ".avpn")).namelist()
            self.assertFalse([n for n in names if n.endswith(("-key.der", "-key.bin", ".key"))], names)
        relay_kem = (self.dev("relay") / "kem-key.bin").read_bytes()
        client_psk = json.loads(zipfile.ZipFile(self.ops / "client.avpn").read("psk.kem.json"))
        with self.assertRaises(Exception):
            kem_open(relay_kem, client_psk, b"advanced-vpn/wireguard-psk/client")

    def test_bundle_for_another_device_is_rejected(self):
        from managed_profile import request

        request("client", self.root / "other-client", "none")
        with self.assertRaises(ValueError):
            enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.root / "other-client")
        self.assertFalse((self.root / "other-client" / "profile.json").exists())
        # The exit has no WireGuard key: its certificate binding is the only guard.
        request("exit", self.root / "other-exit", "none")
        with self.assertRaises(ValueError):
            enroll(self.ops / "exit.avpn", self.ops / "operator.pub", self.root / "other-exit")
        self.assertFalse((self.root / "other-exit" / "profile.json").exists())

    def test_enrollment_derives_wireguard_key_and_keeps_kem_protected(self):
        enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.dev("client"))
        enroll(self.ops / "relay.avpn", self.ops / "operator.pub", self.dev("relay"))
        c = (self.dev("client") / "wireguard-key.bin").read_bytes()
        r = (self.dev("relay") / "wireguard-key.bin").read_bytes()
        self.assertEqual(len(c), 64)
        self.assertEqual(c[32:], r[32:])
        self.assertNotEqual(c[:32], r[:32])  # shared PSK, own keys
        # The KEM key stays (protected like every other key) so a later chain can deliver a new PSK.
        self.assertTrue((self.dev("client") / "kem-key.bin").exists())
        with self.assertRaises(ValueError):
            enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.dev("client"))  # no silent re-enroll

    def test_constant_cell_padding_is_always_on_and_required(self):
        from managed_profile import PADDING_REQUIRED, profile_validate, require_padding

        reqs = {r: (self.dev(r) / "request.json").read_bytes() for r in ["client", "relay", "exit"]}
        out = self.root / "cells"
        create(out, reqs, "192.0.2.1:41194", "198.51.100.2:4444", self.signer)
        profiles = {r: json.loads(zipfile.ZipFile(out / (r + ".avpn")).read("profile.json")) for r in reqs}
        # Every hop pads; there is no option that produces an unpadded chain.
        self.assertEqual({pr["core"]["cells"] for pr in profiles.values()}, {True})
        for pr in profiles.values():
            require_padding(profile_validate(pr))
        # A malformed flag is refused outright.
        for value in (False, "yes", None):
            bad = json.loads(json.dumps(profiles["client"]))
            bad["core"]["cells"] = value
            with self.assertRaisesRegex(ValueError, "malformed padding flag"):
                profile_validate(bad)
        # A chain signed before padding existed is well-formed (so reset and the kill
        # switch still work on it) but can never be connected or enrolled.
        old = json.loads(json.dumps(profiles["client"]))
        del old["core"]["cells"]
        profile_validate(old)
        with self.assertRaises(ValueError) as e:
            require_padding(old)
        self.assertEqual(str(e.exception), PADDING_REQUIRED)
        import inspect

        self.assertNotIn("cells", inspect.signature(create).parameters, "padding must not be optional")

    def test_http3_cloak_is_always_on_and_strictly_bound(self):
        from managed_profile import CLOAK_REQUIRED, cloak_certificate, profile_validate, require_current, spki_sha256

        reqs = {r: (self.dev(r) / "request.json").read_bytes() for r in ["client", "relay", "exit"]}
        out = self.root / "cloak"
        create(out, reqs, "192.0.2.1:443", "198.51.100.2:4444", self.signer, cover_name="ec2-192-0-2-1.example.com")
        profiles = {r: json.loads(zipfile.ZipFile(out / (r + ".avpn")).read("profile.json")) for r in reqs}
        for pr in profiles.values():
            require_current(profile_validate(pr))
        client, relay = profiles["client"], profiles["relay"]
        self.assertEqual(
            (client["cloak"]["cover_name"], relay["cloak"]["cover_name"]), ("ec2-192-0-2-1.example.com",) * 2
        )
        self.assertIsNone(profiles["exit"]["cloak"])
        # Tampering with anything that reaches the cloak's sockets or trust is refused.
        for section, field, value in [
            ("cloak", "remote", "203.0.113.9:443"),
            ("cloak", "listen", "0.0.0.0:41196"),
            ("cloak", "wireguard", "127.0.0.1:41194"),
            ("cloak", "server_spki_sha256", "00"),
            ("cloak", "cover_name", "other.example"),
            ("cloak", "cert", "cloak-cert.der"),
            ("cloak", "extra", 1),
            ("carrier", "endpoint", "192.0.2.1:443"),
            ("carrier", "schema", 1),
        ]:
            bad = json.loads(json.dumps(client))
            bad[section][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                profile_validate(bad)
        bad = json.loads(json.dumps(relay))
        bad["cloak"]["listen"] = "0.0.0.0:443"
        with self.assertRaises(ValueError):
            profile_validate(bad)
        # A profile without the cloak is well-formed, but never connects or enrolls.
        old = json.loads(json.dumps(client))
        del old["cloak"], old["network"]["cover_name"]
        old["carrier"].update(schema=1, endpoint="192.0.2.1:443")
        profile_validate(old)
        with self.assertRaises(ValueError) as e:
            require_current(old)
        self.assertEqual(str(e.exception), CLOAK_REQUIRED)
        # The certificate made at each start carries exactly the key the client pins.
        from managed_profile import load_keys

        key = load_keys(self.dev("relay"), ["cloak"])["cloak"]
        cert = cloak_certificate(key, "ec2-192-0-2-1.example.com")
        self.assertEqual(spki_sha256(cert), client["cloak"]["server_spki_sha256"])
        import inspect

        self.assertNotIn("cloak", inspect.signature(create).parameters, "the cloak must not be optional")

    def test_cloak_proof_key_comes_from_the_psk_only(self):
        import avpnctl

        a = avpnctl.cloak_token(b"\x01" * 32 + b"\x02" * 32)
        self.assertEqual(len(a), 32)
        self.assertEqual(a, avpnctl.cloak_token(b"\x09" * 32 + b"\x02" * 32))  # the private half plays no part
        self.assertNotEqual(a, avpnctl.cloak_token(b"\x01" * 32 + b"\x03" * 32))
        with self.assertRaises(ValueError):
            avpnctl.cloak_token(b"\x01" * 32)

    def test_a_carrier_that_receives_nothing_is_restarted(self):
        import avpnctl

        w = avpnctl.CarrierWatch(limit=20)
        self.assertFalse(w.stalled(10, 500, 0))
        self.assertFalse(w.stalled(10, 500, 19.9))
        self.assertTrue(w.stalled(10, 500, 20))
        # Any received byte, or a new carrier process, starts the clock again.
        self.assertFalse(w.stalled(10, 501, 25))
        self.assertFalse(w.stalled(10, 501, 44))
        self.assertFalse(w.stalled(11, 501, 46))
        self.assertTrue(w.stalled(11, 501, 66))
        # Received decoys are not data: a carrier receiving only decoys is stuck.
        with tempfile.TemporaryDirectory() as d, mock.patch.object(avpnctl, "runtime_dir", lambda state: Path(d)):
            (Path(d) / "carrier-status.json").write_text(json.dumps(dict(rx_bytes=5000, rx_decoy_bytes=4000)))
            self.assertEqual(avpnctl.carrier_rx(Path(d)), 1000)
            (Path(d) / "carrier-status.json").write_text("{")
            self.assertIsNone(avpnctl.carrier_rx(Path(d)))
        # An unreadable status is never a reason to restart.
        self.assertFalse(w.stalled(11, None, 100))
        self.assertFalse(w.stalled(11, None, 200))

    def test_underlay_mtu_floor_matches_the_cloak_packet_size(self):
        import re

        import avpnctl

        # A full WireGuard datagram becomes a cloak::OUTER_MTU-byte QUIC UDP payload, so the
        # underlay link must carry OUTER_MTU + 8 (UDP) + 20 (IPv4) bytes. Keep the Python floor
        # in step with the Rust constant so a too-small path is refused, not silently black-holed.
        outer = int(
            re.search(
                r"pub const OUTER_MTU: u16 = (\d+);",
                (Path(avpnctl.__file__).resolve().parents[1] / "src/cloak.rs").read_text(),
            ).group(1)
        )
        self.assertEqual(avpnctl.UNDERLAY_MIN_MTU, outer + 28)

    def test_first_hop_firewall_keeps_wireguard_on_loopback(self):
        import avpnctl

        text = avpnctl.first_hop_rules({"network": {"relay_endpoint": "192.0.2.1:443"}})
        self.assertIn('udp dport 41194 iifname != "lo" drop', text)
        self.assertIn("fib daddr type local udp dport 443 redirect to :8443", text)
        self.assertIn("fib daddr type local tcp dport 443 redirect to :8443", text)
        self.assertIn('udp dport 4433 iifname != "avwg0" drop', text)

    def test_profiles_for_one_two_and_three_hops(self):
        from managed_profile import request

        for name in ["middle"]:
            request(name, self.dev(name), "none")
        reqs = {r: (self.dev(r) / "request.json").read_bytes() for r in ["client", "relay", "middle", "exit"]}
        cases = {
            1: (None, None, ["inner"], 1100),
            2: ("192.0.2.1:41194", None, ["outer", "inner"], 1100),
            3: ("192.0.2.1:41194", "198.18.0.2:4445", ["outer", "middle", "inner"], 1100),
        }
        for hops, (relay, middle, lanes, mtu) in cases.items():
            roles = ["client"] + {1: ["exit"], 2: ["relay", "exit"], 3: ["relay", "middle", "exit"]}[hops]
            out = self.root / ("chain%d" % hops)
            create(out, {r: reqs[r] for r in roles}, relay, "198.51.100.2:4444", self.signer, hops=hops, middle=middle)
            profiles = {r: json.loads(zipfile.ZipFile(out / (r + ".avpn")).read("profile.json")) for r in roles}
            client = profiles["client"]["core"]
            with self.subTest(hops=hops):
                self.assertEqual([l for l in ["outer", "middle", "inner"] if client.get(l)], lanes)
                self.assertEqual(client["mtu"], mtu)
                self.assertEqual({pr["core"]["layers"] for pr in profiles.values()}, {hops})
                first = roles[1]
                self.assertEqual({r for r, pr in profiles.items() if pr["carrier"]}, {"client", first})
                # WireGuard goes only to the local cloak; the cloak reaches the first hop.
                self.assertEqual(profiles["client"]["carrier"]["endpoint"], "127.0.0.1:41196")
                self.assertEqual(profiles["client"]["cloak"]["remote"], relay or "198.51.100.2:4444")
                self.assertEqual(profiles[first]["carrier"]["listen_port"], 41194)
                self.assertEqual(
                    (profiles[first]["cloak"]["role"], profiles[first]["cloak"]["listen"]), ("server", "0.0.0.0:8443")
                )
                self.assertEqual(
                    profiles["client"]["cloak"]["server_spki_sha256"],
                    json.loads(reqs[first])["cloak_spki_sha256"],
                )
                self.assertEqual({r for r, pr in profiles.items() if pr["cloak"]}, {"client", first})
                if hops == 3:
                    m = profiles["middle"]["core"]
                    self.assertEqual(
                        (m["role"], m["tun"], m["listen"], m["exit"]),
                        ("relay", None, "0.0.0.0:4445", "198.51.100.2:4444"),
                    )
                    self.assertEqual(profiles["relay"]["core"]["exit"], "198.18.0.2:4445")
                if hops == 1:
                    self.assertEqual(profiles["exit"]["core"]["listen"], "10.78.0.1:4433")
                else:
                    self.assertEqual(profiles["exit"]["core"]["listen"], "0.0.0.0:4444")  # binds behind cloud NAT
        with self.assertRaises(ValueError):
            create(
                self.root / "bad",
                {r: reqs[r] for r in ["client", "exit"]},
                "192.0.2.1:41194",
                "198.51.100.2:4444",
                self.signer,
                hops=1,
            )

    def test_replace_switches_chain_and_keeps_device_keys(self):
        enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.dev("client"))
        before = (self.dev("client") / "wireguard-key.bin").read_bytes()
        single = self.root / "single"
        create(
            single,
            {r: (self.dev(r) / "request.json").read_bytes() for r in ["client", "exit"]},
            None,
            "198.51.100.2:51820",
            self.signer,
            hops=1,
        )
        p = enroll(single / "client.avpn", single / "operator.pub", self.dev("client"), replace=True)
        after = (self.dev("client") / "wireguard-key.bin").read_bytes()
        self.assertEqual(p["hops"], 1)
        self.assertEqual(after[:32], before[:32])
        self.assertNotEqual(after[32:], before[32:])
        self.assertFalse((self.dev("client") / "outer-ca.der").exists())  # previous chain's peers removed

    def _rewritten(self, name, replace=None, drop=None, add=None):
        bad = self.root / name
        with zipfile.ZipFile(self.ops / "client.avpn") as src, zipfile.ZipFile(bad, "x") as out:
            for member in src.namelist():
                if member == drop:
                    continue
                out.writestr(member, replace(member, src.read(member)) if replace else src.read(member))
            if add:
                out.writestr(*add)
        return bad

    def test_bundle_tampering_is_rejected(self):
        bad = self._rewritten("t.avpn", lambda m, b: b + b"x" if m == "profile.json" else b)
        with self.assertRaises(ValueError):
            enroll(bad, self.ops / "operator.pub", self.dev("client"))

    def test_mesh_bundles_and_dns_blocklist_enroll(self):
        from managed_profile import (
            mesh_add_hop,
            mesh_admit,
            mesh_bundles,
            mesh_state_new,
            mesh_verify_directory,
            request,
        )

        request("client", self.dev("alice"), "none")
        request("client", self.dev("bob"), "none")
        mesh = mesh_state_new()
        mesh_add_hop(mesh, "r1", "relay", "192.0.2.1:443", (self.dev("relay") / "request.json").read_bytes())
        mesh_add_hop(mesh, "e1", "exit", "198.51.100.2:4444", (self.dev("exit") / "request.json").read_bytes())
        mesh_admit(mesh, "alice", (self.dev("alice") / "request.json").read_bytes(), ["r1", "e1"])
        mesh_admit(mesh, "bob", (self.dev("bob") / "request.json").read_bytes(), ["r1", "e1"])
        out = self.root / "mesh-ops"
        mesh_bundles(
            out,
            mesh,
            self.signer,
            dns=dict(upstream="9.9.9.9:853", server_name="dns.quad9.net", blocklist=b"ads.example.com\n"),
        )
        directory = mesh_verify_directory(out / "directory.avpnd", out / "operator.pub")
        self.assertEqual(directory["hops_len"], 2)
        p_relay = enroll(out / "r1.avpn", out / "operator.pub", self.dev("relay"))
        self.assertEqual(len(p_relay["carrier"]["members"]), 2)
        self.assertEqual(len((self.dev("relay") / "wireguard-key.bin").read_bytes()), 32 + 32 * 2)
        p_exit = enroll(out / "e1.avpn", out / "operator.pub", self.dev("exit"))
        self.assertEqual(p_exit["dns"]["blocklist"], "dns-blocklist.txt")
        self.assertEqual((self.dev("exit") / "dns-blocklist.txt").read_bytes(), b"ads.example.com\n")
        p_alice = enroll(out / "alice.avpn", out / "operator.pub", self.dev("alice"))
        self.assertEqual(p_alice["core"]["local_ip"], "10.77.0.2")
        p_bob = enroll(out / "bob.avpn", out / "operator.pub", self.dev("bob"))
        self.assertEqual(p_bob["core"]["local_ip"], "10.77.0.3")

    def test_zip_traversal_and_unsigned_extras_rejected(self):
        bad = self._rewritten("z.avpn", add=("../escape", b"bad"))
        with self.assertRaises(ValueError):
            enroll(bad, self.ops / "operator.pub", self.dev("client"))

    def test_wrong_operator_cannot_enroll(self):
        from managed_profile import SoftwareOperator

        other = self.root / "other.pub"
        other.write_bytes(canonical(SoftwareOperator(self.root / "other-op").public()))
        other.chmod(0o600)
        with self.assertRaises(Exception):
            enroll(self.ops / "client.avpn", other, self.dev("client"))
        self.assertFalse((self.dev("client") / "profile.json").exists())

    def test_hybrid_signature_requires_both_halves(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

        with zipfile.ZipFile(self.ops / "client.avpn") as z:
            raw = z.read("set.json")
        forged_pq = lambda m, b: mldsa.MLDSA65PrivateKey.generate().sign(raw) if m == "set.mldsa65.sig" else b
        forged_classical = lambda m, b: (
            canonical(
                dict(
                    kind="ed25519", signature=base64.b64encode(ed25519.Ed25519PrivateKey.generate().sign(raw)).decode()
                )
            )
            if m == "set.classical.json"
            else b
        )
        for case, bundle in [
            ("pq-forged", self._rewritten("a.avpn", forged_pq)),
            ("classical-forged", self._rewritten("b.avpn", forged_classical)),
            ("pq-missing", self._rewritten("c.avpn", drop="set.mldsa65.sig")),
        ]:
            with self.subTest(case), self.assertRaises(Exception):
                enroll(bundle, self.ops / "operator.pub", self.dev("client"))
            self.assertFalse((self.dev("client") / "profile.json").exists())

    def test_profile_values_that_reach_firewall_text_are_strictly_validated(self):
        """nftables rules are built as text from profile values; hostile values must
        be rejected by validation before any rule is generated (injection)."""
        from managed_profile import profile_validate

        base = json.loads(zipfile.ZipFile(self.ops / "client.avpn").read("profile.json"))
        hostile = {
            ("network", "relay_endpoint"): [
                "1.1.1.1 } ; flush ruleset ; table x {:41194",
                "evil.example:41194",
                "1.1.1.1:0",
                "1.1.1.1:99999",
                "224.0.0.1:41194",
                "0.0.0.0:41194",
            ],
            ("network", "exit_endpoint"): ["198.51.100.2:4444\nflush ruleset"],
            ("network", "dns_ip"): ["10.77.0.1; flush ruleset"],
            ("carrier", "listen_port"): ["41195; flush ruleset", 80, "41195"],
            ("carrier", "peer_public_hex"): ["zz" * 32, "00" * 31],
        }
        for (section, key), values in hostile.items():
            for value in values:
                p = json.loads(json.dumps(base))
                p[section][key] = value
                with (
                    self.subTest(field=section + "." + key, value=value),
                    self.assertRaises((ValueError, TypeError, KeyError)),
                ):
                    profile_validate(p)
        profile_validate(json.loads(json.dumps(base)))  # the untouched profile still validates

    def test_device_identities_are_ml_dsa_65(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa

        p = enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.dev("client"))
        c = runtime(p, self.dev("client"))["core"]
        for lane in ["outer", "inner"]:
            cert = x509.load_der_x509_certificate(Path(c[lane]["cert"]).read_bytes())
            self.assertIsInstance(cert.public_key(), mldsa.MLDSA65PublicKey)
            self.assertEqual(cert.signature_algorithm_oid.dotted_string, "2.16.840.1.101.3.4.3.18")
        refresh_leaves(c, self.dev("client"))
        fresh = x509.load_der_x509_certificate(Path(c["inner"]["cert"]).read_bytes())
        self.assertEqual(fresh.signature_algorithm_oid.dotted_string, "2.16.840.1.101.3.4.3.18")

    def test_rotated_certificate_keeps_identity_without_authority_key(self):
        p = enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.dev("client"))
        c = runtime(p, self.dev("client"))["core"]
        old = x509.load_der_x509_certificate(Path(c["inner"]["cert"]).read_bytes())
        refresh_leaves(c, self.dev("client"))
        new = x509.load_der_x509_certificate(Path(c["inner"]["cert"]).read_bytes())
        self.assertNotEqual(old.serial_number, new.serial_number)
        self.assertEqual(
            old.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            new.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        )
        self.assertEqual(new.issuer, new.subject)
        self.assertLess(new.not_valid_after_utc - new.not_valid_before_utc, dt.timedelta(hours=13))

    def test_wireguard_psk_key_accepts_only_sealed_handoff_and_daita(self):
        p = enroll(self.ops / "client.avpn", self.ops / "operator.pub", self.dev("client"))
        w = runtime(p, self.dev("client"))["carrier"]
        path = Path(w["identity"]["key"])
        fd = memory_fd(path.read_bytes())
        path.unlink()
        cfg = self.root / "carrier.json"
        cfg.write_text(json.dumps(w))
        cfg.chmod(0o600)
        binary = Path(__file__).resolve().parents[1] / "target/release/advanced-vpn-wireguard"
        try:
            args = [binary, "--config", cfg, "--check", "--key-fd", "wireguard=" + str(fd)]
            # The default chain (what `avpn init` signs) is what the carrier accepts.
            self.assertEqual((w["defense"], w["rate"]), ("strong", "metered"))
            r = subprocess.run(args, pass_fds=[fd], capture_output=True, timeout=5)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["rate"], "metered")
            # Every signed class runs; a bundle signed before rate classes runs metered.
            from managed_profile import RATE_CLASSES

            for rate in [*RATE_CLASSES, None]:
                v = dict(w, rate=rate) if rate else {k: x for k, x in w.items() if k != "rate"}
                cfg.write_text(json.dumps(v))
                r = subprocess.run(args, pass_fds=[fd], capture_output=True, timeout=5)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(json.loads(r.stdout)["rate"], rate or "metered")
            for field, value in [("defense", "off"), ("defense", "balanced"), ("rate", "turbo"), ("rate", "")]:
                cfg.write_text(json.dumps(dict(w, **{field: value})))
                r = subprocess.run(args, pass_fds=[fd], capture_output=True, timeout=5)
                self.assertNotEqual(r.returncode, 0, (field, value))
        finally:
            os.close(fd)


class PerHopShapingTests(unittest.TestCase):
    def test_every_server_link_is_keyed_paced_and_accepted_by_the_core(self):
        from managed_profile import (
            LINKS_REQUIRED,
            SoftwareOperator,
            load_keys,
            profile_validate,
            request,
            require_current,
        )

        binary = Path(__file__).resolve().parents[1] / "target/release/advanced-vpn"
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            roles = ["client", "relay", "middle", "exit"]
            (root / "dev").mkdir()
            for r in roles:
                request(r, root / "dev" / r, "none")
            reqs = {r: (root / "dev" / r / "request.json").read_bytes() for r in roles}
            out = root / "ops"
            create(
                out,
                reqs,
                "192.0.2.1:41194",
                "198.51.100.2:4444",
                SoftwareOperator(root / "opkeys"),
                hops=3,
                middle="198.18.0.2:4445",
                rate="fast",
            )
            expected = {"relay": (1, 0), "middle": (1, 1), "exit": (0, 1)}
            seen = {}
            for role in roles:
                p = enroll(out / (role + ".avpn"), out / "operator.pub", root / "dev" / role)
                core = p["core"]
                if role == "client":
                    self.assertNotIn("link_rate", core)
                    continue
                self.assertEqual(core["link_rate"], "fast")
                self.assertEqual((len(core["link_out"]), core["link_in"]), expected[role])
                lane = {"relay": "outer", "middle": "middle", "exit": "inner"}[role]
                keys = load_keys(root / "dev" / role, [lane, "link"])
                self.assertEqual(len(keys["link"]), 32 * sum(expected[role]))
                seen[role] = keys["link"]
                cfg = root / (role + "-core.json")
                cfg.write_text(json.dumps(runtime(p, root / "dev" / role)["core"]))
                cfg.chmod(0o600)
                fds = {n: memory_fd(v) for n, v in keys.items()}
                try:
                    args = [binary, "--config", cfg, "--check"]
                    for n, f in fds.items():
                        args += ["--key-fd", "%s=%d" % (n, f)]
                    r = subprocess.run(args, pass_fds=list(fds.values()), capture_output=True, timeout=10)
                    self.assertEqual(r.returncode, 0, (role, r.stderr))
                    got = json.loads(r.stdout)
                    self.assertEqual((got["paced_links_out"], got["paced_links_in"]), expected[role])
                    # Without its link keys, a server refuses to start.
                    lane_only = [binary, "--config", cfg, "--check", "--key-fd", "%s=%d" % (lane, fds[lane])]
                    r = subprocess.run(lane_only, pass_fds=[fds[lane]], capture_output=True, timeout=10)
                    self.assertNotEqual(r.returncode, 0, role)
                finally:
                    for f in fds.values():
                        os.close(f)
            # Each link's two ends hold the same key; different links hold different keys.
            self.assertEqual(seen["relay"][:32], seen["middle"][32:])
            self.assertEqual(seen["middle"][:32], seen["exit"])
            self.assertNotEqual(seen["relay"][:32], seen["exit"])
            # A multi-hop server profile signed before per-hop shaping is refused.
            old = json.loads(zipfile.ZipFile(out / "exit.avpn").read("profile.json"))
            for k in ["link_rate", "link_out", "link_in"]:
                old["core"].pop(k)
            profile_validate(old)
            with self.assertRaises(ValueError) as e:
                require_current(old)
            self.assertEqual(str(e.exception), LINKS_REQUIRED)


class RateClassTests(unittest.TestCase):
    def test_classes_mirror_the_carrier(self):
        from managed_profile import RATE_CLASSES

        src = (Path(__file__).resolve().parents[1] / "src/daita.rs").read_text()
        for name in RATE_CLASSES:
            self.assertIn('RateClass::%s => "%s"' % (name.capitalize(), name), src)
        # packets/s = slots per tick / tick; the Rust table is the source of truth.
        self.assertEqual(RATE_CLASSES, {"metered": 50, "standard": 500, "fast": 4000, "line": 16000})

    def test_auto_picks_the_fastest_class_the_allowance_fits(self):
        from managed_profile import choose_rate

        self.assertEqual(choose_rate("auto", 100, 8)[0], "metered")  # an AWS free-plan hop
        self.assertEqual(choose_rate("auto", 10240, 8)[0], "fast")  # OCI Always Free only
        self.assertEqual(choose_rate("auto", 10240, 1)[0], "line")
        self.assertEqual(choose_rate("auto", None, 8)[0], "metered")  # nothing known: slowest

    def test_a_class_over_the_allowance_needs_explicit_acceptance(self):
        from managed_profile import choose_rate

        with self.assertRaises(ValueError):
            choose_rate("fast", 100, 8)
        with self.assertRaises(ValueError):
            choose_rate("auto", 100, 24)  # even metered is over
        self.assertEqual(choose_rate("fast", 100, 8, accept_cost=True)[0], "fast")
        self.assertEqual(choose_rate("auto", 100, 24, accept_cost=True)[0], "metered")
        for bad in [("turbo", None, 8), ("auto", 0, 8), ("auto", 100, 0), ("auto", 100, 25)]:
            with self.assertRaises(ValueError):
                choose_rate(*bad)

    def test_only_the_stream_is_signed_and_old_balanced_chains_are_refused(self):
        from managed_profile import BALANCED_REMOVED, SoftwareOperator, profile_validate, require_current

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "dev").mkdir()
            reqs = _requests(root)
            signer = SoftwareOperator(root / "opkeys")
            with self.assertRaises(ValueError):
                create(root / "a", reqs, "192.0.2.1:41194", "198.51.100.2:4444", signer, defense="balanced")
            with self.assertRaises(ValueError):
                create(root / "b", reqs, "192.0.2.1:41194", "198.51.100.2:4444", signer, rate="turbo")
            create(root / "c", reqs, "192.0.2.1:41194", "198.51.100.2:4444", signer, rate="fast")
            client = json.loads(zipfile.ZipFile(root / "c" / "client.avpn").read("profile.json"))
            self.assertEqual(client["carrier"]["rate"], "fast")
            require_current(profile_validate(client))
            # A profile signed by an older release with balanced still loads (reset,
            # guard and info work) but connect and enroll refuse it with the fix.
            client["carrier"]["defense"] = "balanced"
            profile_validate(client)
            with self.assertRaises(ValueError) as e:
                require_current(client)
            self.assertEqual(str(e.exception), BALANCED_REMOVED)


class HardwareVerificationTests(unittest.TestCase):
    """The FIDO2 operator half, verified offline. A synthetic authenticator stands in
    for the Nitrokey so every rejection path is exercised without a device."""

    def assertion(
        self, message, flags=0x05, rp="advanced-vpn.local", origin="https://advanced-vpn.local", sign_with=None
    ):
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from fido2.cose import EdDSA
        from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData, Aaguid

        key = ed25519.Ed25519PrivateKey.generate()
        cred = AttestedCredentialData.create(
            Aaguid(bytes(16)), os.urandom(16), EdDSA.from_cryptography_key(key.public_key())
        )
        auth = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(), flags, 7)
        cd = CollectedClientData.create(type="webauthn.get", challenge=hashlib.sha256(message).digest(), origin=origin)
        sig = (sign_with or key).sign(bytes(auth) + cd.hash)
        b = lambda v: base64.b64encode(bytes(v)).decode()
        return b(cred), dict(authenticator_data=b(auth), client_data=b(cd), signature=b(sig))

    def test_valid_assertion_and_every_rejection(self):
        from keyguard import verify_assertion
        from cryptography.hazmat.primitives.asymmetric import ed25519

        m = b"enrollment-set"
        cred, a = self.assertion(m)
        verify_assertion(cred, m, a)
        cases = {
            "no PIN (UV)": self.assertion(m, flags=0x01),
            "no touch (UP)": self.assertion(m, flags=0x04),
            "wrong RP": self.assertion(m, rp="evil.example"),
            "wrong origin": self.assertion(m, origin="https://evil.example"),
            "other key": self.assertion(m, sign_with=ed25519.Ed25519PrivateKey.generate()),
        }
        for label, (cred, a) in cases.items():
            with self.subTest(label), self.assertRaises(Exception):
                verify_assertion(cred, m, a)
        cred, a = self.assertion(m)
        with self.assertRaises(ValueError):
            verify_assertion(cred, b"another-set", a)

    def test_hybrid_kem_roundtrip_and_context_binding(self):
        from keyguard import kem_keypair, kem_seal, kem_open

        priv, pub = kem_keypair()
        box = kem_seal(pub, b"p" * 32, b"ctx-a")
        self.assertEqual(kem_open(priv, box, b"ctx-a"), b"p" * 32)
        with self.assertRaises(Exception):
            kem_open(priv, box, b"ctx-b")
        other, _ = kem_keypair()
        with self.assertRaises(Exception):
            kem_open(other, box, b"ctx-a")


class RootFileHandoffTests(unittest.TestCase):
    """Root publishes runtime files into a directory the service UID can write.
    A compromised data-plane process must not be able to redirect root's
    chmod/chown through a symlink planted after the rename (privilege escalation)."""

    def test_symlink_swap_after_rename_cannot_redirect_mode_or_owner(self):
        from unittest import mock
        import avpnctl

        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            victim = d / "victim"
            victim.write_bytes(b"root-owned secret")
            victim.chmod(0o644)
            target = d / "service-dir" / "outer-cert.der"
            target.parent.mkdir()
            real_replace = os.replace

            def racing_replace(src, dst):
                real_replace(src, dst)
                if Path(dst) == target:  # attacker wins the race right after the rename
                    target.unlink()
                    target.symlink_to(victim)

            with mock.patch.object(avpnctl.os, "replace", racing_replace):
                try:
                    avpnctl.owned_public(target, b"public data", os.getuid(), os.getgid())
                except OSError:
                    pass
            self.assertEqual(victim.stat().st_mode & 0o777, 0o644, "root chmod followed an attacker symlink")
            self.assertEqual(victim.read_bytes(), b"root-owned secret")


class HardeningTests(unittest.TestCase):
    def test_controller_hardening_makes_process_non_dumpable(self):
        code = (
            "import ctypes,resource,sys;sys.path.insert(0,sys.argv[1]);import avpnctl;avpnctl.harden_process();"
            "print(ctypes.CDLL(None).prctl(3,0,0,0,0),resource.getrlimit(resource.RLIMIT_CORE)[0])"
        )
        r = subprocess.run(
            [sys.executable, "-c", code, str(Path(__file__).parent)], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(r.stdout.split(), ["0", "0"], r.stderr)  # PR_GET_DUMPABLE == 0, no core files

    def test_main_applies_hardening_first(self):
        import ast

        tree = ast.parse((Path(__file__).parent / "avpnctl.py").read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        body = main.body[1:] if ast.get_docstring(main) else main.body
        first = body[0]
        self.assertTrue(isinstance(first, ast.Expr) and getattr(first.value.func, "id", None) == "harden_process")


class BudgetTests(unittest.TestCase):
    def test_restart_and_clock_rollback_do_not_reset_budget(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "budget.json"
            Allowance(path, 100).reserve(60, "2026-11-07")
            with self.assertRaises(RuntimeError):
                Allowance(path, 100).reserve(60, "2026-11-07")
            with self.assertRaises(RuntimeError):
                Allowance(path, 100).reserve(1, "2026-11-06")
            self.assertEqual(Allowance(path, 100).reserve(60, "2026-11-08")["reserved"], 60)

    def test_grant_release_refunds_unused_bytes_same_day_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "budget.json"
            a = Allowance(path, 1 << 20)
            amount, day = a.grant(1 << 19, "2026-11-07")
            self.assertEqual(amount, 1 << 19)
            a.release(amount - 1000, day)
            self.assertEqual(json.loads(path.read_text())["reserved"], 1000)
            # A smaller remainder is granted partially; below the carrier minimum it is exhausted.
            amount, _ = a.grant(1 << 20, "2026-11-07")
            self.assertEqual(amount, (1 << 20) - 1000)
            with self.assertRaises(RuntimeError):
                a.grant(1 << 20, "2026-11-07")
            # Releasing an old day's grant never credits a new day.
            a.grant(1 << 16, "2026-11-08")
            a.release(1 << 19, "2026-11-07")
            self.assertEqual(json.loads(path.read_text()), dict(day="2026-11-08", reserved=1 << 16))

    def test_cap_is_opt_in(self):
        from avpnctl import daily_limit

        self.assertIsNone(daily_limit({}, dict(daily_budget_bytes=None)))
        self.assertEqual(daily_limit({"daily_limit_mib": 2}, dict(daily_budget_bytes=None)), 2 << 20)
        self.assertIsNone(daily_limit({"daily_limit_mib": None}, dict(daily_budget_bytes=1 << 20)))
        self.assertEqual(daily_limit({}, dict(daily_budget_bytes=1 << 20)), 1 << 20)
        with tempfile.TemporaryDirectory() as d:
            from managed_profile import lab_setup

            lab_setup(Path(d), "192.0.2.1:41194", "198.51.100.2:4444")
            self.assertIsNone(json.loads((Path(d) / "client" / "profile.json").read_text())["daily_budget_bytes"])


if __name__ == "__main__":
    unittest.main()

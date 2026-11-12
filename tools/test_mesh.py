#!/usr/bin/env python3
"""Tests for tools/mesh.py: identity, descriptor validation, chain selection, quota."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mesh

NOW = 1_800_000_000


def node(name, roles, provider, country, op, group="public"):
    key = f"key-{name}".encode()
    return {
        "schema": 1,
        "node_id": mesh.member_id(key),
        "node_public_key": "",
        "wg_public_key": "wg",
        "cloak_endpoint": "203.0.113.8:443",
        "roles": roles,
        "provider": provider,
        "country": country,
        "capacity": {"egress_gib_month": 10240, "cover_budget_mib_day": 2048},
        "health": {"uptime_30d": 0.99, "latency_ms_p50": 20},
        "group": group,
        "operator": mesh.member_id(op.encode()),
        "published": NOW - 100,
        "expires": NOW + 100,
        "signature": "",
    }


class TestIdentity(unittest.TestCase):
    def test_member_id_format_and_stability(self):
        mid = mesh.member_id(b"device-public-key")
        self.assertTrue(mid.startswith("!"))
        self.assertEqual(len(mid), 9)
        self.assertEqual(mid, mesh.member_id(b"device-public-key"))
        self.assertNotEqual(mid, mesh.member_id(b"other"))


class TestValidation(unittest.TestCase):
    def test_valid_descriptor(self):
        self.assertEqual(mesh.validate(node("a", ["relay"], "oci", "DE", "op"), NOW), [])

    def test_expired_refused(self):
        d = node("a", ["relay"], "oci", "DE", "op")
        self.assertTrue(mesh.validate(d, d["expires"] + 1))

    def test_ttl_cap(self):
        d = node("a", ["relay"], "oci", "DE", "op")
        d["expires"] = d["published"] + mesh.DESCRIPTOR_TTL_SECONDS + 1
        self.assertIn("descriptor lifetime above the TTL", mesh.validate(d, NOW))

    def test_country_shape(self):
        d = node("a", ["relay"], "oci", "de", "op")
        self.assertTrue(mesh.validate(d, NOW))


class TestChainSelection(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            node("e1", ["entry"], "oci", "DE", "alice"),
            node("e2", ["entry"], "oci", "DE", "alice"),
            node("r1", ["relay"], "aws", "SE", "bob"),
            node("x1", ["exit"], "host", "CH", "carol"),
        ]

    def test_three_hop_diversity(self):
        chain = mesh.select_chain(self.nodes, 3)
        self.assertEqual(len(chain), 3)
        self.assertEqual(len({d["operator"] for d in chain}), 3)
        self.assertEqual(len({d["provider"] for d in chain}), 3)
        self.assertEqual(len({d["country"] for d in chain}), 3)

    def test_operator_never_reused(self):
        nodes = [node("e1", ["entry"], "oci", "DE", "alice"), node("x1", ["exit"], "host", "CH", "alice")]
        with self.assertRaises(SystemExit):
            mesh.select_chain(nodes, 2)

    def test_exit_country_filter(self):
        with self.assertRaises(SystemExit):
            mesh.select_chain(self.nodes, 2, exit_country="IS")
        chain = mesh.select_chain(self.nodes, 2, exit_country="CH")
        self.assertEqual(chain[-1]["country"], "CH")

    def test_private_group_isolation(self):
        pub = mesh.select_chain(self.nodes, 2, group="public")
        self.assertTrue(pub)
        with self.assertRaises(SystemExit):
            mesh.select_chain(self.nodes, 2, group="private-nope")


class TestQuota(unittest.TestCase):
    def test_epoch_balance(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td) / "tokens.json"
            epoch = mesh.current_epoch(NOW)
            store.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "grants": [{"epoch": epoch}, {"epoch": epoch}, {"epoch": epoch - 1}],
                        "spent": [{"epoch": epoch}],
                    }
                )
            )
            with mock.patch.object(mesh, "token_store_path", return_value=store):
                q = mesh.quota_view(NOW)
        self.assertEqual(q["earned_today"], 2)
        self.assertEqual(q["spent_today"], 1)
        self.assertEqual(q["balance"], 1)
        self.assertIn("closed", q["public_pool"])


class TestOffer(unittest.TestCase):
    def test_guided_catalog_ranks_oci_first(self):
        rows = mesh.cmd_offer(argparse_ns(guided=True, apply=False))["rows"]
        self.assertEqual(rows[0]["label"], "oci")
        self.assertIn("10240", rows[0]["value"])

    def test_gcp_tier_is_not_relay_capable(self):
        gcp = next(t for t in mesh.FREE_TIERS if t["slug"] == "gcp")
        self.assertLess(gcp["egress_gib_month"], mesh.MIN_RELAY_EGRESS_GIB_MONTH)
        self.assertEqual(gcp["role_fit"], [])

    def test_exit_requires_acknowledgement(self):
        ns = argparse_ns(
            guided=False,
            apply=True,
            provider="oci",
            role="exit",
            i_understand_exit_risk=False,
            country="DE",
            name=None,
            private=False,
            cover_budget_mib_day=2048,
            dry_run=False,
            yes=True,
        )
        self.assertEqual(mesh.cmd_offer(ns)["error"], "ExitRequiresAcknowledgement")


def argparse_ns(**kw):
    import argparse

    return argparse.Namespace(**kw)


if __name__ == "__main__":
    unittest.main()

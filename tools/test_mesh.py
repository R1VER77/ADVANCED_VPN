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

    def test_concentration_names_the_largest_provider_and_sphere(self):
        nodes = [
            node("a", ["entry"], "aws", "SE", "!op1"),
            node("b", ["relay"], "aws", "DE", "!op2"),
            node("c", ["exit"], "aws", "FR", "!op3"),
            node("d", ["exit"], "oci", "NL", "!op4"),
        ]
        rows = {r["label"]: r["value"] for r in mesh.concentration(nodes)}
        self.assertIn("aws: 3 of 4 nodes (75%)", rows["largest provider"])
        self.assertIn("sees much of every path", rows["largest provider"])
        balanced = {
            r["label"]: r["value"] for r in mesh.concentration(nodes[2:] + [node("e", ["relay"], "gcp", "IS", "!op5")])
        }
        self.assertNotIn("sees much of every path", balanced["largest provider"])

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


class SharedSelectionTests(unittest.TestCase):
    def test_selection_matches_the_data_plane(self):
        import mesh

        doc = json.loads((Path(__file__).resolve().parent / "testdata/chain_selection.json").read_text())
        for case in doc["cases"]:
            nodes, names = [], {}
            for name, roles, provider, country, op in case["nodes"]:
                node_id = mesh.member_id(("key-" + name).encode())
                names[node_id] = name
                nodes.append(
                    dict(
                        node_id=node_id,
                        roles=roles,
                        provider=provider,
                        country=country,
                        operator=mesh.member_id(op.encode()),
                        group="public",
                        health=dict(uptime_30d=0.99, latency_ms_p50=20),
                        capacity=dict(egress_gib_month=10240, cover_budget_mib_day=2048),
                    )
                )
            own = case.get("own_operator")
            try:
                got = [
                    names[d["node_id"]]
                    for d in mesh.select_chain(
                        nodes,
                        case["hops"],
                        own_operator=mesh.member_id(own.encode()) if own else None,
                        allow_same_jurisdiction=case.get("allow_same_jurisdiction", False),
                    )
                ]
            except SystemExit:
                got = None
            self.assertEqual(got, case["expect"], case["name"])

    def test_us_clouds_are_one_legal_sphere(self):
        import mesh

        self.assertEqual({mesh.legal_parent(p, "DE") for p in ["oci", "aws", "gcp", "azure"]}, {"US"})
        self.assertEqual(mesh.legal_parent("host", "is"), "IS")


if __name__ == "__main__":
    unittest.main()

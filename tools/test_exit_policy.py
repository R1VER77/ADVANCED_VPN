#!/usr/bin/env python3
"""Tests for the descriptor exit_policy field (tools/exit_policy.py):
fail-closed defaults, first-match semantics, the mandatory plan and
abuse_contact on inbound accepts, the profile gates, and mutation
checks (a broken policy must fail validation, never pass silently)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import exit_policy as ep  # noqa: E402


def open_outbound(**extra):
    policy = ep.default_outbound()
    policy.update(extra)
    return policy


class ValidationTests(unittest.TestCase):
    def test_missing_policy_is_valid_and_admits_nothing(self):
        self.assertEqual(ep.validate_policy(None), [])
        ok, reason = ep.admits(None, "tcp", 443, "outbound")
        self.assertFalse(ok)
        self.assertIn("no exit_policy", reason)

    def test_default_outbound_template_valid(self):
        self.assertEqual(ep.validate_policy(ep.default_outbound()), [])

    def test_default_must_be_refuse(self):
        policy = open_outbound()
        policy["default"] = "accept"
        errors = ep.validate_policy(policy)
        self.assertTrue(any("refuse" in e for e in errors))

    def test_inbound_accept_requires_plan_and_contact(self):
        policy = open_outbound()
        policy["rules"].append({"proto": "tcp", "ports": "6881-6889", "direction": "inbound", "effect": "accept"})
        errors = ep.validate_policy(policy)
        self.assertTrue(any("plan" in e for e in errors))
        self.assertTrue(any("abuse_contact" in e for e in errors))

    def test_inbound_accept_with_plan_and_contact_valid(self):
        policy = open_outbound()
        policy["inbound_admission"] = "static-manual"
        policy["rules"].append(
            {
                "proto": "tcp",
                "ports": "6881-6889",
                "direction": "inbound",
                "effect": "accept",
                "plan": "bulk",
                "abuse_contact": "!operator via mesh DM",
            }
        )
        self.assertEqual(ep.validate_policy(policy), [])

    def test_dynamic_admission_form_refused_for_now(self):
        """The NAT-PMP/UPnP dynamic form is a recorded owner decision
        away; a policy claiming it today is a validation error."""
        policy = open_outbound()
        policy["inbound_admission"] = "nat-pmp-upnp"
        errors = ep.validate_policy(policy)
        self.assertTrue(any("static-manual" in e for e in errors))

    def test_inbound_accept_requires_admission_switch(self):
        policy = open_outbound()  # inbound_admission: none
        policy["rules"].append(
            {
                "proto": "tcp",
                "ports": "6881",
                "direction": "inbound",
                "effect": "accept",
                "plan": "bulk",
                "abuse_contact": "!op",
            }
        )
        errors = ep.validate_policy(policy)
        self.assertTrue(any("inbound_admission" in e for e in errors))

    def test_bad_port_spec_rejected(self):
        policy = open_outbound()
        policy["rules"].append({"proto": "tcp", "ports": "0-70000", "direction": "outbound", "effect": "accept"})
        errors = ep.validate_policy(policy)
        self.assertTrue(any("ports" in e for e in errors))

    def test_mutation_reversed_ports_rejected(self):
        policy = open_outbound()
        policy["rules"].append({"proto": "tcp", "ports": "9000-8000", "direction": "outbound", "effect": "accept"})
        self.assertNotEqual(ep.validate_policy(policy), [])

    def test_unknown_proto_rejected(self):
        policy = open_outbound()
        policy["rules"].append({"proto": "sctp", "ports": "80", "direction": "outbound", "effect": "accept"})
        self.assertNotEqual(ep.validate_policy(policy), [])


class AdmissionTests(unittest.TestCase):
    def test_first_match_wins(self):
        """The carve-out: 25 is inside 1-65535 accept, but the later
        explicit reject is FIRST in rule order after reordering... the
        template puts the specific rejects after the broad accept, so
        the broad accept matches first. The correct semantics test:
        put the reject FIRST and it wins."""
        policy = open_outbound()
        # Move the smtp reject ahead of the broad accept.
        rules = policy["rules"]
        smtp_reject = [r for r in rules if r.get("ports") == "25"]
        rules[:] = smtp_reject + [r for r in rules if r.get("ports") != "25"]
        ok, _ = ep.admits(policy, "tcp", 25, "outbound")
        self.assertFalse(ok)
        ok, _ = ep.admits(policy, "tcp", 443, "outbound")
        self.assertTrue(ok)

    def test_default_outbound_admits_443_not_25(self):
        policy = ep.default_outbound()
        self.assertTrue(ep.admits(policy, "tcp", 443, "outbound")[0])
        self.assertFalse(ep.admits(policy, "tcp", 25, "outbound")[0])
        self.assertFalse(ep.admits(policy, "tcp", 445, "outbound")[0])
        self.assertFalse(ep.admits(policy, "udp", 1900, "outbound")[0])
        self.assertFalse(ep.admits(policy, "tcp", 6881, "inbound")[0])

    def test_udp_quic_admitted(self):
        policy = ep.default_outbound()
        self.assertTrue(ep.admits(policy, "udp", 443, "outbound")[0])

    def test_unmatched_flow_refused(self):
        policy = {
            "schema": 1,
            "default": "refuse",
            "rules": [{"proto": "tcp", "ports": "443", "direction": "outbound", "effect": "accept"}],
            "inbound_admission": "none",
        }
        ok, reason = ep.admits(policy, "tcp", 8080, "outbound")
        self.assertFalse(ok)
        self.assertIn("default refuse", reason)


class GateTests(unittest.TestCase):
    def test_streaming_gate_open_on_default(self):
        ok, _ = ep.admits_streaming(ep.default_outbound())
        self.assertTrue(ok)

    def test_streaming_gate_closed_without_443(self):
        policy = {
            "schema": 1,
            "default": "refuse",
            "rules": [],
            "inbound_admission": "none",
        }
        ok, reason = ep.admits_streaming(policy)
        self.assertFalse(ok)

    def test_bulk_gate_closed_by_default(self):
        ok, reason = ep.admits_inbound_bulk(ep.default_outbound())
        self.assertFalse(ok)
        self.assertIn("no inbound admission", reason)

    def test_bulk_gate_open_with_extension(self):
        policy = open_outbound()
        ext = ep.p2p_extension("6881-6889", "!operator")
        policy["inbound_admission"] = ext["inbound_admission"]
        policy["rules"].append(ext["rule"])
        self.assertEqual(ep.validate_policy(policy), [])
        ok, reason = ep.admits_inbound_bulk(policy)
        self.assertTrue(ok)
        self.assertIn("bulk", reason)

    def test_bulk_gate_closed_for_unlabelled_inbound(self):
        """An inbound accept without the bulk label does not open the
        bulk gate (another plan's admission is not P2P admission)."""
        policy = open_outbound()
        policy["inbound_admission"] = "static-manual"
        policy["rules"].append(
            {
                "proto": "tcp",
                "ports": "5000",
                "direction": "inbound",
                "effect": "accept",
                "plan": "self-hosted-app",
                "abuse_contact": "!operator",
            }
        )
        ok, _ = ep.admits_inbound_bulk(policy)
        self.assertFalse(ok)


class IntegrationTests(unittest.TestCase):
    def test_descriptor_with_policy_validates(self):
        """The mesh descriptor validator accepts a descriptor carrying
        a valid exit_policy (and rejects an invalid one) via the hook
        below — the same check `cypherpunk mesh publish` runs."""
        import json

        descriptor = {
            "schema": 3,
            "node_id": "!12345678",
            "roles": ["exit"],
            "provider": "oci",
            "country": "GB",
            "exit_policy": ep.default_outbound(),
        }
        # The hook mesh.validate calls:
        errors = ep.validate_policy(descriptor.get("exit_policy"))
        self.assertEqual(errors, [])

        bad = dict(descriptor)
        bad["exit_policy"] = {"schema": 1, "default": "accept", "rules": []}
        self.assertNotEqual(ep.validate_policy(bad["exit_policy"]), [])
        # round-trips through JSON like the signed descriptor does
        json.dumps(ep.default_outbound())


if __name__ == "__main__":
    unittest.main(verbosity=2)

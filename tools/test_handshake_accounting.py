"""Tests for the handshake and parameter-generation accounting
(tools/handshake_accounting.py) - ROADMAP section 6's "account for all
handshake flights and parameter generations" row, including the MAYO-1
category note and the PMTU/downgrade-preservation requirements.
"""

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import handshake_accounting as ha  # noqa: E402

REPO = TOOLS.parent
LINK_RS = (REPO / "src/link.rs").read_text()
TLS_RS = (REPO / "src/tls.rs").read_text()
CLOAK_RS = (REPO / "src/cloak.rs").read_text()


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.table = ha.build_accounting()

    def test_every_handshake_states_flights_generations_and_classification(self):
        for row in self.table["rows"]:
            for field in (
                "name",
                "plane",
                "flights",
                "generations",
                "kex",
                "auth",
                "classification",
                "inventory_surfaces",
                "note",
            ):
                self.assertIn(field, row, f"{row.get('name')!r} misses {field}")
            self.assertGreaterEqual(row["flights"], 0)
            self.assertGreaterEqual(row["generations"], 0)
            self.assertIn(row["plane"], ("data", "control", "local"))
            self.assertIn(row["classification"], ("classical", "hybrid", "pq"))

    def test_the_accounting_agrees_with_the_inventory_on_every_shared_surface(self):
        # build_accounting raises when they disagree; the totals must also add up
        totals = self.table["totals"]
        self.assertEqual(totals["handshakes"], len(ha.HANDSHAKES))
        self.assertEqual(totals["flights"], sum(r["flights"] for r in ha.HANDSHAKES))
        self.assertEqual(totals["secret_generations_per_full_setup"], sum(r["generations"] for r in ha.HANDSHAKES))
        self.assertEqual(
            totals["data_planes"] + totals["control_planes"] + totals["local_planes"], totals["handshakes"]
        )

    def test_a_row_naming_an_unknown_surface_fails_the_build(self):
        saved = ha.HANDSHAKES[0]["inventory_surfaces"]
        ha.HANDSHAKES[0]["inventory_surfaces"] = "a surface the inventory never heard of"
        try:
            with self.assertRaisesRegex(ValueError, "the PQ inventory does not"):
                ha.build_accounting()
        finally:
            ha.HANDSHAKES[0]["inventory_surfaces"] = saved

    def test_the_quoted_source_facts_still_hold(self):
        """The rows' notes quote the code; the code must still say so."""
        self.assertIn("pub const REKEY: Duration = Duration::from_secs(120);", LINK_RS)
        self.assertIn("X25519MLKEM768", TLS_RS)
        self.assertIn("no 0-RTT or resumption", TLS_RS)
        self.assertIn("fn role_proof", CLOAK_RS)
        self.assertIn("confirm_server", CLOAK_RS)


class MayoTests(unittest.TestCase):
    def test_mayo_is_accounted_as_category_one_not_three(self):
        self.assertEqual(ha.MAYO["parameter_set"], "MAYO_1")
        self.assertEqual(ha.MAYO["nist_category"], 1)
        self.assertIn("category-1 parameter set", ha.MAYO["category_note"])
        self.assertIn("ML-DSA-65", ha.MAYO["category_note"])
        self.assertIn("which MAYO-1 is not", ha.MAYO["category_note"])

    def test_the_baseline_is_retained_and_mayo_is_not_adopted(self):
        self.assertIn("retained", ha.MAYO["baseline"])
        self.assertIn("evaluated, not adopted", ha.MAYO["baseline"])
        self.assertIn("versioned migration", ha.MAYO["baseline"])
        self.assertIn("drill", ha.MAYO["baseline"])

    def test_pmtu_and_downgrade_protection_are_preserved(self):
        self.assertIn("PMTU", ha.MAYO["pmtu"])
        self.assertIn("never buys a weaker negotiation", ha.MAYO["pmtu"])

    def test_the_sizes_note_carries_the_corrected_numbers(self):
        self.assertIn("1,456-byte public keys", ha.MAYO["sizes_note"])
        self.assertIn("464-byte signatures", ha.MAYO["sizes_note"])
        self.assertIn("a sketch, not", ha.MAYO["sizes_note"])

    def test_the_stack_keeps_the_mldsa_baseline_today(self):
        """No shipped handshake row may name MAYO as its authentication."""
        for row in ha.HANDSHAKES:
            self.assertNotIn("MAYO", row["auth"], f"{row['name']} would be an adoption, not an evaluation")
            self.assertNotIn("MAYO", row["kex"])


if __name__ == "__main__":
    unittest.main()

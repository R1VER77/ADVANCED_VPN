"""The fail-closed and classical-vs-PQ pins of the mesh membership and credit
review (docs/MESH_CREDIT_REVIEW_20261122.md, ROADMAP section 4).

The roadmap row: "Review mesh membership and credit verification; keep
unreviewed mechanisms fail-closed and clearly label classical versus
post-quantum security assumptions." These tests hold the review's verdicts
against the real files, the same source-contract convention
test_controller_create_join.py uses: if someone wires an unreviewed
mechanism into the product or removes a label, a test fails here first.
"""

import re
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

REPO = TOOLS.parent
RUST_TOKENS = (REPO / "src/mesh/tokens.rs").read_text()
MESH_PY = (TOOLS / "mesh.py").read_text()
INVENTORY = (REPO / "docs/PQ_INVENTORY.md").read_text()
CYPHERPUNKCTL = (TOOLS / "cypherpunkctl.py").read_text()
ZK_DESIGN = (REPO / "docs/ZK_MEMBERSHIP_DESIGN.md").read_text()


class FailClosedPins(unittest.TestCase):
    """Unreviewed mechanisms never silently become load-bearing."""

    def test_the_rust_data_plane_rejects_every_spend_until_vendored(self):
        """src/mesh/tokens.rs verify_spend must bail on every call: the only
        path from a spend to accepted capacity runs through the reviewed
        verifier that does not exist yet."""
        self.assertIn("fail-closed", RUST_TOKENS)
        found = re.search(r"pub fn verify_spend\([^)]*\) -> Result<\(\)> \{(.*?)\n\}", RUST_TOKENS, re.S)
        self.assertIsNotNone(found, "verify_spend must stay the single verification gate")
        body = found.group(1)
        bails = re.findall(r'bail!\("([^"]+)"\)', body)
        self.assertTrue(bails, "verify_spend must bail, not accept")
        self.assertIn("VOPRF verification is not yet vendored; spend rejected (fail-closed)", bails)
        # and nothing in the data plane accepts a spend by another route
        self.assertNotIn("fn accept_spend", RUST_TOKENS)
        self.assertNotIn("Ok(())\n    } else", RUST_TOKENS.replace("bail!", ""))

    def test_the_quota_view_states_the_fail_closed_posture_and_both_labels(self):
        import mesh

        q = mesh.quota_view(now=1000000000)
        self.assertIn("fail-closed", q["public_pool"])
        self.assertIn("classical unforgeability", q["public_pool"])
        self.assertIn("unlinkability survives", q["public_pool"])
        self.assertIn("classical unforgeability", q["private_groups"])
        # Perfectly hiding blinding: no adversary, quantum or not, links a redemption.
        self.assertIn("unlinkability survives", q["private_groups"])
        self.assertNotIn("links redemptions", q["private_groups"])

    def test_the_zk_membership_prototype_is_wired_into_no_shipping_command(self):
        """ZK membership is research (its design says so); nothing in the CLI
        may depend on it until it is reviewed. cypherpunkctl is the command surface."""
        self.assertIn("research track, not wired into any command", ZK_DESIGN)
        for token in ("zk", "ZK_MEMBERSHIP", "zkid", "nullifier"):
            self.assertNotIn(
                token, CYPHERPUNKCTL, f"cypherpunkctl must not reference the unreviewed ZK mechanism ({token})"
            )

    def test_the_membership_proof_artifact_is_consumed_by_nothing(self):
        """publish() writes the FIDO2 assertion beside the descriptor as an
        artifact for the future ZK registration; until a verifier that checks
        it exists, nothing may read it as authorization (fail-closed by
        non-use, pinned here - test modules discuss it, they never consume it)."""
        writers = 0
        for source in TOOLS.glob("*.py"):
            if source.name.startswith("test_"):
                continue
            text = source.read_text()
            if "membership-proof" in text:
                # only the publish writer may name it
                self.assertEqual(source.name, "mesh.py")
                self.assertIn('MESH_DIR / "membership-proof.json"', text)
                writers += 1
        self.assertEqual(writers, 1, "exactly one module (mesh.py publish) may write the proof")
        for rust in (REPO / "src").rglob("*.rs"):
            self.assertNotIn("membership-proof", rust.read_text(), rust.name)


class QuantumLabelPins(unittest.TestCase):
    """Every credit mechanism states classical versus post-quantum plainly."""

    def test_the_voprf_group_credits_label_their_quantum_claim(self):
        import mesh_voprf

        # Forgery falls to a quantum adversary; linkage does not (perfectly hiding blinding).
        self.assertIn("classical unforgeability", mesh_voprf.QUANTUM_STATUS)
        self.assertIn("unlinkability survives", mesh_voprf.QUANTUM_STATUS)
        self.assertNotIn("does NOT survive", mesh_voprf.QUANTUM_STATUS)
        # the module's own docstring carries the explanation, not just a constant
        docstring = mesh_voprf.__doc__
        self.assertIn("CLASSICAL", docstring)
        self.assertIn("perfectly hiding", " ".join(docstring.split()))

    def test_the_inventory_names_every_credit_exception(self):
        for row, fragment in (
            ("1", "Mesh contribution credits"),  # public pool, blind RSA
            ("6", "Private-group contribution credits"),  # VOPRF, classical unforgeability
            ("7", "The voucher engine"),  # vouchers, blind RSA
        ):
            self.assertIsNotNone(
                re.search(rf"^{row}\. \*\*{fragment}", INVENTORY, re.M),
                f"exception {row} must stay named",
            )
        self.assertIn("perfectly hiding", INVENTORY)  # exception 6: only forgery falls
        # the count in the prose matches the list (the prose spells the number)
        count = len(re.findall(r"^([1-9])\.", INVENTORY, re.M))
        words = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}
        self.assertIn(f"The {words.get(count, count)} exceptions below are named", INVENTORY)

    def test_the_rsa_credits_state_which_half_survives(self):
        tokens_source = (TOOLS / "mesh_tokens.py").read_text()
        self.assertIn("RSA-3072 ~ 128-bit classical security", tokens_source)
        self.assertIn(
            "Unforgeability is the property a quantum adversary breaks",
            tokens_source,
        )


class MembershipPins(unittest.TestCase):
    """What the mesh's public membership actually rests on today."""

    def test_membership_is_the_hardware_backed_mldsa_key_fail_closed_at_ingestion(self):
        """A member IS the ML-DSA operator key: verify_descriptor checks the
        signature and that node_id is the key's hash; unverified descriptors
        never enter the directory (load_directory) and are never gossiped
        (the publish self-check)."""
        self.assertIn("pub.verify", MESH_PY)
        self.assertIn('member_id(base64.b64decode(descriptor["node_public_key"])) == descriptor["node_id"]', MESH_PY)
        self.assertIn("if validate(signed, now) or not verify_descriptor(signed)", MESH_PY)
        self.assertIn("refusing to gossip it", MESH_PY)
        # and the server-side member routing carries its own bounded pin set
        self.assertIn("member routing is server-only and bounded", (TOOLS / "managed_profile.py").read_text())

    def test_the_fido2_assertion_that_publish_records_is_labeled_advisory(self):
        """The assertion is recorded for the future ZK registration; the
        design must not let it be read as membership authorization today."""
        self.assertIn("together with the FIDO2 membership assertion over the same bytes", MESH_PY)


if __name__ == "__main__":
    unittest.main()

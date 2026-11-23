"""Pins for the voucher proof models (ROADMAP section 6, the voucher proofs row).

The provers themselves (ProVerif 2.05, Tamarin 1.12.0) run in CI through
tools/proverif_check.py and tools/tamarin_check.py; this module pins, on the
real files, that the models exist, say what they model, are registered in the
harnesses, and that every registered mutant edit still applies - so the CI
run cannot silently skip a broken mutant. The same source-contract
convention test_mesh_fail_closed.py uses.
"""

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

REPO = TOOLS.parent
PV = (REPO / "formal/voucher/voucher_unlinkability.pv").read_text()
SPTHY = (REPO / "formal/voucher/voucher_spend.spthy").read_text()
import proverif_check  # noqa: E402
import tamarin_check  # noqa: E402


class VoucherModelPins(unittest.TestCase):
    def test_the_unlinkability_model_states_its_property_adversary_and_limits(self):
        for fragment in (
            "PROPERTY: a mint that sees every payment webhook and every blinded issuance cannot",
            "ADVERSARY: the mint, also running the redemption ledger",
            "NOT CLAIMED (by design, and visible in the model): cross-TIER unlinkability",
            "timing (a",
            "voucher redeemed immediately after its webhook is linkable by wall-clock",
        ):
            self.assertIn(fragment, PV)
        # the blind-signature equational theory, the same as the credits model
        self.assertIn("unblind(sign(blind(m, r), k), r) = sign(m, k)", PV)
        # the equivalence is not vacuous: the adversary holds the mint key
        self.assertIn("out(c, sk);", PV)
        # within one tier: both webhooks and both redemptions carry the same tier
        self.assertEqual(PV.count("(payA, tier,"), 1)
        self.assertEqual(PV.count("(payB, tier,"), 1)
        self.assertGreaterEqual(PV.count("tier)"), 4)

    def test_the_spend_model_states_spent_state_recovery_as_its_lemma(self):
        for fragment in (
            "revoked_forever  after an epoch key's supply audit revokes it",
            "redemption BORROWS and",
            "no_double_redeem a voucher secret is redeemed at most once",
        ):
            self.assertIn(fragment, SPTHY)
        for lemma in ("executable:\n  exists-trace", "no_double_redeem:", "revoked_forever:"):
            self.assertIn(f"lemma {lemma}", SPTHY)

    def test_the_proved_model_is_registered_and_the_draft_is_not(self):
        self.assertEqual(
            proverif_check.MODELS["formal/voucher/voucher_unlinkability.pv"], ["Observational equivalence is true."]
        )
        # The spent-state model's revoked_forever does not terminate yet (its header says
        # why); registering it would fail CI's formal-models job, so it waits for its invariant.
        self.assertNotIn("formal/voucher/voucher_spend.spthy", tamarin_check.MODELS)
        self.assertIn("NOT registered in tools/tamarin_check.py", SPTHY)

    def test_every_voucher_mutant_edit_still_applies(self):
        """A mutant whose edit no longer applies fails the CI check outright;
        this pin catches it here first, without the provers."""
        for model, edits, what in proverif_check.MUTANTS:
            if "voucher" not in model:
                continue
            text = (REPO / model).read_text()
            for old, new in edits:
                self.assertIn(old, text, f"mutant ({what}) edit no longer applies: {old!r}")
                self.assertNotIn(new, text, f"mutant ({what}) already applied?: {new!r}")
        for model, edits, lemma in tamarin_check.MUTANTS:
            if "voucher" not in model:
                continue
            text = (REPO / model).read_text()
            for old, new in edits:
                self.assertIn(old, text, f"mutant ({lemma}) edit no longer applies: {old!r}")
                self.assertNotIn(new, text, f"mutant ({lemma}) already applied?: {new!r}")

    def test_the_voucher_row_names_its_remaining_halves(self):
        roadmap = (REPO / "docs/ROADMAP.md").read_text()
        # the row stays open until the spent-state model proves and the ZK side binds nullifiers
        self.assertIn("revoked_forever", roadmap)
        self.assertIn("nullifier binding on the ZK side", roadmap)
        voucher = (TOOLS / "voucher.py").read_text()
        self.assertIn("PQ_INVENTORY exception 7", voucher)  # the label from the review


if __name__ == "__main__":
    unittest.main()

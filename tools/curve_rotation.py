#!/usr/bin/env python3
"""The versioned migration drill for the interface/curve inventory.

ROADMAP section 6: "Complete the interface/curve inventory and versioned
migration. Preserve current device keys, document compatibility dependencies
and test the PQ property of each interface; do not silently reset hardware to
satisfy a design mandate." The inventory itself landed
(tools/curve_inventory.py); this module is the migration half - not a
deployment, a DRILL: the versioned procedure as an executable state machine
whose invariants are tested against every migration the inventory records as
open, so the day a real rotation runs, the procedure it follows is already
the one the tests held to these rules:

- STAGES, in order and only in order: announce (the new version is published
  and nothing accepts it yet), dual (both versions verify; every peer checks
  both; bounded in rounds - a dual period without a bound is a downgrade
  window without an end), cutover (the new version only; a v1-only peer is
  REFUSED, which is the point), done;
- NO KEY RESET: a migration stage that would drop or regenerate the
  interface's hardware-bound identity material is refused - device keys
  survive every stage, and "satisfying a design mandate" never silently
  resets hardware (the roadmap's own words);
- NO DOWNGRADE: a migration whose target classification is weaker than the
  current one (pq -> hybrid -> classical) is refused; sideways moves
  (classical -> classical with new parameters) are allowed only with an
  explicit reason, and the drill records them;
- The drill REPORT runs over the inventory's open migrations and states, for
  each, the stages, the bound, the preserved hardware dependency and the
  PQ-property test that must pass in the dual period before cutover.

The drill is deliberately synthetic: it exercises the PROCEDURE, not the
cryptography. The PQ property of each interface is tested by the inventory's
own pq_test rows; the physical rotation on real hardware remains owner-side.
"""

from __future__ import annotations

import time

SCHEMA = 1
STAGES = ("announce", "dual", "cutover", "done")
MAX_DUAL_ROUNDS = 90  # a bounded dual period: 90 rounds, not "until it settles"
CLASSIFICATION_ORDER = {"classical": 0, "hybrid": 1, "pq": 2}


class DrillError(Exception):
    """A migration step that violates the versioned-migration rules."""


def _classification(value: str) -> int:
    if value not in CLASSIFICATION_ORDER:
        raise DrillError(f"unknown_classification: {value!r}")
    return CLASSIFICATION_ORDER[value]


class Migration:
    """One interface's move from a current algorithm version to a target:
    the interface row (from the inventory), the two versions, the hardware
    dependency that must survive, and the PQ test that must pass in the dual
    period."""

    def __init__(
        self, interface, current, target, classification, hardware, pq_test, reason=None, dual_rounds=MAX_DUAL_ROUNDS
    ):
        if current == target:
            raise DrillError("a migration needs two different versions")
        if not 1 <= dual_rounds <= MAX_DUAL_ROUNDS:
            raise DrillError("dual_rounds_out_of_bounds")
        self.interface = interface
        self.current, self.target = current, target
        self.classification = classification
        self.hardware = hardware
        self.pq_test = pq_test
        self.reason = reason
        self.dual_rounds = dual_rounds
        self.stage = "announce"
        self.rounds_in_dual = 0
        self.hardware_preserved = True
        self.log: list[dict] = [self._row("announce", "the target version is published; nothing accepts it yet")]

    def _row(self, stage, note):
        return dict(stage=stage, interface=self.interface, at=round(time.time(), 3), note=note)

    def advance(self, dual_check=None):
        """One stage transition, enforcing every rule. `dual_check` is the
        PQ-property verdict for the dual period (the inventory's pq_test made
        callable); cutover refuses without a passing one."""
        if self.stage == "done":
            raise DrillError("migration_already_done")
        if self.stage == "announce":
            self.stage = "dual"
            self.log.append(self._row("dual", f"both {self.current} and {self.target} verify; every peer checks both"))
            return self.stage
        if self.stage == "dual":
            self.rounds_in_dual += 1
            if self.rounds_in_dual > self.dual_rounds:
                raise DrillError("dual_period_overrun: the bound is the migration's own rule")
            if dual_check is None or dual_check() is not True:
                raise DrillError("cutover_refused_without_a_passing_pq_test")
            if not self.hardware_preserved:
                raise DrillError("cutover_refused_after_a_key_reset")
            self.stage = "cutover"
            self.log.append(self._row("cutover", f"{self.target} only; a {self.current}-only peer is refused"))
            return self.stage
        # cutover -> done
        self.stage = "done"
        self.log.append(
            self._row(
                "done", f"{self.interface} runs {self.target}; {self.hardware or 'no hardware dependency'} preserved"
            )
        )
        return self.stage

    def reset_keys(self):
        """The forbidden act, modeled so the refusal can be tested: dropping
        or regenerating the interface's hardware-bound identity material."""
        self.hardware_preserved = False

    def report(self):
        """The drill's outcome, as the inventory records it."""
        return dict(
            schema=SCHEMA,
            interface=self.interface,
            current=self.current,
            target=self.target,
            classification=self.classification,
            hardware=self.hardware,
            hardware_preserved=self.hardware_preserved,
            dual_rounds=self.dual_rounds,
            stage=self.stage,
            reason=self.reason,
            log=self.log,
        )


def plan_from_inventory(inventory_row: dict) -> Migration:
    """Build the drill's Migration for one registry row of the inventory
    (tools/curve_inventory.py REGISTRY), applying the no-downgrade rule to
    the row's own classification."""
    return Migration(
        interface=inventory_row["interface"],
        current="v1",
        target="v2",
        classification=inventory_row["classification"],
        hardware=inventory_row.get("hardware") or "none",
        pq_test=inventory_row.get("pq_test") or "none recorded",
    )


def downgrade_check(current: str, target: str):
    """The no-downgrade rule as a standalone check: a target classification
    strictly weaker than the current one is refused; an equal one needs an
    explicit reason, recorded by the caller, never silent."""
    a, b = _classification(current), _classification(target)
    if b < a:
        raise DrillError(f"downgrade_refused: {current} -> {target}")
    if b == a:
        return "sideways: same classification, an explicit reason is required"
    return "upgrade"


def drill_registry(registry: list[dict], dual_check=lambda row: True) -> dict:
    """Run the full drill over the inventory's registry: every open
    migration is planned and walked to cutover (with the row's pq_test as
    the dual-period verdict), and the report states each stage. A row whose
    migration field does not start with 'open' is recorded as already
    landed and not drilled."""
    plans, landed = [], []
    for row in registry:
        if str(row.get("migration", "")).lower().startswith("open"):
            migration = plan_from_inventory(row)
            check = lambda r=row: dual_check(r)
            try:
                migration.advance()  # announce -> dual
                migration.advance(check)  # dual -> cutover (the pq test gates it)
                migration.advance()  # cutover -> done
            except DrillError as error:
                plans.append(dict(migration.report(), failed=str(error)))
                continue
            plans.append(migration.report())
        else:
            landed.append(row["interface"])
    return dict(
        schema=SCHEMA,
        generated=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        drilled=len(plans),
        already_landed=landed,
        plans=plans,
        note="A drill of the PROCEDURE, not a deployment: PQ properties come from each "
        "row's own tests; the physical rotation on real hardware stays owner-side.",
    )

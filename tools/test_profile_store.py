"""Tests for the client's profile store (tools/profile_store.py): the
multi-chain store, the active selection, the crash-safe swap and the launch
viability view of ROADMAP section 3.

The production verifier (the controller's own loader) needs the hash-locked
cryptography environment (mldsa/mlkem), so these tests drive the store with
stub verifiers that model every verdict the real one can produce; one gated
test at the bottom exercises production_verifier itself where available.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import profile_store as ps  # noqa: E402


def _pq_crypto_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401

        import managed_profile  # noqa: F401

        return True
    except ImportError:
        return False


class ChainFixture:
    """A state directory shaped like a real client enrollment, with the two
    facts the store reads outside the verifier (preferences and the pre-VPN
    network snapshot) under the test's control."""

    def __init__(
        self,
        root: Path,
        name="chain",
        *,
        current=True,
        guard_ready=True,
        endpoints=("192.0.2.10:41194", "198.51.100.20:4444"),
    ):
        self.dir = root / name
        self.dir.mkdir(mode=0o700, parents=True)
        self.endpoints = list(endpoints)
        self.current = current
        for file_name, payload in (
            ("profile.json", "{}"),
            ("network-before.json", "{}"),
            ("preferences.json", json.dumps({"mode": "applications"})),
        ):
            path = self.dir / file_name
            if guard_ready or file_name == "profile.json":
                path.write_text(payload)
                os.chmod(path, 0o600)

    def verifier(self, state):
        """A stub of production_verifier: verified+current by default; the
        fixture's flags model the verdicts the real one can produce."""
        if not (Path(state) / "profile.json").exists():
            raise ValueError("no profile")
        return {
            "role": "client",
            "hops": len(self.endpoints),
            "endpoints": self.endpoints,
            "current": self.current,
        }


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.where = ps.paths(self.root / "cypherpunk")
        (self.root / "cypherpunk").mkdir(mode=0o700)

    def chain(self, name, **kwargs):
        return ChainFixture(self.root, name, **kwargs)

    def per_name_verifier(self, current_by_name):
        """A stub verifier that answers by chain name (the active directory
        resolves to whatever selection.json names), modeling chains the real
        loader would accept or refuse as current."""
        where = self.where

        def verifier(state):
            if Path(state) == Path(where["active"]):
                name = ps.read_selection(where)["active"]
            else:
                name = Path(state).name
            if name not in current_by_name:
                raise ValueError("unknown chain")
            return {
                "role": "client",
                "hops": 2,
                "endpoints": ["192.0.2.10:41194", "198.51.100.20:4444"],
                "current": current_by_name[name] is True,
            }

        return verifier

    def adopt(self, fixture, name):
        return ps.adopt(fixture.dir, name, self.where, verifier=fixture.verifier)


class AdoptionTests(StoreTestCase):
    def test_a_verified_chain_moves_into_the_store(self):
        fixture = self.chain("one")
        result = self.adopt(fixture, "work")
        self.assertEqual(result["schema"], 1)
        self.assertEqual(result["name"], "work")
        self.assertFalse(fixture.dir.exists())
        self.assertTrue((self.where["store"] / "work" / "profile.json").exists())

    def test_names_are_bounded_and_refuse_traversal(self):
        fixture = self.chain("one")
        for bad in ("Work", "work limit", "../escape", "x" * 17, "", "-lead", "a_b"):
            with self.assertRaises(ps.Refused):
                self.adopt(fixture, bad)
        for good in ("work", "w", "work-2", "a" * 15):
            self.adopt(fixture, good)
            fixture = self.chain("again")  # a fresh source each time

    def test_collisions_and_unverified_chains_are_refused(self):
        fixture = self.chain("one")
        self.adopt(fixture, "work")
        other = self.chain("two")
        with self.assertRaisesRegex(ps.Refused, "profile_name_taken"):
            self.adopt(other, "work")
        broken = self.chain("three")
        (broken.dir / "profile.json").unlink()
        with self.assertRaises(ValueError):  # the verifier's own refusal
            self.adopt(broken, "broken")

    def test_non_client_roles_are_not_stored(self):
        class Server:
            def __init__(self, root):
                self.dir = root / "server"
                self.dir.mkdir(mode=0o700)
                (self.dir / "profile.json").write_text("{}")

            def verifier(self, state):
                return {"role": "exit", "hops": 1, "endpoints": ["198.51.100.9:4444"]}

        server = Server(self.root)
        with self.assertRaisesRegex(ps.Refused, "only_client_chains"):
            ps.adopt(server.dir, "exit-node", self.where, verifier=server.verifier)

    def test_the_store_is_bounded(self):
        for index in range(ps.MAX_STORED):
            self.adopt(self.chain(f"c{index}"), f"chain-{index}")
        with self.assertRaisesRegex(ps.Refused, "profile_store_full"):
            self.adopt(self.chain("extra"), "one-too-many")


class SelectionTests(StoreTestCase):
    def armed_world(self, *, current="home", extra=("work",)):
        """An active chain named in the selection plus stored chains."""
        active = self.chain(current)
        self.adopt(active, current)
        ps.select(current, self.where, unprotected=True, verifier=active.verifier)
        # promote: the chain is active again but the slot is empty; selection names it
        stored = []
        for name in extra:
            fixture = self.chain(name)
            self.adopt(fixture, name)
            stored.append(fixture)
        return active, stored

    def test_select_fails_closed_under_an_unconfirmed_guard(self):
        active, _ = self.armed_world()
        with self.assertRaisesRegex(ps.Refused, "refused_beneath_a_guard"):
            ps.select("work", self.where, verifier=active.verifier)

    def test_select_swaps_the_two_chains_and_updates_the_selection(self):
        active, _ = self.armed_world()
        result = ps.select("work", self.where, unprotected=True, verifier=active.verifier)
        self.assertEqual(result, {"schema": 1, "active": "work", "stored_previous": "home"})
        self.assertTrue((self.where["active"] / "profile.json").exists())
        self.assertFalse((self.where["store"] / "work").exists())
        self.assertTrue((self.where["store"] / "home").exists())
        self.assertEqual(ps.read_selection(self.where), {"schema": 1, "active": "work"})

    def test_select_refuses_unknown_targets_and_name_collisions(self):
        active, _ = self.armed_world()
        with self.assertRaisesRegex(ps.Refused, "no_such_stored_profile"):
            ps.select("nope", self.where, unprotected=True, verifier=active.verifier)
        # an active chain whose recorded name already has a slot
        other = self.chain("intruder")
        self.adopt(other, "home")
        with self.assertRaisesRegex(ps.Refused, "profile_name_taken"):
            ps.select("work", self.where, unprotected=True, verifier=active.verifier)

    def test_an_unnamed_active_chain_must_be_stored_first(self):
        fixture = self.chain("loose")
        self.adopt(fixture, "loose")
        ps.select("loose", self.where, unprotected=True, verifier=fixture.verifier)
        # model a client enrolled before the store existed: an active chain, no selection
        self.where["selection"].unlink()
        work = self.chain("work")
        self.adopt(work, "work")
        with self.assertRaisesRegex(ps.Refused, "name_the_active_chain"):
            ps.select("work", self.where, unprotected=True, verifier=work.verifier)
        # the explicit name satisfies it
        result = ps.select("work", self.where, unprotected=True, store_current_as="loose", verifier=work.verifier)
        self.assertEqual(result["stored_previous"], "loose")


class CrashRecoveryTests(StoreTestCase):
    """Every crash window of the swap, exercised by reconstructing the exact
    on-disk state the crash leaves behind."""

    def marker(self, **doc):
        path = self.where["selection"]
        path.write_text(json.dumps({"schema": 1, **doc}))
        os.chmod(path, 0o600)

    def armed_world(self):
        active = self.chain("home")
        self.adopt(active, "home")
        ps.select("home", self.where, unprotected=True, verifier=active.verifier)
        work = self.chain("work")
        self.adopt(work, "work")
        return active, work

    def swap_up_to(self, stop_after):
        """Replay the swap's renames by hand, stopping where a crash would."""
        active, work = self.armed_world()
        self.marker(active="home", phase="swap", **{"from": "home", "to": "work"})
        if stop_after == "marker":
            return active, work
        os.rename(self.where["active"], self.where["store"] / "home")
        if stop_after == "first-rename":
            return active, work
        os.rename(self.where["store"] / "work", self.where["active"])
        return active, work  # crash before the final selection write

    def test_a_crash_before_any_rename_rolls_back_to_the_steady_state(self):
        active, work = self.swap_up_to("marker")
        result = ps.repair(self.where)
        self.assertEqual(result["repaired"], "cleared_unstarted_swap")
        self.assertEqual(ps.read_selection(self.where)["active"], "home")
        self.assertTrue((self.where["active"] / "profile.json").exists())
        self.assertTrue((self.where["store"] / "work").exists())

    def test_a_crash_between_the_renames_undoes_the_half_swap(self):
        self.swap_up_to("first-rename")
        result = ps.repair(self.where)
        self.assertEqual(result["repaired"], "undid_half_swap")
        self.assertEqual(ps.read_selection(self.where)["active"], "home")
        self.assertTrue((self.where["active"] / "profile.json").exists())
        self.assertTrue((self.where["store"] / "work").exists())

    def test_a_crash_before_the_final_write_finalizes_the_completed_swap(self):
        self.swap_up_to("both-renames")
        result = ps.repair(self.where)
        self.assertEqual(result["repaired"], "finalized_completed_swap")
        self.assertEqual(ps.read_selection(self.where)["active"], "work")
        self.assertTrue((self.where["active"] / "profile.json").exists())
        self.assertTrue((self.where["store"] / "home").exists())
        self.assertFalse((self.where["store"] / "work").exists())

    def test_a_crashed_promotion_is_finalized_from_its_marker(self):
        # a promotion with no active chain: crash after the rename, before the write
        home = self.chain("home")
        self.adopt(home, "home")
        travel = self.chain("travel")
        self.adopt(travel, "travel")
        # the world has no active chain; the promotion of travel crashed mid-flight
        self.marker(active=None, phase="swap", **{"from": None, "to": "travel"})
        os.rename(self.where["store"] / "travel", self.where["active"])
        result = ps.repair(self.where)
        self.assertEqual(result["repaired"], "finalized_completed_swap")
        self.assertEqual(ps.read_selection(self.where)["active"], "travel")
        self.assertTrue((self.where["active"] / "profile.json").exists())

    def test_repair_reports_ambiguity_instead_of_guessing(self):
        self.swap_up_to("both-renames")
        # both slots present AND an active chain: not a state our swap can leave
        ghost = self.chain("ghost")
        self.adopt(ghost, "work")  # re-occupy the promoted slot: now all three exist
        result = ps.repair(self.where)
        self.assertEqual(result["repaired"], "ambiguous_swap_state")

    def test_a_malformed_marker_is_refused(self):
        self.armed_world()
        for bad in (
            {"active": "home", "phase": "swap"},  # missing from/to
            {"active": "home", "phase": "swap", "from": "../x", "to": "work"},
            {"active": "home", "phase": "rebase", "from": "home", "to": "work"},
            {"active": "home", "phase": "swap", "from": None, "to": None},
            {"active": "home", "phase": "swap", "from": "home", "to": "work", "extra": 1},
        ):
            self.marker(**bad)
            with self.assertRaises(ps.Refused):
                ps.repair(self.where)


class ViabilityTests(StoreTestCase):
    def viable(self, fixture, **kwargs):
        return ps.viability(fixture.dir, fixture.dir.name, self.where, verifier=fixture.verifier, **kwargs)

    def test_a_complete_chain_is_viable(self):
        fixture = self.chain("good")
        verdict = self.viable(fixture)
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["current"])
        self.assertTrue(verdict["protection_intact"])
        self.assertTrue(verdict["servers_healthy"])
        self.assertTrue(verdict["viable"])
        self.assertEqual(verdict["detail"]["probe"], "not_run")  # honest: no live probe ran

    def test_a_legacy_chain_is_verified_but_not_current(self):
        fixture = self.chain("old", current=False)
        verdict = self.viable(fixture)
        self.assertTrue(verdict["verified"])
        self.assertFalse(verdict["current"])
        self.assertFalse(verdict["viable"])

    def test_a_state_without_its_snapshot_is_not_protection_intact(self):
        fixture = self.chain("nosnap", guard_ready=False)
        verdict = self.viable(fixture)
        self.assertEqual(verdict["detail"]["protection"], "missing_network_snapshot")
        self.assertFalse(verdict["protection_intact"])

    def test_a_bad_preferences_file_is_not_protection_intact(self):
        fixture = self.chain("badprefs")
        (fixture.dir / "preferences.json").write_text(json.dumps({"mode": "everything"}))
        verdict = self.viable(fixture)
        self.assertEqual(verdict["detail"]["protection"], "preferences_out_of_contract")

    def test_unsafe_state_files_are_verdicts_not_crashes(self):
        fixture = self.chain("symlinked")
        (fixture.dir / "preferences.json").unlink()
        (fixture.dir / "preferences.json").symlink_to("/etc/passwd")
        verdict = self.viable(fixture)
        self.assertFalse(verdict["protection_intact"])

    def test_the_probe_hook_decides_servers_healthy_and_says_it_ran(self):
        fixture = self.chain("probed")
        verdict = self.viable(fixture, probe=lambda endpoint: True)
        self.assertEqual(verdict["detail"]["probe"], "run")
        self.assertTrue(verdict["servers_healthy"])
        verdict = self.viable(fixture, probe=lambda endpoint: False)
        self.assertFalse(verdict["servers_healthy"])
        verdict = self.viable(fixture, probe=lambda endpoint: (_ for _ in ()).throw(OSError("down")))
        self.assertEqual(verdict["detail"]["probe"], "probe_error")
        self.assertFalse(verdict["servers_healthy"])

    def test_an_unloadable_chain_reports_the_loaders_reason(self):
        fixture = self.chain("broken")
        (fixture.dir / "profile.json").unlink()
        verdict = self.viable(fixture)
        self.assertFalse(verdict["verified"])
        self.assertFalse(verdict["viable"])
        self.assertEqual(verdict["detail"]["verified"], "no profile")


class LaunchViewTests(StoreTestCase):
    def test_nothing_viable_offers_setup(self):
        view = ps.launch_view(self.where, verifier=lambda state: (_ for _ in ()).throw(ValueError("none")))
        self.assertEqual(view["offer"], "setup")
        self.assertEqual(view["profiles"], [])

    def test_a_viable_active_chain_offers_connect(self):
        active = self.chain("home")
        self.adopt(active, "home")
        ps.select("home", self.where, unprotected=True, verifier=active.verifier)
        view = ps.launch_view(self.where, verifier=active.verifier)
        self.assertEqual(view["offer"], "connect")
        self.assertEqual(view["active"], "home")
        self.assertEqual([p["where"] for p in view["profiles"]], ["active"])

    def test_only_stored_chains_viable_offers_choose(self):
        home = self.chain("home", current=False)  # the active chain is legacy
        self.adopt(home, "home")
        ps.select("home", self.where, unprotected=True, verifier=home.verifier)
        work = self.chain("work")
        self.adopt(work, "work")
        view = ps.launch_view(self.where, verifier=self.per_name_verifier({"home": False, "work": True}))
        self.assertEqual(view["offer"], "choose")
        self.assertEqual(view["active"], "home")
        self.assertEqual(
            [(p["name"], p["where"], p["viable"]) for p in view["profiles"]],
            [("home", "active", False), ("work", "stored", True)],
        )

    def test_the_view_repairs_a_half_swapped_world_before_offering(self):
        active = self.chain("home")
        self.adopt(active, "home")
        ps.select("home", self.where, unprotected=True, verifier=active.verifier)
        work = self.chain("work")
        self.adopt(work, "work")
        # crash the swap between the two renames
        self.where["selection"].write_text(
            json.dumps({"schema": 1, "active": "home", "phase": "swap", "from": "home", "to": "work"})
        )
        os.chmod(self.where["selection"], 0o600)
        os.rename(self.where["active"], self.where["store"] / "home")
        view = ps.launch_view(self.where, verifier=self.per_name_verifier({"home": True, "work": True}))
        self.assertEqual(view["repaired"], "undid_half_swap")
        self.assertEqual(view["offer"], "connect")  # home is active again and viable

    def test_foreign_directories_are_not_offered(self):
        (self.where["store"]).mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.where["store"] / "Not Ours").mkdir()
        view = ps.launch_view(self.where, verifier=lambda state: (_ for _ in ()).throw(ValueError("none")))
        self.assertEqual(view["profiles"], [])


class SelectionFileTests(StoreTestCase):
    def test_selection_permissions_and_shape_are_enforced(self):
        fixture = self.chain("one")
        self.adopt(fixture, "work")
        ps.write_selection(self.where, "work")
        path = self.where["selection"]
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(ps.Refused, "unsafe_selection"):
            ps.read_selection(self.where)
        os.chmod(path, 0o600)
        path.write_text("{not json")
        with self.assertRaisesRegex(ps.Refused, "unreadable_selection"):
            ps.read_selection(self.where)
        path.write_text(json.dumps({"schema": 2, "active": "work"}))
        with self.assertRaisesRegex(ps.Refused, "malformed_selection"):
            ps.read_selection(self.where)
        path.write_text(json.dumps({"schema": 1, "active": "../escape"}))
        with self.assertRaisesRegex(ps.Refused, "malformed_selection"):
            ps.read_selection(self.where)


@unittest.skipUnless(_pq_crypto_available(), "production_verifier needs the hash-locked environment (mldsa/mlkem)")
class ProductionVerifierTests(StoreTestCase):
    def test_the_production_verifier_reads_a_real_enrollment(self):
        # A real enrollment needs the full signing pipeline; here we only pin
        # that production_verifier is the controller's own loader (cypherpunkctl
        # load_profile + managed_profile require_current + chain_of) and that
        # it refuses an empty state directory.
        import inspect

        source = inspect.getsource(ps.production_verifier)
        self.assertIn("require_current", source)
        self.assertIn("load_profile", source)
        self.assertIn("chain_of", source)
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(Exception):
            ps.production_verifier(empty)


if __name__ == "__main__":
    unittest.main()

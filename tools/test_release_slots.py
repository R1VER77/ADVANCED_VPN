"""Application pointer failures must preserve code and never touch security state."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release_slots as slots


class ReleaseTransactions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "application"
        self.state = self.base / "enrolled"
        self.state.mkdir()
        (self.state / "replay-floor").write_text("9001")
        self.store = slots.Store(self.root)

    def build(self, text):
        def builder(path):
            (path / "program").write_text(text)
            (path / "program").chmod(0o644)

        return builder

    def initial(self):
        with self.store.transaction():
            name = self.store.prepare(self.build("previous"))
            self.store.activate(name, lambda _: None)
        return name

    def assert_state(self):
        self.assertEqual((self.state / "replay-floor").read_text(), "9001")

    def test_a_legacy_venv_may_name_only_its_system_interpreter(self):
        # Installs before the bundled runtime made classic venvs: venv/bin/python3 ->
        # /usr/bin/python3. Adopting one (--adopt-legacy) must keep it runnable; every other
        # link out of a slot stays refused.
        system = Path("/usr/bin/python3")
        if not system.exists() or system.resolve().stat().st_uid != 0:
            self.skipTest("no root-owned system python3 here")

        def legacy(links):
            def builder(path):
                (path / "venv/bin").mkdir(parents=True)
                (path / "venv").chmod(0o755)
                (path / "venv/bin").chmod(0o755)
                for name, target in links.items():
                    (path / "venv/bin" / name).symlink_to(target)

            return builder

        with self.store.transaction():
            name = self.store.prepare(legacy({"python3": str(system), "python": "python3", "python3.13": "python3"}))
        self.assertTrue((self.root / "releases" / name / "venv/bin/python").exists())
        for links in ({"pip": str(system)}, {"python3": "/etc/passwd"}, {"python3": "/bin/sh"}):
            with self.subTest(links), self.store.transaction(), self.assertRaisesRegex(ValueError, "escapes"):
                self.store.prepare(legacy(links))

    def test_upgrade_retains_running_slot_and_selects_one_coherent_tree(self):
        old = self.initial()
        old_path = self.store.verify(old)
        with (old_path / "program").open() as running:
            with self.store.transaction():
                new = self.store.prepare(self.build("candidate"))
                self.store.activate(new, lambda path: self.assertEqual((path / "program").read_text(), "candidate"))
            self.assertEqual(running.read(), "previous")
        self.assertEqual(self.store.current(), new)
        self.assertTrue(old_path.exists())
        self.assert_state()

    def legacy(self):
        self.root.mkdir(mode=0o700)
        app = self.root / "app"
        app.mkdir(mode=0o755)
        (app / "program").write_text("old flat code")
        (app / "program").chmod(0o644)
        return app

    def test_legacy_exchange_keeps_the_public_name_and_original_inode(self):
        app = self.legacy()
        original = app.stat().st_ino
        with self.store.transaction():
            candidate = self.store.prepare(self.build("old flat code"))
            self.store.adopt(candidate, ["app"])
        self.assertTrue(app.is_symlink())
        self.assertEqual((app / "program").read_text(), "old flat code")
        self.assertEqual((self.root / "legacy-flat/app").stat().st_ino, original)
        self.assert_state()

    def test_interrupted_legacy_exchange_recovers_before_next_installation(self):
        app = self.legacy()
        rename = Path.rename

        def interrupted(path, target):
            if path.name.startswith(".adopt-"):
                raise OSError("power-loss simulation after atomic exchange")
            return rename(path, target)

        with self.store.transaction():
            candidate = self.store.prepare(self.build("old flat code"))
            with mock.patch.object(Path, "rename", interrupted):
                with self.assertRaisesRegex(OSError, "power-loss"):
                    self.store.adopt(candidate, ["app"])
            self.assertTrue(app.exists())
            self.assertEqual((app / "program").read_text(), "old flat code")
        with slots.Store(self.root).transaction():
            self.assertEqual(slots.read_json(self.root / "ADOPTION.json")["phase"], "complete")
        self.assertTrue((self.root / "legacy-flat/app/program").exists())
        self.assert_state()

    def test_legacy_exchange_cannot_name_external_state(self):
        self.initial()
        with self.store.transaction():
            with self.assertRaises(ValueError):
                self.store.exchange("../enrolled", ".adopt-" + "a" * 32)
        self.assert_state()

    def test_failed_application_check_restores_only_application_pointer(self):
        previous = self.initial()
        with self.store.transaction():
            new = self.store.prepare(self.build("new"))

            def incompatible(_):
                (self.state / "replay-floor").write_text("9002")
                raise ValueError("incompatible profile")

            with self.assertRaisesRegex(ValueError, "incompatible profile"):
                self.store.activate(new, incompatible)
        self.assertEqual(self.store.current(), previous)
        self.assertEqual((self.state / "replay-floor").read_text(), "9002")
        self.assertEqual(json.loads(self.store.journal.read_text())["phase"], "rolled_back")

    def test_disk_full_during_preparation_never_changes_current(self):
        previous = self.initial()
        with self.store.transaction():
            with mock.patch.object(slots, "sync_tree", side_effect=OSError(28, "No space left")):
                with self.assertRaises(OSError):
                    self.store.prepare(self.build("new"))
        self.assertEqual(self.store.current(), previous)

    def test_verified_repair_retains_corrupt_slot_without_rolling_back_to_it(self):
        previous = self.initial()
        (self.store.slot_path(previous) / "program").write_text("damaged")
        with self.store.transaction():
            candidate = self.store.prepare(self.build("verified repair"))
            with self.assertRaises(ValueError):
                self.store.activate(candidate, lambda _: None)
            self.store.activate(candidate, lambda _: None, repair_damaged=True)
        self.assertEqual(self.store.current(), candidate)
        self.assertEqual((self.store.slot_path(previous) / "program").read_text(), "damaged")
        self.assertEqual(slots.read_json(self.store.journal)["unusable_previous"], previous)
        self.assert_state()

    def test_failed_repair_and_interrupted_repair_never_select_damaged_code(self):
        previous = self.initial()
        (self.store.slot_path(previous) / "program").write_text("damaged")
        with self.store.transaction():
            candidate = self.store.prepare(self.build("incompatible repair"))
            with self.assertRaisesRegex(RuntimeError, "incompatible"):
                self.store.activate(
                    candidate, lambda _: (_ for _ in ()).throw(RuntimeError("incompatible")), repair_damaged=True
                )
        self.assertIsNone(self.store.current())
        # Simulate a cut after durable repair intent, before pointer replacement.
        with self.store.transaction():
            self.store.pointer(candidate)
            slots.durable_json(
                self.store.journal,
                dict(schema=1, phase="prepared", candidate=candidate, previous=None, unusable_previous=previous),
            )
        with self.store.transaction():
            self.assertIsNone(self.store.current())
        self.assert_state()
        self.assertFalse(list(self.store.releases.glob(".prepare-*")))
        self.assert_state()

    def test_torn_activation_recovers_before_or_after_journal_update(self):
        for phase in ("prepared", "activated"):
            with self.subTest(phase=phase):
                previous = self.initial()
                with self.store.transaction():
                    new = self.store.prepare(self.build("new"))
                    slots.durable_json(
                        self.store.journal, dict(schema=1, phase=phase, previous=previous, candidate=new)
                    )
                    self.store.pointer(new)
                # Represents a new invocation after loss of process/power, with
                # the already persisted pointer and journal. It is a simulation.
                with slots.Store(self.root).transaction() as recovered:
                    self.assertEqual(recovered.current(), previous)
                self.assert_state()

    def test_corrupt_candidate_is_never_activated(self):
        previous = self.initial()
        with self.store.transaction():
            new = self.store.prepare(self.build("new"))
            (self.store.slot_path(new) / "program").write_text("corrupt")
            with self.assertRaisesRegex(ValueError, "manifest"):
                self.store.activate(new, lambda _: self.fail("corrupt code executed"))
        self.assertEqual(self.store.current(), previous)

    def test_exclusive_lock_refuses_another_upgrade(self):
        with self.store.transaction():
            with self.assertRaises(BlockingIOError):
                with slots.Store(self.root).transaction():
                    self.fail("second owner obtained the lock")

    def test_symlink_and_special_file_candidates_are_refused(self):
        self.initial()
        builders = [
            lambda p: (p / "escape").symlink_to(self.state),
            lambda p: os.mkfifo(p / "fifo"),
            lambda p: (p / "escape").symlink_to("../../enrolled/replay-floor"),
        ]
        with self.store.transaction():
            for builder in builders:
                with self.assertRaises(ValueError):
                    self.store.prepare(builder)
        self.assert_state()

    def test_journal_traversal_or_unexpected_current_never_mutates_state(self):
        previous = self.initial()
        slots.durable_json(
            self.store.journal, dict(schema=1, phase="activated", previous=previous, candidate="../enrolled")
        )
        with self.assertRaises(ValueError):
            with self.store.transaction():
                self.fail("untrusted journal accepted")
        self.assert_state()

    def test_first_install_failure_restores_absence(self):
        with self.store.transaction():
            new = self.store.prepare(self.build("new"))
            with self.assertRaisesRegex(RuntimeError, "failed"):
                self.store.activate(new, lambda _: (_ for _ in ()).throw(RuntimeError("failed")))
        self.assertIsNone(self.store.current())
        with self.store.transaction():
            self.assertIsNone(self.store.current())
        self.assert_state()

    def test_fsync_or_pointer_failure_never_reports_a_commit(self):
        previous = self.initial()
        with self.store.transaction():
            new = self.store.prepare(self.build("new"))
            replace = os.replace

            def fail_current(source, destination):
                if Path(destination).name == "current":
                    raise OSError("injected pointer failure")
                return replace(source, destination)

            with mock.patch.object(slots.os, "replace", side_effect=fail_current):
                with self.assertRaisesRegex(OSError, "pointer failure"):
                    self.store.activate(new, lambda _: self.fail("unselected code checked"))
        self.assertEqual(self.store.current(), previous)
        self.assertNotEqual(slots.read_json(self.store.journal)["phase"], "committed")


if __name__ == "__main__":
    unittest.main()

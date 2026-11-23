#!/usr/bin/env python3
"""The first-launch agreement the app ships: made from the documents, and current."""

from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agreement  # noqa: E402


class Agreement(unittest.TestCase):
    def test_the_app_ships_the_current_documents(self):
        self.assertEqual(agreement.OUT.read_text(encoding="utf-8"), agreement.render(),
                         "run tools/agreement.py --generate")  # fmt: skip

    def test_both_documents_are_shipped_whole_as_plain_text(self):
        built = agreement.build()
        self.assertEqual([d["title"] for d in built["documents"]], ["Terms of service", "Privacy notice"])
        for doc, name in zip(built["documents"], agreement.SOURCES, strict=True):
            source = (agreement.ROOT / name).read_text(encoding="utf-8")
            headings = [line.lstrip("#").strip() for line in source.splitlines() if line.startswith("## ")]
            self.assertEqual([s["heading"] for s in doc["sections"] if s["heading"]], headings)
            text = " ".join(b["t"] for s in doc["sections"] for b in s["blocks"])
            for marker in ("](", "**", "`", "|---"):
                self.assertNotIn(marker, text)
        # A clause from inside a list and the table both arrive.
        terms = " ".join(b["t"] for s in built["documents"][0]["sections"] for b in s["blocks"])
        self.assertIn("You may not impose further restrictions", terms)
        privacy = [b["t"] for s in built["documents"][1]["sections"] for b in s["blocks"]]
        self.assertIn("Websites. Can see: The exit's address and what you send them. Cannot see: Your address.", privacy)

    def test_any_change_to_a_document_changes_the_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in agreement.SOURCES:
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(agreement.ROOT / name, root / name)
            with mock.patch.object(agreement, "ROOT", root):
                before = agreement.version()
                self.assertRegex(before, r"^[0-9a-f]{64}$")
                with open(root / agreement.SOURCES[1], "a", encoding="utf-8") as f:
                    f.write(" ")
                self.assertNotEqual(agreement.version(), before)

    def test_check_fails_on_a_stale_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "agreement.json"
            stale.write_text("{}")
            with mock.patch.object(agreement, "OUT", stale), mock.patch("sys.stderr"):
                self.assertEqual(agreement.main(["--check"]), 1)


if __name__ == "__main__":
    unittest.main()

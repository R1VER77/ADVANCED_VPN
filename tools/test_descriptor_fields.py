"""The descriptor's exit_policy and streaming fields: tools/mesh.py accepts and refuses
exactly the cases in tests/fixtures/descriptor_fields.json, which the Rust
Descriptor::validate test (src/mesh/descriptor.rs) runs too, so a descriptor the Python
side signs is never one every Rust node refuses."""

import json
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mesh  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / "tests/fixtures/descriptor_fields.json").read_text())


def descriptor(extra):
    now = int(time.time())
    base = dict(schema=mesh.SCHEMA, roles=["exit"], country="DE", published=now, expires=now + 3600)
    return dict(base, **extra)


class SharedFixture(unittest.TestCase):
    def test_accepted_cases_validate(self):
        for i, case in enumerate(FIXTURE["accept"]):
            with self.subTest(case=i):
                self.assertEqual(mesh.validate(descriptor(case)), [])

    def test_refused_cases_are_refused(self):
        for i, case in enumerate(FIXTURE["refuse"]):
            with self.subTest(case=i):
                errors = [e for e in mesh.validate(descriptor(case)) if e.startswith(("exit_policy", "streaming"))]
                self.assertTrue(errors, case)

    def test_the_rust_test_reads_the_same_file(self):
        rust = (Path(__file__).resolve().parents[1] / "src/mesh/descriptor.rs").read_text()
        self.assertIn('include_str!("../../tests/fixtures/descriptor_fields.json")', rust)


if __name__ == "__main__":
    unittest.main()

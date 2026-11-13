"""`avpn init` signs a chain only against a stated bandwidth allowance or an accepted cost."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

AVPNCTL = Path(__file__).resolve().parent / "avpnctl.py"
sys.path.insert(0, str(AVPNCTL.parent))

from rates import rate_cost_gib  # noqa: E402


def init(d, *extra):
    return subprocess.run(
        [sys.executable, AVPNCTL, "init", "--out", d / "bundles", "--exit", "192.0.2.10:443", "--relay",
         "192.0.2.11:443", "--hops", "2", "--request", "client=%s" % (d / "missing.req"), "--software-operator",
         d / "op", *extra],
        capture_output=True, text=True, timeout=120,
    )  # fmt: skip


class CostGateTests(unittest.TestCase):
    def test_no_allowance_and_no_accepted_cost_is_refused_with_the_cost(self):
        with tempfile.TemporaryDirectory() as d:
            r = init(Path(d), "--hours-per-day", "24")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no --allowance-gib", r.stderr)
        # metered, a relay's two links, around the clock (about 350 GiB/month).
        self.assertIn("%d GiB/month around the clock" % rate_cost_gib("metered", 24, 2), r.stderr)

    def test_an_allowance_or_accepted_cost_passes_the_gate(self):
        for extra in (["--allowance-gib", "10240"], ["--accept-cost"]):
            with tempfile.TemporaryDirectory() as d:
                r = init(Path(d), *extra)
            # Past the gate: it then fails on the (deliberately missing) request file.
            self.assertNotIn("no --allowance-gib", r.stderr, extra)


if __name__ == "__main__":
    unittest.main()

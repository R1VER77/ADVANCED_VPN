"""System-install preflight blocks before staging or host writes; no real install is performed."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import install


class InstallationGate(unittest.TestCase):
    def test_a_blocker_is_shown_with_package_guidance(self):
        report = dict(
            ready=False,
            install="sudo apt-get install nftables",
            findings=[dict(severity="blocker", message="nft is missing")],
        )
        with patch("preflight.inspect_host", return_value=report):
            with self.assertRaisesRegex(RuntimeError, "nft is missing"):
                install.installation_preflight()

    def test_failed_preflight_does_not_create_stage_or_touch_host(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "stage"
            with (
                patch("sys.argv", ["install.py", "--out", str(out), "--apply"]),
                patch.object(install.os, "geteuid", return_value=0),
                patch.object(install, "installation_preflight", side_effect=RuntimeError("blocked")),
                patch.object(install, "install_system") as system,
                patch.object(install.subprocess, "run") as run,
                patch.object(Path, "mkdir", side_effect=AssertionError("write before preflight")),
            ):
                with self.assertRaisesRegex(RuntimeError, "blocked"):
                    install.main()
            self.assertFalse(out.exists())
            system.assert_not_called()
            run.assert_not_called()

    def test_passing_gate_uses_release_binaries_and_no_optional_credentials(self):
        report = dict(ready=True, install=None, findings=[dict(severity="warning", message="Review Landlock support")])
        with (
            patch("preflight.inspect_host", return_value=report) as check,
            contextlib.redirect_stderr(io.StringIO()) as warning,
        ):
            self.assertIs(install.installation_preflight("systemd-creds"), report)
        options = check.call_args.args[0]
        self.assertEqual(options.package, install.ROOT / "target/release")
        self.assertFalse(options.hardware)
        self.assertEqual(options.provider, [])
        self.assertIn("Review Landlock", warning.getvalue())

    def test_plaintext_keys_are_refused_before_staging(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "stage"
            with (
                patch(
                    "sys.argv", ["install.py", "--out", str(out), "--apply", "--role", "client", "--protect", "none"]
                ),
                patch.object(install.os, "geteuid", return_value=0),
                patch.object(install, "installation_preflight") as check,
                patch.object(Path, "mkdir", side_effect=AssertionError("write before validation")),
            ):
                with self.assertRaises(ValueError):
                    install.main()
            check.assert_not_called()
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()

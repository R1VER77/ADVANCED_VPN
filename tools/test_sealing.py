"""The server key-protection rule shared by the installer, `cypherpunkctl request` and
`cypherpunk cloud host setup` (tools/sealing.py): TPM2-sealed, or locked to the operator's
Nitrokey; never the host key alone."""

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import install  # noqa: E402
import sealing  # noqa: E402


def no_tpm():
    return False


def tpm():
    return True


class Rule(unittest.TestCase):
    def test_a_server_without_a_tpm_may_not_use_systemd_creds(self):
        for role in sealing.SERVER_ROLES:
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, "--protect operator --unlock-key"):
                sealing.check_server_protection(role, "systemd-creds", probe=no_tpm)
            sealing.check_server_protection(role, "systemd-creds", probe=tpm)

    def test_operator_protection_is_for_servers_and_needs_the_unlock_key(self):
        sealing.check_server_protection("exit", "operator", Path("u.pub"), probe=no_tpm)
        with self.assertRaisesRegex(ValueError, "needs --unlock-key"):
            sealing.check_server_protection("exit", "operator", probe=no_tpm)
        with self.assertRaisesRegex(ValueError, "for servers"):
            sealing.check_server_protection("client", "operator", Path("u.pub"), probe=no_tpm)
        with self.assertRaisesRegex(ValueError, "with --protect operator only"):
            sealing.check_server_protection("exit", "systemd-creds", Path("u.pub"), probe=tpm)

    def test_a_client_keeps_its_choices(self):
        for protect in ("nitrokey", "systemd-creds"):
            sealing.check_server_protection("client", protect, probe=no_tpm)

    def test_the_probe_answers_without_raising(self):
        self.assertIsInstance(sealing.tpm2_sealing_works(), bool)  # as an ordinary user: False


class Installer(unittest.TestCase):
    def run_install(self, *args):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "stage"
            with (
                mock.patch("sys.argv", ["install.py", "--out", str(out), "--apply", *args]),
                mock.patch.object(install.os, "geteuid", return_value=0),
                mock.patch.object(sealing, "tpm2_sealing_works", no_tpm),
                mock.patch.object(install, "installation_preflight") as check,
                mock.patch.object(Path, "mkdir", side_effect=AssertionError("write before validation")),
            ):
                with self.assertRaises(ValueError) as caught:
                    install.main()
            check.assert_not_called()
            self.assertFalse(out.exists())
            return str(caught.exception)

    def test_a_server_without_a_tpm_is_refused_before_anything_is_staged(self):
        self.assertIn("--protect operator", self.run_install("--role", "exit", "--protect", "systemd-creds"))

    def test_operator_protection_needs_an_existing_unlock_key_and_a_server(self):
        self.assertIn("needs --unlock-key", self.run_install("--role", "exit", "--protect", "operator"))
        self.assertIn("for servers", self.run_install("--role", "client", "--protect", "operator", "--unlock-key", "x"))
        self.assertIn(
            "no unlock key at",
            self.run_install("--role", "exit", "--protect", "operator", "--unlock-key", "/nonexistent"),
        )


class Request(unittest.TestCase):
    def test_cypherpunkctl_request_refuses_a_tpm_less_server_with_systemd_creds(self):
        import cypherpunkctl

        with tempfile.TemporaryDirectory() as d:
            argv = ["cypherpunkctl", "--state", d + "/s", "request", "--role", "exit", "--protect", "systemd-creds",
                    "--out", d + "/r.req"]  # fmt: skip
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(cypherpunkctl, "harden_process", lambda: None),
                mock.patch.object(sealing, "tpm2_sealing_works", no_tpm),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as caught:
                    cypherpunkctl.main()
            self.assertIn("TPM2", str(caught.exception))
            self.assertFalse(Path(d, "s").exists())


class Preflight(unittest.TestCase):
    def test_preflight_accepts_operator_protection(self):
        import preflight

        p = preflight.build_parser() if hasattr(preflight, "build_parser") else None
        if p is None:
            import argparse

            p = argparse.ArgumentParser()
            preflight.add_arguments(p)
        self.assertEqual(p.parse_args(["--protect", "operator"]).protect, "operator")


if __name__ == "__main__":
    unittest.main()

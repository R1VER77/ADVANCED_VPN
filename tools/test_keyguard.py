"""Key envelopes, hybrid KEM, trusted executables and the PIN prompt order."""

import os
import fcntl
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidTag
from keyguard import b64, seal_bytes, open_bytes, memory_fd, F_GET_SEALS, F_SEAL_WRITE


class KeyEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.secret = os.urandom(32)
        self.meta = dict(credential=b64(os.urandom(64)), salt=b64(os.urandom(32)))
        self.cert = b"test certificate"
        self.key = os.urandom(128)
        self.envelope = seal_bytes(self.secret, self.meta, "inner", self.cert, self.key)

    def test_roundtrip(self):
        self.assertEqual(open_bytes(self.secret, self.meta, "inner", self.cert, self.envelope), self.key)

    def test_wrong_hardware_secret_rejected(self):
        with self.assertRaises(InvalidTag):
            open_bytes(os.urandom(32), self.meta, "inner", self.cert, self.envelope)

    def test_role_and_certificate_swapping_rejected(self):
        for role, cert in [("outer", self.cert), ("inner", b"other")]:
            with self.assertRaises(ValueError):
                open_bytes(self.secret, self.meta, role, cert, self.envelope)

    def test_ciphertext_tampering_rejected(self):
        from keyguard import unb64

        value = dict(self.envelope)
        b = bytearray(unb64(value["ciphertext"]))
        b[-1] ^= 1
        value["ciphertext"] = b64(b)
        with self.assertRaises(InvalidTag):
            open_bytes(self.secret, self.meta, "inner", self.cert, value)

    def test_ml_dsa_65_identity_key_roundtrip(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import mldsa

        key = mldsa.MLDSA65PrivateKey.generate()
        der = key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        opened = open_bytes(
            self.secret, self.meta, "outer", self.cert, seal_bytes(self.secret, self.meta, "outer", self.cert, der)
        )
        fd = memory_fd(opened)
        try:
            restored = serialization.load_der_private_key(os.read(fd, 16384), password=None)
            self.assertIsInstance(restored, mldsa.MLDSA65PrivateKey)
            self.assertEqual(
                restored.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            )
        finally:
            os.close(fd)

    def test_memfd_is_readable_but_immutable(self):
        fd = memory_fd(self.key)
        try:
            self.assertEqual(os.read(fd, 1000), self.key)
            with self.assertRaises(OSError):
                os.write(fd, b"x")
            self.assertTrue(fcntl.fcntl(fd, F_GET_SEALS) & F_SEAL_WRITE)
        finally:
            os.close(fd)


class TrustedExecutableTests(unittest.TestCase):
    def test_resolves_only_system_binaries_never_path(self):
        import tempfile
        from keyguard import trusted_exe

        self.assertTrue(trusted_exe("sh").startswith(("/usr/", "/bin/")))
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "ip"
            fake.write_text("#!/bin/sh\necho hijacked\n")
            fake.chmod(0o755)
            old = os.environ.get("PATH", "")
            os.environ["PATH"] = d + ":" + old
            try:
                self.assertNotEqual(
                    trusted_exe("ip") if Path("/usr/sbin/ip").exists() or Path("/sbin/ip").exists() else "", str(fake)
                )
            finally:
                os.environ["PATH"] = old
        for bad in ["../ip", "/tmp/ip", ""]:
            with self.assertRaises(ValueError):
                trusted_exe(bad)
        with self.assertRaises(FileNotFoundError):
            trusted_exe("definitely-not-a-real-binary-avpn")


class PinPromptTests(unittest.TestCase):
    """Where the FIDO2 PIN comes from: terminal, systemd service, desktop, or nowhere."""

    def run_prompt(self, tty=False, env=None, completed=None):
        import subprocess, sys
        from unittest import mock
        import keyguard

        calls = []

        def fake_run(args, **kw):
            calls.append(list(args))
            if args[0] == "/fake/pinentry-gnome3":
                return subprocess.CompletedProcess(args, 0, stdout=b"OK\nD desktop-pin\nOK\n", stderr=b"")
            return completed or subprocess.CompletedProcess(args, 0, stdout=b"4711\n", stderr=b"")

        environ = {k: v for k, v in os.environ.items() if k not in ("INVOCATION_ID", "DISPLAY", "WAYLAND_DISPLAY")}
        environ.update(env or {})
        with (
            mock.patch.object(sys.stdin, "isatty", return_value=tty),
            mock.patch.dict(os.environ, environ, clear=True),
            mock.patch.object(keyguard, "ASK_PASSWORD", sys.executable),
            mock.patch.object(keyguard.subprocess, "run", fake_run),
            mock.patch.object(keyguard, "PINENTRY", "/fake/pinentry-gnome3"),
            mock.patch.object(
                keyguard.Path, "exists", lambda self: str(self) in (sys.executable, "/fake/pinentry-gnome3")
            ),
            mock.patch("getpass.getpass", return_value="tty-pin"),
        ):
            try:
                return keyguard.pinentry(), calls
            except RuntimeError as e:
                return e, calls

    def test_terminal_uses_no_echo_prompt(self):
        value, calls = self.run_prompt(tty=True, env={"INVOCATION_ID": "x"})
        self.assertEqual(value, "tty-pin")
        self.assertEqual(calls, [])

    def test_service_asks_systemd_agents_without_caching(self):
        import sys

        value, calls = self.run_prompt(env={"INVOCATION_ID": "abc"})
        self.assertEqual(value, "4711")
        self.assertEqual(calls[0][0], sys.executable)
        self.assertFalse(
            [a for a in calls[0] if a.startswith(("--keyname", "--accept-cached", "--credential"))], calls[0]
        )
        self.assertIn("--echo=no", calls[0])
        self.assertTrue(any(a.startswith("--timeout=") for a in calls[0]))

    def test_unanswered_or_empty_service_prompt_is_refused(self):
        import subprocess

        for completed in [
            subprocess.CompletedProcess([], 1, stdout=b"", stderr=b""),
            subprocess.CompletedProcess([], 0, stdout=b"\n", stderr=b""),
        ]:
            value, _ = self.run_prompt(env={"INVOCATION_ID": "abc"}, completed=completed)
            self.assertIsInstance(value, RuntimeError)

    def test_desktop_session_inside_systemd_scope_uses_desktop_dialog(self):
        # Regression: desktop apps run in systemd scopes, so INVOCATION_ID alone
        # must not divert a desktop session to systemd's (absent) password agent.
        value, calls = self.run_prompt(env={"INVOCATION_ID": "scope", "DISPLAY": ":0"})
        self.assertEqual(value, "desktop-pin")
        self.assertEqual([c[0] for c in calls], ["/fake/pinentry-gnome3"])

    def test_no_terminal_service_or_desktop_refuses_without_prompting(self):
        value, calls = self.run_prompt()
        self.assertIsInstance(value, RuntimeError)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()

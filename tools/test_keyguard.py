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


class PinDialogTests(unittest.TestCase):
    """The desktop pop-up comes first, also under sudo (as the invoking user); a dialog
    that cannot open falls back to the terminal; Cancel stops; never over SSH."""

    def prompt(self, euid=1000, env=None, tty=True, dialog=b"OK\nD dialog-pin\nOK\n", rc=0, raises=None):
        import subprocess
        import sys
        import tempfile
        from unittest import mock
        import keyguard

        calls = []

        def fake_run(args, **kw):
            calls.append((list(args), kw))
            if raises:
                raise raises
            return subprocess.CompletedProcess(args, rc, stdout=dialog, stderr=b"")

        self.tmp = tempfile.TemporaryDirectory()
        environ = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION")}
        environ.update(env or {})
        real_path = keyguard.Path

        def fake_path(*parts):
            p = real_path(*parts)
            # /run/user/<uid> lives under a temporary root for the sudo case.
            if str(p).startswith("/run/user"):
                return real_path(self.tmp.name + str(p))
            return p

        run_dir = real_path(self.tmp.name + "/run/user/1000")
        run_dir.mkdir(parents=True)
        (run_dir / "wayland-0").touch()
        (run_dir / "wayland-0.lock").touch()
        (run_dir / "bus").touch()
        with (
            mock.patch.dict(os.environ, environ, clear=True),
            mock.patch.object(keyguard.os, "geteuid", return_value=euid),
            mock.patch.object(keyguard, "Path", fake_path),
            mock.patch.object(keyguard, "PINENTRY", sys.executable),
            mock.patch.object(keyguard.subprocess, "run", fake_run),
            mock.patch.object(sys.stdin, "isatty", return_value=tty),
            mock.patch("getpass.getpass", return_value="tty-pin"),
        ):
            try:
                return keyguard.pinentry(), calls
            except RuntimeError as e:
                return e, calls
            finally:
                self.tmp.cleanup()

    def test_your_own_desktop_pops_up_before_the_terminal(self):
        value, calls = self.prompt(env={"WAYLAND_DISPLAY": "wayland-0"})
        self.assertEqual(value, "dialog-pin")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("user", calls[0][1])  # already you: no user switch

    def test_under_sudo_the_dialog_runs_as_the_invoking_user_in_their_session(self):
        # Live regression (14 Nov 2026): as root the dialog could not open ("PIN dialog stopped").
        value, calls = self.prompt(euid=0, env={"SUDO_UID": "1000", "SUDO_GID": "1000"})
        self.assertEqual(value, "dialog-pin")
        kw = calls[0][1]
        self.assertEqual((kw["user"], kw["group"], kw["extra_groups"]), (1000, 1000, []))
        self.assertEqual(kw["env"]["WAYLAND_DISPLAY"], "wayland-0")
        self.assertTrue(kw["env"]["DBUS_SESSION_BUS_ADDRESS"].endswith("/run/user/1000/bus"))
        self.assertTrue(kw["env"]["XDG_RUNTIME_DIR"].endswith("/run/user/1000"))

    def test_a_dialog_that_cannot_open_falls_back_to_the_terminal(self):
        for case in [dict(dialog=b"ERR 83918950 Inappropriate ioctl\n", rc=0), dict(raises=OSError("no display"))]:
            value, _ = self.prompt(env={"WAYLAND_DISPLAY": "wayland-0"}, **case)
            self.assertEqual(value, "tty-pin", case)

    def test_cancel_stops_and_does_not_fall_back(self):
        value, _ = self.prompt(env={"WAYLAND_DISPLAY": "wayland-0"}, dialog=b"ERR 83886179 Operation cancelled\n")
        self.assertIsInstance(value, RuntimeError)
        self.assertIn("cancelled", str(value))

    def test_never_a_dialog_over_ssh_or_when_switched_off(self):
        for extra in [{"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22"}, {"AVPN_PIN_DIALOG": "0"}]:
            value, calls = self.prompt(env={"WAYLAND_DISPLAY": "wayland-0", **extra})
            self.assertEqual((value, calls), ("tty-pin", []), extra)

    def test_root_without_sudo_has_no_desktop_to_use(self):
        value, calls = self.prompt(euid=0, env={})
        self.assertEqual((value, calls), ("tty-pin", []))

    def test_root_with_a_display_of_its_own_uses_it(self):
        # As before the pop-up came first: root's own desktop, or a root process given
        # DISPLAY without sudo, keeps its dialog (in its own session, as root).
        value, calls = self.prompt(euid=0, env={"DISPLAY": ":0"})
        self.assertEqual(value, "dialog-pin")
        self.assertIsNone(calls[0][1].get("user"))
        self.assertEqual(calls[0][1]["env"]["DISPLAY"], ":0")


if __name__ == "__main__":
    unittest.main()


class PinProtocolQuirkTests(unittest.TestCase):
    """A key whose hmac-secret works only under PIN/UV protocol 1 is named by AAGUID up front."""

    def info(self, aaguid, protocols):
        from fido2.ctap2 import Info
        from fido2.webauthn import Aaguid

        return Info(
            versions=["FIDO_2_0"], extensions=["hmac-secret"], aaguid=Aaguid.parse(aaguid), pin_uv_protocols=protocols
        )

    def test_tkey_negotiates_protocol_1(self):
        import keyguard

        self.assertEqual(keyguard.pin_protocols(self.info("dbe42d66-22be-4624-8811-972a8e65367e", [1, 2])), [1])

    def test_a_tkey_without_protocol_1_is_left_with_nothing(self):
        import keyguard

        self.assertEqual(keyguard.pin_protocols(self.info("dbe42d66-22be-4624-8811-972a8e65367e", [2])), [])

    def test_other_keys_keep_every_protocol_they_offer(self):
        import keyguard

        self.assertEqual(keyguard.pin_protocols(self.info("00000000-0000-0000-0000-000000000001", [2, 1])), [2, 1])

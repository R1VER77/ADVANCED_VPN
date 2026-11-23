#!/usr/bin/env python3
"""The troubleshooting engine and the local assistant (tools/troubleshoot.py, assistant.py).

The engine is tested against the tools' real failure text, including the relay's own
line from the 22 November incident. The assistant is tested with stand-in models for
every way an answer can be wrong, and once with the real Gemma model when
CPVPN_ASSISTANT_MODEL and CPVPN_ASSISTANT_SERVER name a verified model and llama-server.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import assistant  # noqa: E402
import troubleshoot  # noqa: E402

INCIDENT = [  # the relay rebuild of 22 Nov 2026, as its build output ended
    "Install cpvpn-relay as the relay",
    "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 489333 (apt-get)",
]


def actions(finding):
    return [f["action"] for f in finding["fixes"]]


class Engine(unittest.TestCase):
    def test_the_relay_incident_is_a_held_apt_lock_with_retry_first(self):
        f = troubleshoot.diagnose("Install cpvpn-relay as the relay", INCIDENT, server="cpvpn-relay")
        self.assertEqual(f["code"], "apt_lock_held")
        self.assertEqual(f["fixes"], [dict(action="retry_build"), dict(action="host_update", server="cpvpn-relay")])
        self.assertIn("Could not get lock", f["evidence"][0])

    def test_each_failure_class_from_its_real_text(self):
        cases = {
            "aws_signed_out": ["An error occurred (ExpiredToken) when calling the GetCallerIdentity operation"],
            "server_dns_blocked": ["Err:1 http://deb.debian.org/debian trixie InRelease",
                                   "  Temporary failure resolving 'deb.debian.org'"],
            "server_locked": ["cpvpn-flyexit did not accept its data key"],
            "pin_wrong": ["fido2.ctap.CtapError: CTAP error: 0x31 - PIN_INVALID"],
            "pin_blocked": ["CTAP error: 0x32 - PIN_BLOCKED"],
            "key_not_touched": ["debug1: ssh_sk_sign: fido_dev_get_assert: FIDO_ERR_USER_ACTION_TIMEOUT"],
            "ssh_unreachable": ["ssh: connect to host 203.0.113.9 port 22: Connection timed out"],
            "fly_token_missing": ["fly api: 401 Unauthorized"],
            "capped": ["cpvpn-relay: capped until 2026-12-01"],
        }  # fmt: skip
        for code, lines in cases.items():
            with self.subTest(code=code):
                self.assertEqual(troubleshoot.diagnose("a step", lines, server="cpvpn-relay")["code"], code)

    def test_the_helpers_signed_out_event_decides_even_without_log_lines(self):
        f = troubleshoot.diagnose("Check sign-ins", [], server="cpvpn-relay", event=dict(error="signed_out"))
        self.assertEqual(f["code"], "aws_signed_out")
        self.assertEqual(f["fixes"][0], dict(action="sign_in_aws", server="cpvpn-relay"))

    def test_normal_setup_output_triggers_nothing(self):
        lines = ["keys locked to the operator's Nitrokey (unlock after each reboot: cypherpunk cloud unlock cpvpn-x)",
                 "Renew it with: aws login --profile flashbots", "Open the firewalls", "Sign the chain"]  # fmt: skip
        self.assertEqual(troubleshoot.diagnose("Sign the chain", lines)["code"], "unknown")

    def test_an_unknown_failure_keeps_its_last_lines_and_offers_a_retry(self):
        f = troubleshoot.diagnose("x", ["a", "b", "c", "d"])
        self.assertEqual(
            (f["code"], f["evidence"], actions(f)), ("unknown", ["b", "c", "d"], ["retry_build", "open_docs"])
        )

    def test_server_fixes_need_a_server(self):
        self.assertEqual(actions(troubleshoot.diagnose("x", INCIDENT)), ["retry_build"])

    def test_evidence_is_scrubbed_of_addresses_accounts_tokens_and_keys(self):
        secrets = [
            "ssh: connect to host 198.51.100.4 port 22: Connection refused",
            "relay 2a05:d016:13e:b301:f141:8630:66d7:aaa1 refused",
            "account 123456789012 key " + "AKIA" + "ABCDEFGHIJKLMNOP",  # built here, not a real key
            "Authorization: Fly" + "V1 fm2" + "_lJPECAAAAAAAB secret",  # a fake token, split
            "pubkey " + "ab" * 32,
            "blob " + "Qk" * 30,
            "PIN=4821 rejected: Connection refused",
            "instance i-0123456789abcdef0 Connection refused",
        ]
        f = troubleshoot.diagnose("x", secrets)
        text = " ".join(f["evidence"])
        for leak in ("198.51.100.4", "2a05:", "123456789012", "AKIA", "fm2_", "abab" * 4, "QkQk", "4821",
                     "i-0123456789abcdef0"):  # fmt: skip
            self.assertNotIn(leak, text)

    def test_only_offered_fixes_are_admissible(self):
        f = troubleshoot.diagnose("x", INCIDENT, server="cpvpn-relay")
        self.assertTrue(troubleshoot.valid_fix(f, dict(action="retry_build")))
        self.assertFalse(troubleshoot.valid_fix(f, dict(action="host_update", server="cpvpn-other")))
        self.assertFalse(troubleshoot.valid_fix(f, dict(action="unlock_server", server="cpvpn-relay")))


class Assistant(unittest.TestCase):
    def setUp(self):
        self.finding = troubleshoot.diagnose("Install cpvpn-relay as the relay", INCIDENT, server="cpvpn-relay")

    def reply(self, answer):
        return assistant.explain(self.finding, ask=lambda *_: answer)

    def test_a_valid_answer_is_used_with_its_offered_suggestion(self):
        r = self.reply(json.dumps(dict(explanation="The server was busy updating.", suggestion="host_update")))
        self.assertEqual((r["source"], r["explanation"]), ("assistant", "The server was busy updating."))
        self.assertEqual(r["suggestion"], dict(action="host_update", server="cpvpn-relay"))

    def test_a_suggestion_the_finding_does_not_offer_is_dropped(self):
        r = self.reply(json.dumps(dict(explanation="Busy.", suggestion="unlock_server")))
        self.assertEqual((r["source"], r["suggestion"]), ("assistant", None))

    def test_an_explanation_that_gives_commands_is_refused(self):
        for bad in ("Run `sudo apt-get update` first.", "Type sudo rm -rf /var/lib/apt/lists then retry.",
                    "See https://example.com/fix", "Use curl to fetch it && retry."):  # fmt: skip
            with self.subTest(bad=bad):
                r = self.reply(json.dumps(dict(explanation=bad, suggestion="retry_build")))
                self.assertEqual((r["source"], r["why"]), ("rules", "answer_refused"))
                self.assertEqual(r["explanation"], self.finding["meaning"])

    def test_malformed_answers_fall_back_to_the_rules(self):
        for bad in ("not json", "[]", json.dumps(dict(suggestion="retry_build")), json.dumps(dict(explanation=""))):
            with self.subTest(bad=bad):
                self.assertEqual(self.reply(bad)["source"], "rules")

    def test_no_model_gives_the_rules_text_and_says_why(self):
        def missing(*_):
            raise assistant.AssistantUnavailable("assistant_not_installed")

        r = assistant.explain(self.finding, ask=missing)
        self.assertEqual((r["source"], r["why"], r["explanation"]), ("rules", "assistant_not_installed",
                                                                      self.finding["meaning"]))  # fmt: skip

    def test_the_model_sees_only_scrubbed_facts_and_the_offered_fixes(self):
        f = troubleshoot.diagnose("x", ["ssh: connect to host 198.51.100.4 port 22: Connection timed out"],
                                  server="cpvpn-relay")  # fmt: skip
        text = assistant.prompt(f)
        self.assertNotIn("198.51.100.4", text)
        self.assertIn("check_health", text)
        self.assertEqual(
            assistant.answer_schema(f)["properties"]["suggestion"]["enum"], ["check_health", "retry_build"]
        )

    def test_an_unverified_model_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            model, server = Path(tmp) / "m.gguf", Path(tmp) / "llama-server"
            with self.assertRaisesRegex(assistant.AssistantUnavailable, "assistant_not_installed"):
                assistant.installed(model, server)
            model.write_bytes(b"x")
            server.write_text("#!/bin/sh\n")
            server.chmod(0o755)
            with self.assertRaisesRegex(assistant.AssistantUnavailable, "model_not_verified"):
                assistant.installed(model, server)
            model.with_name(model.name + ".sha256").write_text("0" * 64 + "\n")
            with self.assertRaisesRegex(assistant.AssistantUnavailable, "model_not_verified"):
                assistant.installed(model, server)


class Launcher(unittest.TestCase):
    """Installed, the packaged launcher creates the namespace; from a checkout, unshare -rn."""

    def argv_for(self, packaged):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            model, server, isolate = home / "m.gguf", home / "llama-server", home / "isolate"
            for f in (model, server, isolate):
                f.write_bytes(b"x")
            server.chmod(0o755)
            seen = []

            def popen(argv, **_):
                seen.append(argv)
                raise RuntimeError("stop before running anything")

            with mock.patch.object(assistant, "SERVER", server if packaged else home / "other"), \
                 mock.patch.object(assistant, "ISOLATE", isolate), \
                 mock.patch.object(assistant, "installed"), \
                 mock.patch.object(assistant.subprocess, "Popen", popen):  # fmt: skip
                with self.assertRaises(RuntimeError):
                    assistant.ask_local_model("q", {}, model, server)
            return seen[0], isolate, server

    def test_the_installed_server_runs_through_the_launcher(self):
        argv, isolate, _ = self.argv_for(packaged=True)
        self.assertEqual(argv[0], str(isolate))
        self.assertNotIn("unshare", " ".join(argv))
        self.assertIn("--offline", argv)

    @unittest.skipUnless(shutil.which("unshare"), "needs unshare")
    def test_a_checkout_server_runs_under_unshare(self):
        argv, _, server = self.argv_for(packaged=False)
        self.assertEqual(argv[1:4], ["-rn", "--", str(server)])


def namespace_works():
    unshare = shutil.which("unshare")
    return bool(unshare) and subprocess.run([unshare, "-rn", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(namespace_works(), "unprivileged network namespaces are not allowed here")
class Isolation(unittest.TestCase):
    def test_the_models_namespace_has_no_interface_but_loopback(self):
        out = subprocess.run(["unshare", "-rn", "cat", "/proc/net/dev"], capture_output=True, text=True, check=True)
        names = [line.split(":")[0].strip() for line in out.stdout.splitlines()[2:]]
        self.assertEqual(names, ["lo"])


@unittest.skipUnless(namespace_works() and shutil.which("gcc"), "needs gcc and unprivileged namespaces")
class IsolateLauncher(unittest.TestCase):
    """deploy/assistant/isolate.c, built pointing at cat: what the started program gets."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.exe = Path(cls.tmp.name) / "isolate"
        source = Path(__file__).resolve().parents[1] / "deploy/assistant/isolate.c"
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", '-DSERVER="/bin/cat"', "-o", str(cls.exe),
                        str(source)], check=True)  # fmt: skip

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, path):
        return subprocess.run([str(self.exe), path], capture_output=True, text=True, check=True).stdout

    def test_only_loopback_own_uid_no_capabilities_no_new_privileges(self):
        self.assertEqual([x.split(":")[0].strip() for x in self.read("/proc/net/dev").splitlines()[2:]], ["lo"])
        uid = str(os.getuid())
        self.assertEqual(self.read("/proc/self/uid_map").split(), [uid, uid, "1"])
        status = dict(x.split(":", 1) for x in self.read("/proc/self/status").splitlines() if ":" in x)
        self.assertEqual(status["CapEff"].strip(), "0" * 16)
        self.assertEqual(status["NoNewPrivs"].strip(), "1")

    def test_it_starts_only_its_fixed_program(self):
        # argv[1] is an argument to the fixed program, never a program to run.
        r = subprocess.run([str(self.exe), "/bin/sh", "-c", "echo escaped"], capture_output=True, text=True)
        self.assertNotIn("escaped", r.stdout)


MODEL = os.environ.get("CPVPN_ASSISTANT_MODEL")
SERVER = os.environ.get("CPVPN_ASSISTANT_SERVER")


@unittest.skipUnless(MODEL and SERVER and namespace_works(), "set CPVPN_ASSISTANT_MODEL/_SERVER for the real model")
class RealModel(unittest.TestCase):
    def test_gemma_explains_the_relay_incident_within_the_rules(self):
        f = troubleshoot.diagnose("Install cpvpn-relay as the relay", INCIDENT, server="cpvpn-relay")
        text = assistant.ask_local_model(assistant.prompt(f), assistant.answer_schema(f), Path(MODEL), Path(SERVER))
        r = assistant.check(f, text)
        self.assertIsNotNone(r, text)
        self.assertRegex(r["explanation"].lower(), r"lock|busy|update|another")
        self.assertIn(r["suggestion"], f["fixes"])


if __name__ == "__main__":
    unittest.main()

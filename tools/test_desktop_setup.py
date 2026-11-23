#!/usr/bin/env python3
"""The desktop app's own-servers helper: profile, server listing, checks and the chain build."""

import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cloud  # noqa: E402
import desktop_setup  # noqa: E402

REQUEST = json.dumps({"role": "client", "schema": 1, "keys": "public only"}).encode()


class Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


class FakeProcess:
    """Stands in for `cloud.py chain --apply`: progress events, then the signed bundles."""

    def __init__(self, argv, chain_dir, inventory, code=0, **_):
        self.argv, self.code = argv, code
        events = [cloud.PROGRESS_MARK + json.dumps(dict(plan=["Open the firewalls", "Sign the chain"])),
                  cloud.PROGRESS_MARK + json.dumps(dict(step=1, state="wait", note="touch")),
                  "ssh: some noise", "last words"]  # fmt: skip
        self.stderr = io.StringIO("\n".join(events) + "\n")
        if code == 0:
            bundles = chain_dir / "bundles"
            bundles.mkdir(parents=True)
            (bundles / "client.cpvpn").write_bytes(b"signed-bundle")
            (bundles / "operator.pub").write_bytes(b"operator-key")
            inv = json.loads(inventory.read_text())
            inv["chain"].update(bundles=str(bundles), hops=argv[argv.index("--order") + 1].split(","))
            inventory.write_text(json.dumps(inv))

    def wait(self):
        return self.code


class DesktopSetup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.vault = self.home / "vault"
        self.vault.mkdir()
        (self.vault / "credential.json").write_text("{}")
        self.inventory = self.home / "cypherpunk-vpn" / "cloud.json"
        self.inventory.parent.mkdir()
        resources = {
            "cpvpn-relay": dict(
                provider="aws",
                profile="flashbots",
                role="relay",
                public_ip="192.0.2.10",
                ssh_key="k",
                region="eu-north-1",
            ),
            "cpvpn-flyexit": dict(provider="fly", catalog="fly", role="exit", public_ip="2001:db8::1"),
            "cpvpn-home": dict(provider="ssh", role="exit", public_ip="198.51.100.7", ssh_key="k"),
            "cpvpn-unbuilt": dict(provider="oci", catalog="oci", role="exit"),
        }
        chain = dict(hops=["cpvpn-relay", "cpvpn-flyexit"], created="x", bundles="", vault=str(self.vault))
        self.inventory.write_text(json.dumps(dict(schema=1, resources=resources, chain=chain)))
        patches = [mock.patch.dict(os.environ, XDG_CONFIG_HOME=str(self.home)),
                   mock.patch.object(cloud, "INVENTORY", self.inventory),
                   mock.patch.object(desktop_setup.providers, "cli_path", return_value="/usr/bin/aws")]  # fmt: skip
        # AWS sign-ins answer "signed in" unless a test says otherwise; no test reaches AWS.
        self.signed_out = set()
        self.asked = []

        def quick(argv, **_):
            self.asked.append(argv)
            return argv[argv.index("--profile") + 1] not in self.signed_out

        patches.append(mock.patch.object(desktop_setup.providers, "quick", side_effect=quick))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_state_names_a_private_profile_seeded_from_the_recorded_chain(self):
        s = desktop_setup.state()
        self.assertRegex(s["profile"]["name"], r"^[a-z]+-[a-z]+-\d\d$")
        self.assertEqual(s["profile"]["providers"], ["aws", "fly"])
        self.assertEqual(s["profile"]["active_providers"], 2)
        self.assertEqual(os.stat(desktop_setup.profile_path()).st_mode & 0o777, 0o600)
        # The name is kept: a second read is the same profile.
        self.assertEqual(desktop_setup.state()["profile"]["name"], s["profile"]["name"])
        names = {x["name"]: x for x in s["servers"]}
        self.assertEqual(set(names), {"cpvpn-relay", "cpvpn-flyexit", "cpvpn-home"})  # unbuilt is no hop
        self.assertFalse(names["cpvpn-flyexit"]["first_hop_ok"])
        self.assertEqual(names["cpvpn-home"]["provider"], "own")
        self.assertEqual(names["cpvpn-relay"]["sphere"], "US")
        self.assertTrue(s["chain"]["operator_vault"])

    def test_providers_are_added_and_removed_only_from_the_fixed_list(self):
        desktop_setup.state()
        self.assertIn("hetzner", desktop_setup.add("hetzner")["profile"]["providers"])
        # A provider without a recorded server is in the profile but not active.
        self.assertEqual(desktop_setup.state()["profile"]["active_providers"], 2)
        self.assertNotIn("aws", desktop_setup.remove("aws")["profile"]["providers"])
        self.assertEqual(desktop_setup.state()["profile"]["active_providers"], 1)
        for bad in ("../x", "AWS", "evil;rm", ""):
            with self.assertRaises(desktop_setup.Refused):
                desktop_setup.add(bad)

    def test_build_refuses_out_of_contract_routes_before_running_anything(self):
        run = mock.Mock()
        for order, hours, reason in (
            ("cpvpn-flyexit,cpvpn-relay", 8, "first_hop_needs_ipv4"),
            ("cpvpn-relay,cpvpn-unbuilt", 8, "unknown_server"),
            ("cpvpn-relay,--accept-cost", 8, "unknown_server"),
            ("cpvpn-relay,cpvpn-relay", 8, "one_to_three_different_servers"),
            ("cpvpn-relay,cpvpn-home,cpvpn-flyexit,cpvpn-x", 8, "one_to_three_different_servers"),
            ("cpvpn-relay,cpvpn-flyexit", 7, "invalid_hours"),
        ):
            with self.assertRaises(desktop_setup.Refused) as e:
                desktop_setup.build(order, hours, Stdin(REQUEST), run)
            self.assertEqual(str(e.exception), reason)
        for raw in (b"", b"not json", json.dumps({"role": "exit"}).encode(), b"x" * (desktop_setup.MAX_REQUEST + 1)):
            with self.assertRaises(desktop_setup.Refused):
                desktop_setup.build("cpvpn-relay,cpvpn-flyexit", 8, Stdin(raw), run)
        run.assert_not_called()

    def test_build_runs_the_fixed_chain_command_and_returns_the_bundle(self):
        seen = {}

        def run(argv, **kw):
            seen.update(argv=argv, env=kw["env"])
            return FakeProcess(argv, self.home / "chain", self.inventory)

        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = desktop_setup.build("cpvpn-relay,cpvpn-flyexit", 6, Stdin(REQUEST), run)
        self.assertEqual(code, 0)
        argv = seen["argv"]
        self.assertEqual(argv[argv.index("--order") + 1], "cpvpn-relay,cpvpn-flyexit")
        self.assertEqual(argv[argv.index("--vault") + 1], str(self.vault))
        self.assertEqual(argv[argv.index("--hours-per-day") + 1], "6")
        self.assertNotIn("--accept-cost", argv)
        self.assertEqual(seen["env"]["CPVPN_PROGRESS"], "events")
        request = Path(argv[argv.index("--client-request") + 1])
        self.assertEqual(request.read_bytes(), REQUEST)
        self.assertEqual(os.stat(request).st_mode & 0o777, 0o600)
        events = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([e["event"] for e in events], ["progress", "progress", "done"])
        self.assertEqual(events[1]["state"], "wait")
        done = events[-1]
        self.assertEqual(base64.b64decode(done["bundle_base64"]), b"signed-bundle")
        self.assertEqual(base64.b64decode(done["operator_base64"]), b"operator-key")
        self.assertEqual(desktop_setup.state()["profile"]["hours_per_day"], 6)

    def test_a_failed_build_reports_its_last_line_and_no_bundle(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = desktop_setup.build(
                "cpvpn-relay,cpvpn-flyexit", 8, Stdin(REQUEST),
                lambda argv, **kw: FakeProcess(argv, self.home / "chain", self.inventory, code=1),
            )  # fmt: skip
        self.assertEqual(code, 1)
        last = json.loads(out.getvalue().splitlines()[-1])
        self.assertEqual((last["event"], last["message"]), ("error", "last words"))
        # the whole output is kept, owner-only, without the progress events
        kept = Path(last["log"])
        self.assertEqual(kept.read_text(), "ssh: some noise\nlast words\n")
        self.assertEqual(os.stat(kept).st_mode & 0o777, 0o600)
        self.assertNotIn("bundle_base64", out.getvalue())

    def test_export_saves_only_a_request_shaped_file_into_documents(self):
        with mock.patch.object(desktop_setup, "documents_dir", return_value=self.home / "Docs"):
            out = desktop_setup.export(Stdin(REQUEST))
            path = Path(out["path"])
            self.assertEqual((path.parent, path.read_bytes()), (self.home / "Docs", REQUEST))
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(desktop_setup.Refused):
                desktop_setup.export(Stdin(b"#!/bin/sh\nid\n"))

    def test_build_needs_the_operator_vault(self):
        (self.vault / "credential.json").unlink()
        with self.assertRaises(desktop_setup.Refused) as e:
            desktop_setup.build("cpvpn-relay,cpvpn-flyexit", 8, Stdin(REQUEST), mock.Mock())
        self.assertEqual(str(e.exception), "no_operator_vault")

    def test_check_records_the_answer_without_touching_other_providers(self):
        self.signed_out.add("flashbots")
        with mock.patch.object(desktop_setup.providers, "readiness", return_value=(True, "default profile")):
            r = desktop_setup.check("aws")
        # The recorded relay's own profile decides, not the CLI's default profile.
        self.assertEqual((r["ready"], r["why"]), (False, "sign-in ran out for profile flashbots"))
        self.assertEqual(desktop_setup.state()["profile"]["checked"]["aws"]["ready"], False)
        r = desktop_setup.check("hetzner")
        self.assertTrue(r["ready"])
        with self.assertRaises(desktop_setup.Refused):
            desktop_setup.check("nope")

    def test_a_signed_out_route_stops_before_the_chain_and_names_the_server(self):
        self.signed_out.add("flashbots")
        run = mock.Mock()
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = desktop_setup.build("cpvpn-relay,cpvpn-flyexit", 8, Stdin(REQUEST), run)
        self.assertEqual(code, 1)
        run.assert_not_called()  # no PIN prompt, no server touched
        event = json.loads(out.getvalue().splitlines()[-1])
        self.assertEqual(
            (event["error"], event["server"], event["profile"]), ("signed_out", "cpvpn-relay", "flashbots")
        )
        self.assertEqual(self.asked[-1][-4:], ["--output", "json", "--region", "eu-north-1"])

    def test_sign_in_runs_the_browser_login_for_that_servers_profile_only(self):
        done = mock.Mock(return_value=mock.Mock(stdout="Updated profile flashbots", stderr=""))
        r = desktop_setup.sign_in("cpvpn-relay", run=done)
        argv, kw = done.call_args
        self.assertEqual(argv[0], ["/usr/bin/aws", "login", "--profile", "flashbots", "--region", "eu-north-1"])
        self.assertNotIn("--remote", argv[0])  # the local callback: nothing is pasted
        self.assertIs(kw["stdin"], desktop_setup.subprocess.DEVNULL)
        self.assertEqual((r["ready"], r["profile"]), (True, "flashbots"))
        self.signed_out.add("flashbots")
        failed = mock.Mock(return_value=mock.Mock(stdout="", stderr="Login was cancelled"))
        self.assertEqual(desktop_setup.sign_in("cpvpn-relay", run=failed)["why"], "Login was cancelled")
        for name, reason in (("cpvpn-flyexit", "sign_in_not_needed"), ("cpvpn-nope", "unknown_server"),
                             ("--remote", "unknown_server")):  # fmt: skip
            with self.assertRaises(desktop_setup.Refused) as e:
                desktop_setup.sign_in(name, run=done)
            self.assertEqual(str(e.exception), reason)

    def test_the_agreement_is_accepted_once_per_version_and_kept_private(self):
        v1, v2 = "a" * 64, "b" * 64
        self.assertFalse(desktop_setup.agreement_state(v1)["accepted"])  # first launch
        self.assertTrue(desktop_setup.agreement_accept(v1)["accepted"])
        self.assertTrue(desktop_setup.agreement_state(v1)["accepted"])
        path = desktop_setup.agreement_path()
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(set(json.loads(path.read_text())), {"schema", "version", "accepted_at"})
        # Edited documents have a new version, which asks again.
        self.assertFalse(desktop_setup.agreement_state(v2)["accepted"])
        path.write_text("not json")
        self.assertFalse(desktop_setup.agreement_state(v1)["accepted"])

    def test_the_agreement_takes_only_a_sha256_version(self):
        for bad in ("", "A" * 64, "a" * 63, "a" * 65, "../" + "a" * 61, "a" * 63 + "\n", None):
            for call in (desktop_setup.agreement_state, desktop_setup.agreement_accept):
                with self.assertRaises(desktop_setup.Refused):
                    call(bad)
        self.assertFalse(desktop_setup.agreement_path().exists())

    def test_the_agreement_command_answers_one_json_line(self):
        for argv, accepted in ((["agreement", "state", "c" * 64], False), (["agreement", "accept", "c" * 64], True),
                               (["agreement", "state", "c" * 64], True), (["agreement", "state", "d" * 64], False)):  # fmt: skip
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                self.assertEqual(desktop_setup.main(argv), 0)
            self.assertEqual(json.loads(out.getvalue()), dict(schema=1, accepted=accepted))
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            self.assertEqual(desktop_setup.main(["agreement", "accept", "x"]), 1)
        self.assertEqual(json.loads(out.getvalue())["error"], "invalid_agreement_version")


if __name__ == "__main__":
    unittest.main()

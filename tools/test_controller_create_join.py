"""Integration tests for the setup wizard's create/join write side
(tools/controller_create_join.py): the module's exact execution specs
against the real CLI's parser definitions, the backend wiring, and the
TypeScript controller contract.

The dynamic parser tests need cypherpunkctl (whose managed_profile import needs
the hash-locked environment's mldsa/mlkem); here they are skipped and the
source-contract tests below pin the same agreement statically, on the
real files.
"""

import re
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import controller_create_join as cj  # noqa: E402
import test_controller_create_join_units as units  # noqa: E402

REPO = TOOLS.parent
CYPHERPUNKCTL = (TOOLS / "cypherpunkctl.py").read_text()
BACKEND = (TOOLS / "controller_backend.py").read_text()
TYPES_TS = (REPO / "apps/cypherpunk-vpn/src/controller/types.ts").read_text()
CAPABILITY = (REPO / "apps/cypherpunk-vpn/src-tauri/permissions/controller-bridge.toml").read_text()

CREATE_ACTIONS = {"create_operator_keys", "request_exit", "sign_route"}


def _pq_crypto_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401

        import managed_profile  # noqa: F401

        return True
    except ImportError:
        return False


class CliContractTests(unittest.TestCase):
    """The three specs' verbs and flags exist in the real CLI, with the
    types and choices the module assumes."""

    def test_the_unlock_key_verb_exists_and_takes_the_operator_vault(self):
        self.assertIn('"unlock-key"', CYPHERPUNKCTL)
        self.assertIn('uk.add_argument("--vault"', CYPHERPUNKCTL)
        # the handler writes exactly the file check_operator reads
        self.assertIn('operator-unlock.pub" if a.vault', CYPHERPUNKCTL)
        self.assertEqual(cj.OPERATOR_UNLOCK, "operator-unlock.pub")

    def test_the_request_verb_supports_the_exit_role_under_operator_protection(self):
        self.assertIn('choices=["client", "relay", "middle", "exit"]', CYPHERPUNKCTL)
        self.assertIn('choices=["nitrokey", "systemd-creds", "operator", "none"]', CYPHERPUNKCTL)
        self.assertIn('rq.add_argument("--unlock-key", type=Path', CYPHERPUNKCTL)
        self.assertIn('"--out", type=Path, required=True', CYPHERPUNKCTL)

    def test_the_init_verb_matches_the_module_constants(self):
        self.assertIn('init = s.add_parser("init"', CYPHERPUNKCTL)
        # the 3-hop ceiling is the CLI's own choices list
        found = re.search(r'"--hops", type=int, choices=\[([^\]]+)\]', CYPHERPUNKCTL)
        self.assertIsNotNone(found, "the init parser must declare its hop choices")
        self.assertEqual([int(x) for x in found.group(1).split(",")], list(cj.HOPS))
        self.assertIn('"--allowance-gib", type=int', CYPHERPUNKCTL)
        self.assertIn('"--request", action="append", required=True', CYPHERPUNKCTL)
        self.assertIn('"--cover-name"', CYPHERPUNKCTL)
        # the cost gate: the CLI-informed acceptance exists but the GUI never emits it
        self.assertIn('"--accept-cost", action="store_true"', CYPHERPUNKCTL)

    def test_init_requires_a_hardware_signer_group(self):
        self.assertIn("add_mutually_exclusive_group(required=True)", CYPHERPUNKCTL)
        self.assertIn(
            '"--vault", type=Path, help="Nitrokey vault: hardware-signed operator (production)"', CYPHERPUNKCTL
        )
        self.assertIn(
            '"--software-operator", type=Path, help="LAB ONLY: plaintext operator keys in this directory"',
            CYPHERPUNKCTL,
        )

    def test_the_module_kem_length_is_keyguards_own(self):
        from keyguard import KEM_PUBLIC

        self.assertEqual(cj.KEM_PUBLIC_LEN, KEM_PUBLIC)


class BackendWiringTests(unittest.TestCase):
    """The broker's setup, preview and apply paths carry the two branches
    and the three new actions through to the module."""

    def test_getsetup_uses_the_branch_step_lists_and_action_surface(self):
        self.assertIn("controller_create_join.steps_for(branch)", BACKEND)
        self.assertIn("controller_create_join.decorate_report(branch, report, STATE, findings)", BACKEND)
        # the engine context carries the exit directory the checks read
        self.assertIn('exit=wizard["exit"]', BACKEND)

    def test_preview_and_apply_know_exactly_the_three_new_actions(self):
        guarded = re.findall(r'name in \(("create_operator_keys", "request_exit", "sign_route")\)', BACKEND)
        self.assertEqual(len(guarded), 2, "prepare() and execute() must both guard the same three actions")
        self.assertIn("controller_create_join.prepare(", BACKEND)
        self.assertIn("controller_create_join.apply(", BACKEND)

    def test_every_applied_action_is_journaled_after_success(self):
        self.assertIn("controller_create_join.journal_append(", BACKEND)

    def test_the_guarded_names_match_the_module_surface(self):
        offered = {a for actions in cj.CREATE_ACTIONS.values() for a in actions}
        self.assertEqual(offered, CREATE_ACTIONS)

    def test_the_rust_bridge_surface_is_unchanged(self):
        """The three actions ride the existing Preview/Apply pipe: no new
        bridge command, capability entry or TS client call is needed."""
        for command in ("preview_action", "apply_action", "get_setup"):
            self.assertIn(command, CAPABILITY)
        self.assertNotIn("create_operator_keys", CAPABILITY)
        self.assertNotIn("sign_route", CAPABILITY)


class TypesContractTests(unittest.TestCase):
    def test_the_typescript_action_union_carries_the_three_new_actions(self):
        for action in CREATE_ACTIONS:
            self.assertIn(f"'{action}'", TYPES_TS)
        self.assertIn("branch: 'create'", TYPES_TS)
        self.assertIn("allowance_gib: number", TYPES_TS)
        self.assertIn("hops: 1 | 2 | 3", TYPES_TS)

    def test_the_setup_branch_type_still_governs(self):
        self.assertIn("export type SetupBranch = 'create' | 'join'", TYPES_TS)


@unittest.skipUnless(_pq_crypto_available(), "cypherpunkctl needs the hash-locked environment (mldsa/mlkem)")
class RealParserTests(unittest.TestCase):
    """Every execution spec parses against the real cypherpunkctl parser."""

    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.where = cj.paths(Path(self.tmp.name))
        units.OperatorUnlockFixture(self.where["vault"])
        self.where["state"].mkdir(parents=True, exist_ok=True)
        (self.where["state"] / "device.req").write_bytes(b"client public request")
        self.where["exit"].mkdir(parents=True, exist_ok=True)
        (self.where["exit"] / "device.req").write_bytes(b"exit public request")

    def parsed(self, spec):
        import cypherpunkctl

        return cypherpunkctl.build_parser().parse_args(
            ["--state", spec["state"] or str(self.tmp), "--json", *spec["argv"]]
        )

    def test_the_unlock_key_spec_parses(self):
        spec = cj.apply("create", "create_operator_keys", None, self.where)
        args = self.parsed(spec)
        self.assertEqual(args.action, "unlock-key")
        self.assertEqual(str(args.vault), str(self.where["vault"]))

    def test_the_request_exit_spec_parses(self):
        spec = cj.apply("create", "request_exit", None, self.where)
        args = self.parsed(spec)
        self.assertEqual(args.action, "request")
        self.assertEqual(args.role, "exit")
        self.assertEqual(args.protect, "operator")
        self.assertEqual(str(args.unlock_key), str(self.where["vault"] / cj.OPERATOR_UNLOCK))
        self.assertEqual(str(args.out), str(self.where["exit"] / "device.req"))

    def test_the_sign_route_spec_parses(self):
        request = dict(
            hops=3,
            exit="198.51.100.4:443",
            relay="198.51.100.5:443",
            middle="198.51.100.6:443",
            cover_name="cdn.example.net",
            allowance_gib=900,
            extra_requests=[dict(role="relay", name="relay-a"), dict(role="middle", name="middle-a")],
        )
        (self.where["requests"]).mkdir(parents=True, exist_ok=True)
        for name in ("relay-a", "middle-a"):
            (self.where["requests"] / f"{name}.req").write_bytes(b"public request")
        spec = cj.apply("create", "sign_route", request, self.where)
        args = self.parsed(spec)
        self.assertEqual(args.action, "init")
        self.assertEqual(args.hops, 3)
        self.assertEqual(args.exit, "198.51.100.4:443")
        self.assertEqual(args.allowance_gib, 900)
        self.assertEqual(args.cover_name, "cdn.example.net")
        self.assertEqual(str(args.vault), str(self.where["vault"]))
        self.assertEqual(
            args.request,
            [
                f"client={self.where['state'] / 'device.req'}",
                f"relay={self.where['requests'] / 'relay-a.req'}",
                f"middle={self.where['requests'] / 'middle-a.req'}",
                f"exit={self.where['exit'] / 'device.req'}",
            ],
        )


if __name__ == "__main__":
    unittest.main()

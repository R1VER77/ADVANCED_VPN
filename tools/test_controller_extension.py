"""The GUI controller's observation commands (tools/controller_extension.py): the streaming
eligibility table, multi-hop presets and auto-connect policy cross to the GUI as bounded,
validated reads; SSIDs never do."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from controller_extension import (  # noqa: E402
    ExtensionError,
    MAX_TABLE_ROWS,
    SCHEMA,
    TOOLS,
    autoconnect_policy,
    dispatch_extension,
    multihop_presets,
    streaming_eligibility,
)  # noqa: E402


class StreamingEligibilityTests(unittest.TestCase):
    def test_payload_from_the_real_artifact(self):
        payload = streaming_eligibility()
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertIsInstance(payload["rows"], list)
        self.assertLessEqual(len(payload["rows"]), MAX_TABLE_ROWS)
        for row in payload["rows"]:
            self.assertIn(row["kind"], ("measured", "class-knowledge"))
            self.assertIn("result", row)

    def test_missing_table_is_an_honest_empty_not_an_error(self):
        with tempfile.TemporaryDirectory() as empty:
            payload = streaming_eligibility(Path(empty))
        self.assertEqual(payload["rows"], [])
        self.assertIn("stream-check", payload["note"])

    def test_corrupt_table_is_refused(self):
        with tempfile.TemporaryDirectory() as broken:
            (Path(broken) / "STREAMING_ELIGIBILITY.json").write_text("{not json")
            with self.assertRaises(ExtensionError):
                streaming_eligibility(Path(broken))


class MultihopPresetsTests(unittest.TestCase):
    def test_payload_lists_the_real_presets(self):
        payload = multihop_presets()
        names = {p["name"] for p in payload["presets"]}
        self.assertIn("always", names)
        self.assertIn("when-needed", names)
        self.assertIn("never", names)
        self.assertIn("streaming", names)
        self.assertEqual(payload["default"], "when-needed")
        self.assertEqual(payload["ceiling"], 3)

    def test_every_preset_carries_its_protection_label(self):
        for preset in multihop_presets()["presets"]:
            self.assertTrue(preset["label"], f"{preset['name']} needs a label")


class AutoconnectPolicyTests(unittest.TestCase):
    def test_absent_policy_is_disabled_fail_closed(self):
        payload = autoconnect_policy(policy=None)
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertFalse(payload["enabled"])

    def test_ssids_never_cross_the_boundary(self):
        secret = "home-network-ssid-xyz"  # noqa: S105 (an SSID, not a password)
        payload = autoconnect_policy(
            policy={
                "schema": 1,
                "enabled": True,
                "trusted": {"ssids": [secret], "wired": False},
            }
        )
        self.assertTrue(payload["enabled"])
        self.assertEqual(payload["trusted_ssids_count"], 1)
        self.assertNotIn(secret, json.dumps(payload))
        self.assertNotIn("ssid", json.dumps(payload).replace("ssids_count", ""))

    def test_emission_guard_fires_on_a_leak(self):
        # defense in depth: if a future edit leaks the SSID into the
        # payload, the emission itself raises
        leaked = {"schema": 1, "enabled": True, "trusted": {"ssids": ["very-secret-ssid"], "wired": False}}
        with unittest.mock.patch("json.dumps", return_value='{"x": "very-secret-ssid"}'):
            with self.assertRaises(ExtensionError):
                autoconnect_policy(policy=leaked)


class DispatchWiringTests(unittest.TestCase):
    def test_the_three_methods_dispatch(self):
        for method in ("GetStreamingEligibility", "GetMultihopPresets", "GetAutoconnectPolicy"):
            payload = dispatch_extension(method, None)
            self.assertIsInstance(payload, dict)
            self.assertEqual(payload["schema"], SCHEMA)

    def test_unknown_method_returns_none(self):
        self.assertIsNone(dispatch_extension("DoSomethingElse", None))

    def test_the_rust_bridge_and_capability_and_types_agree(self):
        """Cross-language consistency: every new command appears in the
        Rust invoke handler list, the capability allowlist, and the
        TypeScript controller - parsed from the real files."""
        lib = (TOOLS.parent / "apps/cypherpunk-vpn/src-tauri/src/lib.rs").read_text()
        capability = (TOOLS.parent / "apps/cypherpunk-vpn/src-tauri/permissions/controller-bridge.toml").read_text()
        real_ts = (TOOLS.parent / "apps/cypherpunk-vpn/src/controller/real.ts").read_text()
        types_ts = (TOOLS.parent / "apps/cypherpunk-vpn/src/controller/types.ts").read_text()
        backend = (TOOLS / "controller_backend.py").read_text()
        for method, command in (
            ("GetStreamingEligibility", "streaming_eligibility"),
            ("GetMultihopPresets", "multihop_presets"),
            ("GetAutoconnectPolicy", "autoconnect_policy"),
        ):
            with self.subTest(method=method):
                self.assertIn(method, backend, "backend dispatch knows the method")
                self.assertIn(f"async fn {command}", lib, "Rust command exists")
                self.assertIn(command, capability, "capability allowlists the command")
                self.assertIn(command, real_ts, "TS controller calls the command")
                self.assertIn(method.replace("Get", ""), types_ts, "TS types name the payload")

    def test_the_gui_extension_is_observe_only(self):
        """The discipline: the three new commands take no user input and
        touch no plan/operation surface. The Rust side must not accept
        arguments; the backend handlers must not mutate state."""
        lib = (TOOLS.parent / "apps/cypherpunk-vpn/src-tauri/src/lib.rs").read_text()
        for command in ("streaming_eligibility", "multihop_presets", "autoconnect_policy"):
            start = lib.index(f"async fn {command}")
            body = lib[start : lib.index("}", start)]
            self.assertNotIn("request", body, f"{command} must take no request argument")
            self.assertNotIn("apply", body.lower().replace("apply_action", ""))


if __name__ == "__main__":
    unittest.main()

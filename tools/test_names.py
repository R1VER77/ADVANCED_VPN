#!/usr/bin/env python3
"""Naming gate (D019): no legacy `advanced-vpn`, `advanced_vpn`, `ADVANCED_VPN`, `avpn`
or `AVPN` identifier may appear anywhere outside the historical allowlist and the
one-time legacy adoption/cleanup hooks."""

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = re.compile(
    r"advanced-vpn|advanced_vpn|ADVANCED_VPN|ADVANCED VPN|Advanced VPN|\bavpn\b|\bAVPN\b|\bavpn[-_:/0-9]|\bAVPN[-_:/0-9]|\.avpn\b"
)

# Historical records that intentionally preserve the pre-v0.11.0 name as history.
HISTORICAL_FILES = {
    "docs/INCIDENTS.md",
    "docs/NAME_MIGRATION.md",
    "tools/test_names.py",
}

# Generated current-tree evidence files that must NOT contain old names.
CURRENT_EVIDENCE = {
    "docs/evidence/INTERFACE_INVENTORY.json",
    "docs/evidence/SECRET_REVIEW.json",
}

# One-time legacy migration/cleanup hooks (exact function or section scopes).
LEGACY_LINE_SUBSTRINGS = {
    "tools/cloud.py": (
        "/opt/advanced-vpn",
        "/etc/advanced-vpn",
        "advanced-vpn",
        "advanced_vpn",
        "/usr/local/bin/avpn",
        "avpn-",
    ),
    "tools/test_cloud.py": (
        "advanced-vpn",
        "advanced_vpn_egress",
        "avpn-relay",
        "avpn-flyexit",
        "avpn-ociexit",
        "avpn-bastion",
    ),
    "tools/native_package.py": (
        "/opt/advanced-vpn",
        "/usr/bin/avpn",
        "advanced-vpn*.service",
        'LEGACY_UNITS = ("advanced-vpn.service", "advanced-vpn-guard.service")',
        'LEGACY_TABLE = "inet advanced_vpn"',
    ),
    "tools/test_native_package.py": ("/usr/bin/avpn", "advanced-vpn.service"),
    # Checks, in a guest, that the pre-rename install is gone after an upgrade.
    "tools/upgrade_vm_test.py": ("/opt/advanced-vpn", "advanced-vpn*.service", "/usr/bin/avpn", "grep -c advanced-vpn"),
    "docs/cli/cloud.md": (
        "~/.config/advanced-vpn",
        "`avpn-*`",
    ),
}


def find_violations(root: Path = ROOT) -> list[str]:
    """Return `file:line: match` for any forbidden old name outside the allowlist."""
    files = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
    violations = []
    for rel in files:
        if rel in HISTORICAL_FILES:
            continue
        if rel.startswith("docs/evidence/") and rel not in CURRENT_EVIDENCE:
            continue
        path = root / rel
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raw = path.read_bytes()
            if FORBIDDEN.search(raw.decode("latin1")):
                violations.append(f"{rel}:binary")
            continue
        if rel == "CHANGELOG.md":
            # Only entries before v0.11.0 (from ## v0.10.2 downward) are history.
            marker = "\n## v0.10.2"
            text = text[: text.index(marker)] if marker in text else text
        elif rel == "docs/DECISIONS.md":
            # Decisions D001-D018 are history; D019+ must not reintroduce old names.
            marker = "| D019 /"
            text = text[text.index(marker) :] if marker in text else ""
            # D019 itself mentions NAME_MIGRATION.md and test_names.py, not old identifiers.
        allowed_subs = LEGACY_LINE_SUBSTRINGS.get(rel, ())
        for lineno, line in enumerate(text.splitlines(), 1):
            if FORBIDDEN.search(line):
                if allowed_subs and any(sub in line for sub in allowed_subs):
                    continue
                violations.append(f"{rel}:{lineno}: {line.strip()[:120]}")
    return violations


class NameMigrationGate(unittest.TestCase):
    def test_no_old_names_outside_history(self):
        violations = find_violations()
        self.assertEqual(violations, [], "Old identifiers found:\n" + "\n".join(violations[:50]))

    def test_gate_catches_each_forbidden_token(self):
        for token in (
            "advanced-vpn",
            "advanced_vpn",
            "ADVANCED_VPN",
            "avpn",
            "AVPN",
            "avpn-relay",
            "AVPN_CLOUD",
            "client.avpn",
        ):
            self.assertIsNotNone(FORBIDDEN.search(token), token)


if __name__ == "__main__":
    unittest.main()

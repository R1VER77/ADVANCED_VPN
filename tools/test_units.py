"""The installed systemd units stay sandboxed: `systemd-analyze security --offline`
scores each unit file, and a unit whose exposure rises above its ceiling fails. The
ceilings are what the units reach today (guard 1.8, supervisor 5.5); loosening a unit
must be a deliberate change here, never a side effect."""

import re
import shutil
import subprocess
import unittest
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"

# Unit file -> highest exposure allowed (systemd's 0-10 scale, lower is safer).
CEILINGS = {
    "cypherpunk-vpn-guard.service": 2.5,
    "cypherpunk-vpn.service": 6.0,
}


# Every protection the guard depends on, by name: the score alone moves little when one
# is dropped, and differs a little between systemd versions.
GUARD_SANDBOX = [
    "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
    "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes", "ProtectProc=invisible",
    "ProcSubset=pid", "RestrictAddressFamilies=AF_NETLINK AF_UNIX", "RestrictNamespaces=yes",
    "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native", "SystemCallFilter=@system-service", "NoNewPrivileges=yes",
]  # fmt: skip
SUPERVISOR_SANDBOX = [
    "NoNewPrivileges=yes", "RestrictNamespaces=net mnt", "RestrictSUIDSGID=yes", "RestrictRealtime=yes",
    "LockPersonality=yes", "SystemCallArchitectures=native", "ProtectHostname=yes", "KeyringMode=private",
    "SystemCallFilter=~@clock @cpu-emulation @debug @module @obsolete @raw-io @reboot @swap",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
]  # fmt: skip


def exposure(unit):
    """systemd's overall exposure score for one unit file, read without installing it."""
    r = subprocess.run(
        ["systemd-analyze", "security", "--offline=yes", str(unit)],
        capture_output=True,
        text=True,
        check=False,
    )
    m = re.search(r"exposure level for \S+: ([0-9.]+)", r.stdout)
    if not m:
        raise AssertionError("no exposure score for %s:\n%s\n%s" % (unit.name, r.stdout[-2000:], r.stderr[-2000:]))
    return float(m.group(1))


def scores_offline():
    """Whether this systemd-analyze can score a unit file offline (`--offline` is systemd
    250+; Ubuntu 22.04 ships 249, which still runs the units unchanged)."""
    if not shutil.which("systemd-analyze"):
        return False
    out = subprocess.run(["systemd-analyze", "--version"], capture_output=True, text=True, check=False).stdout
    m = re.match(r"systemd (\d+)", out)
    return bool(m) and int(m.group(1)) >= 250


@unittest.skipUnless(scores_offline(), "needs systemd-analyze 250+ (security --offline)")
class UnitSandboxTests(unittest.TestCase):
    def test_every_installed_unit_stays_under_its_exposure_ceiling(self):
        for name, ceiling in CEILINGS.items():
            score = exposure(DEPLOY / name)
            self.assertLessEqual(score, ceiling, "%s exposure %.1f > %.1f" % (name, score, ceiling))

    def test_the_guard_keeps_only_the_capability_it_needs(self):
        text = (DEPLOY / "cypherpunk-vpn-guard.service").read_text()
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN\n", text)
        for line in GUARD_SANDBOX:
            self.assertIn(line + "\n", text)

    def test_the_supervisor_keeps_every_limit_it_can_have(self):
        text = (DEPLOY / "cypherpunk-vpn.service").read_text()
        for line in SUPERVISOR_SANDBOX:
            self.assertIn(line + "\n", text)


class NamespaceEntryTests(unittest.TestCase):
    def test_every_setns_names_the_namespace_type(self):
        # systemd's RestrictNamespaces= cannot tell what setns(fd, 0) enters, so it refuses
        # it: the installed client supervisor then stopped with PermissionError on a real
        # systemd host (KVM validation). Naming the type is also stricter: the kernel
        # rejects a descriptor of any other kind.
        import re as _re

        tools = Path(__file__).resolve().parent
        offenders = []
        for f in sorted(tools.glob("*.py")):
            for n, line in enumerate(f.read_text().splitlines(), 1):
                if not line.lstrip().startswith("#") and _re.search(r"\bsetns\([^)]*,\s*0\s*\)", line):
                    offenders.append("%s:%d" % (f.name, n))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

"""Shared acceptance cases for the Python checks and the native bootstrap engine."""

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import preflight as pf
from test_preflight import Sim


class SharedPolicyFixtures(unittest.TestCase):
    def test_host_findings_match_shared_acceptance_cases(self):
        fixture = json.loads(Path(__file__).with_name("preflight-fixtures.json").read_text())
        self.assertEqual(fixture["schema"], 1)
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                facts = {**fixture["base"], **case["set"]}
                sim = Sim()
                try:
                    sim.write(
                        "etc/os-release",
                        'ID=%s\nVERSION_ID=%s\nID_LIKE="%s"\n'
                        % (facts["os_id"], facts["os_version"], " ".join(facts["os_like"])),
                    )
                    sim.kw["machine"] = facts["machine"]
                    sim.kw["glibc"] = "glibc %d.%d" % tuple(facts["glibc"]) if facts["glibc"] else ""
                    sim.kw["free_mb"] = lambda _, n=facts["free_mb"] - facts["package_mb"]: n
                    if not facts["tun"]:
                        sim.remove("dev/net/tun")
                    for program in pf.PROGRAMS:
                        if program not in facts["programs"]:
                            sim.remove("usr/bin/" + program)
                    if not facts["nf_tables"]:
                        sim.remove("sys/module/nf_tables")
                    if not facts["seccomp"]:
                        sim.write("proc/self/status", "Name:\tpreflight\n")
                    if not facts["landlock"]:
                        sim.write("sys/kernel/security/lsm", "capability")
                    sim.systemd = "systemd %s" % facts["systemd"] if facts["systemd"] else "unavailable"
                    for name in facts["vpn_interfaces"]:
                        (sim.root / "sys/class/net" / name).mkdir()
                    options = case.get("options", {})
                    opts = SimpleNamespace(
                        operator_only=options.get("operator_only", False),
                        protect="systemd-creds" if options.get("systemd_creds") else None,
                    )
                    # Host-Python readiness is intentionally outside a bootstrap
                    # that runs before a verified bundled interpreter is started.
                    checks = (
                        [pf.check_os, pf.check_arch, pf.check_glibc, pf.check_space]
                        if opts.operator_only
                        else [c for c in pf.CHECKS if c != pf.check_python]
                    )
                    with mock.patch.object(pf, "glibc_need", return_value=tuple(facts["glibc_need"])):
                        actual = pf.run_checks(sim.host(), opts, checks)
                    actual = sorted([f.code, f.severity] for f in actual)
                    expected = sorted(
                        [row for row in fixture["baseline"] if row[0] not in case["remove"]] + case["add"]
                    )
                    self.assertEqual(actual, expected)
                finally:
                    sim.tmp.cleanup()

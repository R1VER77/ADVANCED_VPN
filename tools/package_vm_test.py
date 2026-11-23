#!/usr/bin/env python3
"""Validate a native candidate's lifecycle in a disposable local KVM guest.

The guest alone installs/removes packages and arms/disarms test protection. No host
network change, hardware forwarding, paid resource or real enrollment is involved.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

import bootguard_vm as guard
import vm_validation as vm

UNITS = ("cypherpunk-vpn.service", "cypherpunk-vpn-guard.service", "cypherpunk-vpn-controller.service")
PACKAGE_ENV = {"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
RPM_ADMIN_HOOK = "/usr/libexec/qemu-ga/fsfreeze-hook.d/cypherpunk-validation-exec"


class RpmAdministrationAgent(vm.Agent):
    """VM-only trusted administration context; product services retain their labels."""

    def run(self, argv, **kwargs):
        """Use Fedora/RHEL's explicit QGA hook transition, never permissive mode."""
        kwargs["env"] = dict(PACKAGE_ENV, **(kwargs.get("env") or {}))
        return super().run([RPM_ADMIN_HOOK, *argv], **kwargs)

    def hook_context(self):
        """Record the explicit administration transport's policy transition."""
        return super().run([RPM_ADMIN_HOOK, "/usr/bin/id", "-Z"])[1].strip()


def wait_administration_hook(work):
    """Cloud-init prepares the hook before any confined QGA exec is attempted."""
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        with (work / "client-console.log").open("rb") as console:
            console.seek(0, os.SEEK_END)
            console.seek(max(0, console.tell() - (1 << 20)))
            if b"CYPHERPUNK_VALIDATION_ADMIN_READY" in console.read():
                return
        time.sleep(1)
    raise TimeoutError("RPM test administration hook did not become ready; preserve console")


def rpm_version_checks(agent, work):
    """Exercise native RPM EVR logic in the guest; this does not qualify an RPM distro."""
    code, out, err = agent.run(
        ["/usr/bin/apt-get", "install", "-y", "rpm"],
        timeout=360,
        check=False,
        env=PACKAGE_ENV,
    )
    (work / "rpm-dependencies.log").write_text(out + err)
    if code:
        raise RuntimeError("guest RPM compatibility dependencies failed")
    script = """import json,os,subprocess,sys
sys.path.insert(0,"/opt/cypherpunk-vpn/current/tools")
import native_package
cases=[("0\\t1.2.4\\t1","newer"),("1\\t1.0.0\\t1","newer"),
       ("0\\t1.2.3\\t2","newer"),("0\\t1.2.3\\t1","allowed"),
       ("0\\t1.2.3~rc1\\t1","allowed"),("0\\t1.2.2\\t999","allowed"),
       ("0\\t1.2.3^git1\\t1","newer"),("0\\t1.2.10\\t1","newer"),
       ("0\\t1.2\\t999","allowed"),("unparseable","invalid"),("","invalid"),
       ("0\\t1.2.2\\t1\\n1\\t1.0\\t1","newer")]
for installed,expected in cases:
 result=subprocess.run(["/usr/bin/rpm","--eval",native_package.rpm_compare_expression()],
  env=dict(os.environ,CYPHERPUNK_RPM_INSTALLED=installed,CYPHERPUNK_RPM_TARGET="1.2.3"),
  check=True,capture_output=True,text=True,timeout=10)
 if result.stdout.strip()!=expected:raise RuntimeError(repr((installed,expected,result.stdout,result.stderr)))
print(json.dumps(dict(status="passed_native_rpm_evr",cases=len(cases))))
"""
    code, out, err = agent.run(
        ["/opt/cypherpunk-vpn/current/venv/bin/python3", "-B", "-E", "-s", "-c", script], timeout=120, check=False
    )
    (work / "rpm-evr.log").write_text(out + err)
    if code:
        raise RuntimeError("native RPM EVR compatibility checks failed")
    return json.loads(out)


def controller_checks(agent, work):
    """Actual bus/worker tests with an explicit disposable Polkit authorization fixture."""
    program = "/usr/local/libexec/cypherpunk-bus-validation"
    agent.run(["/usr/bin/install", "-D", "-m", "0755", "/mnt/cypherpunk-package/bus-validation", program])
    guard.put(agent, "/run/cypherpunk-controller-validation.fixture", b"disposable-controller-test-v1\n")
    version = agent.run(["/usr/bin/pkaction", "--version"])[1].strip()
    match = re.fullmatch(r"pkaction version (\d+)(?:\.(\d+))?(?:\.\d+)?", version)
    if not match:
        raise RuntimeError("unrecognized guest Polkit version")
    legacy = tuple(int(value or 0) for value in match.groups()) < (0, 106)
    rule = (
        "/etc/polkit-1/localauthority/50-local.d/cypherpunk-disposable-validation.pkla"
        if legacy
        else "/etc/polkit-1/rules.d/00-cypherpunk-disposable-validation.rules"
    )
    try:
        agent.run(["systemctl", "start", "cypherpunk-vpn-controller.service"])
        code, out, err = agent.run(["/usr/sbin/runuser", "-u", "tester", "--", program, "denied"], check=False)
        (work / "controller-denied.log").write_text(out + err)
        if code or json.loads(out).get("status") != "denied_as_expected":
            raise RuntimeError("default inactive-user authorization test failed")
        guard.put(
            agent,
            rule,
            b"""[Disposable cypherpunk controller validation only]
Identity=unix-user:tester
Action=org.cypherpunk_vpn.observe;org.cypherpunk_vpn.manage
ResultAny=yes
ResultInactive=yes
ResultActive=yes
"""
            if legacy
            else b"""// Only in this disposable validation VM. Not a production policy.
polkit.addRule(function(action, subject) {
 if (subject.user == "tester" &&
     (action.id == "org.cypherpunk_vpn.observe" || action.id == "org.cypherpunk_vpn.manage")) {
  return polkit.Result.YES;
 }
});
""",
        )
        agent.run(["systemctl", "restart", "polkit.service"])
        code, out, err = agent.run(["/usr/sbin/runuser", "-u", "tester", "--", program], check=False, timeout=90)
        (work / "controller-boundary.log").write_text(out + err)
        if code or json.loads(out).get("status") != "passed_bus_boundary_with_test_authorization":
            for filename, command in (
                (
                    "controller-journal.log",
                    ["/usr/bin/journalctl", "-b", "--no-pager", "-n", "120", "-u", "cypherpunk-vpn-controller.service"],
                ),
                ("controller-audit.log", ["/usr/bin/tail", "-n", "160", "/var/log/audit/audit.log"]),
                ("controller-contexts.log", ["/bin/ps", "-eZ"]),
            ):
                _, out, err = agent.run(command, timeout=20, check=False)
                (work / filename).write_text(out + err)
            raise RuntimeError("controller live-bus boundary test failed")
        return dict(
            status="passed_with_test_authorization",
            polkit_version=version,
            authorization_fixture="legacy_pkla" if legacy else "javascript_rule",
            native_authentication_agent_qualified=False,
        )
    finally:
        agent.run(["/usr/bin/rm", "-f", rule, program, "/run/cypherpunk-controller-validation.fixture"])
        agent.run(["systemctl", "restart", "polkit.service"])
        agent.run(["systemctl", "stop", "cypherpunk-vpn-controller.service"])


def units(agent):
    """Record service state; package installation must never activate a tunnel."""
    return {
        name: dict(
            active=agent.run(["systemctl", "is-active", name], check=False)[1].strip(),
            enabled=agent.run(["systemctl", "is-enabled", name], check=False)[1].strip(),
        )
        for name in UNITS
    }


def probe(agent, work, expected):
    """Require an out-of-band external witness, not just a failed application call."""
    start = guard.cursor(work / "client-wan.pcap")
    agent.run(
        [
            "/usr/sbin/runuser",
            "-u",
            "tester",
            "--",
            "/usr/bin/python3",
            "-c",
            "import socket,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "for _ in range(5):\n"
            ' try:s.sendto(b"CYPHERPUNK_BOOTGUARD_VALIDATION_20261117",("10.0.2.2",39091))\n'
            " except OSError:pass\n"
            " time.sleep(.1)\n",
        ]
    )
    time.sleep(1)
    observed = guard.markers(work / "client-wan.pcap", start, guard.cursor(work / "client-wan.pcap"))
    if (observed > 0) != expected:
        raise RuntimeError("external probe witness contradicted the expected guard state")
    return dict(attempts=5, external_marker_frames=observed)


def prepare_dependencies(agent, work, os_release, family="deb"):
    """Download only system prerequisites before the networkless lifecycle phases."""
    legacy = "ID=ubuntu\n" in os_release and 'VERSION_ID="22.04"' in os_release
    packages = [
        "libc6",
        "libgcc-s1",
        "systemd",
        "nftables",
        "iproute2",
        "mount",
        "passwd",
        "dbus",
        "policykit-1" if legacy else "polkitd",
    ]
    command = ["/usr/bin/apt-get", "install", "-y", "--no-install-recommends", *packages]
    if family == "rpm":
        command = [
            "/usr/bin/dnf",
            "install",
            "-y",
            "glibc",
            "libgcc",
            "systemd",
            "nftables",
            "iproute",
            "util-linux",
            "shadow-utils",
            "dbus",
            "polkit",
            "policycoreutils",
            "python3",
        ]
    code, out, err = agent.run(
        package_command(command, family),
        timeout=900,
        check=False,
        env=PACKAGE_ENV,
    )
    (work / "dependencies.log").write_text(out + err)
    if code:
        raise RuntimeError("guest system dependency preparation failed")


def install_candidate(agent, package, family="deb"):
    """Unix sockets remain available; no external interface or download is available."""
    # dpkg installs/replaces the explicitly opened local archive without apt's
    # --no-download local-filename handling. Dependencies were prepared above.
    command = ["/usr/bin/unshare", "--net", "--", "/usr/bin/dpkg", "--install"]
    if family == "rpm":
        command = ["/usr/bin/unshare", "--net", "--", "/usr/bin/rpm", "--upgrade", "--replacepkgs"]
    return agent.run(package_command([*command, package], family), timeout=600, check=False, env=PACKAGE_ENV)


def package_command(command, family):
    """RPM scriptlets need normal root-service context, rather than QGA's domain."""
    if family != "rpm":
        return command
    return [
        "/usr/bin/systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        *("--setenv=" + key + "=" + value for key, value in PACKAGE_ENV.items()),
        "--",
        *command,
    ]


def test_public_key(path, fingerprint):
    """Pin one supplied public test key without using the host keyring."""
    if not re.fullmatch(r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", fingerprint or ""):
        raise ValueError("a full RPM test-key fingerprint is required")
    if not 0 < path.stat().st_size <= 65536:
        raise ValueError("RPM test public key exceeds the bound")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-rpm-public-") as home:
        value = subprocess.run(
            ["/usr/bin/gpg", "--no-options", "--batch", "--homedir", home, "--with-colons", "--show-keys", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.splitlines()
    if sum(line.startswith("pub:") for line in value) != 1:
        raise ValueError("expected one RPM public test key")
    actual = next(line.split(":")[9] for line in value if line.startswith("fpr:"))
    if actual != fingerprint.upper():
        raise ValueError("RPM public test key does not match its fingerprint")
    return actual


def run(
    base,
    package,
    work,
    keep=False,
    controller_client=None,
    downgrade_package=None,
    rpm_checks=False,
    family="deb",
    rpm_public_key=None,
    rpm_fingerprint=None,
):
    """Preserve evidence and remove only the owned stopped guest's disposable disks."""
    if os.geteuid() == 0 or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("use the ordinary user's Linux system Python with pidfd support")
    if family not in ("deb", "rpm") or package.suffix != "." + family:
        raise ValueError("package archive does not match the selected family")
    if family == "rpm" and rpm_checks:
        raise ValueError("--rpm-checks is a Debian-guest compatibility trial, not an RPM lifecycle option")
    if family == "rpm" and not rpm_public_key:
        raise ValueError("RPM lifecycle requires a signed candidate and an explicit pinned test public key")
    if rpm_public_key:
        if family != "rpm":
            raise ValueError("RPM public key belongs only to a disposable RPM trial")
        rpm_fingerprint = test_public_key(rpm_public_key, rpm_fingerprint)
    work.mkdir(mode=0o700, exist_ok=False)
    result = dict(
        schema=1,
        status="running",
        scope="local_native_" + family + "_lifecycle_only",
        started=time.time(),
        base_sha256=guard.vm_hash(base),
        package_sha256=guard.vm_hash(package),
        harness_sha256=guard.vm_hash(Path(__file__)),
        controller_client_sha256=guard.vm_hash(controller_client) if controller_client else None,
        downgrade_package_sha256=guard.vm_hash(downgrade_package) if downgrade_package else None,
        phases={},
    )
    if rpm_public_key:
        result["test_signing_key"] = dict(
            fingerprint=rpm_fingerprint,
            sha256=guard.vm_hash(rpm_public_key),
            scope="explicit_testing_key_import_in_this_guest_only_not_production_signing",
        )
    started = False
    try:
        payload = work / "pkg"
        payload.mkdir(mode=0o755)
        shutil.copy2(package, payload / ("candidate." + family))
        if controller_client:
            shutil.copy2(controller_client, payload / "bus-validation")
        if downgrade_package:
            shutil.copy2(downgrade_package, payload / ("downgrade." + family))
        if rpm_public_key:
            shutil.copy2(rpm_public_key, payload / "validation-rpm-public-key.asc")
        subprocess.run(
            [
                "/usr/sbin/mke2fs",
                "-q",
                "-t",
                "ext4",
                "-L",
                "cpvpnpkg",
                "-d",
                str(payload),
                str(work / "pkg.img"),
                "256M",
            ],
            check=True,
            timeout=30,
        )
        vm.seed(
            work,
            "client",
            minimal_indexes=family == "deb",
            packages=["qemu-guest-agent", "nftables", "python3", "iproute", "curl", "policycoreutils"]
            if family == "rpm"
            else None,
            administration_hook=family == "rpm",
        )
        vm.start(work, base, "client")
        started = True
        agent = (RpmAdministrationAgent if family == "rpm" else vm.Agent)(work / "client-qga.sock")
        vm.wait_agent(agent, 900, "native package")
        if family == "rpm":
            wait_administration_hook(work)
        code, out, err = agent.run(["/usr/bin/cloud-init", "status", "--wait"], timeout=360, check=False)
        (work / "bootstrap-status.log").write_text(out + err)
        if code:
            _, out, err = agent.run(["/usr/bin/cloud-init", "schema", "--system"], timeout=30, check=False)
            (work / "bootstrap-schema.log").write_text(out + err)
            raise RuntimeError("guest bootstrap reported errors; see bootstrap status/schema logs")
        agent.sh("mkdir -p /mnt/cypherpunk-package && mount -o ro /dev/vdc /mnt/cypherpunk-package")
        result["os_release"] = agent.run(["/bin/cat", "/etc/os-release"])[1]
        if family == "rpm":
            enforcement = agent.run(["/bin/cat", "/sys/fs/selinux/enforce"])[1].strip()
            if enforcement != "1":
                raise RuntimeError("RPM qualification requires the publisher image's SELinux enforcing policy")
            result["selinux_enforcing"] = True
            context = agent.hook_context()
            if context.split(":")[2:3] != ["virt_qemu_ga_unconfined_t"]:
                raise RuntimeError("unexpected RPM administration-hook SELinux context")
            result["administration_fixture"] = dict(
                hook=RPM_ADMIN_HOOK,
                context=context,
                virt_qemu_ga_run_unconfined=True,
                scope="trusted_vm_administration_only_not_a_product_policy",
                commands="trusted_guest_agent_hook_with_fixed_system_environment",
                package_administration="transient_root_systemd_services_product_units_unchanged",
            )
            for name, command in (
                ("administration-agent-unit.log", ["/usr/bin/systemctl", "cat", "qemu-guest-agent.service"]),
                ("administration-context.log", ["/bin/cat", "/proc/self/status"]),
            ):
                _, out, err = agent.run(command, check=False)
                (work / name).write_text(out + err)
        prepare_dependencies(agent, work, result["os_release"], family)
        result["phases"]["dependency_preparation"] = dict(
            status="passed", networkless_install_phases=True, package_downloads_disabled=True
        )
        guest_package = "/mnt/cypherpunk-package/candidate." + family
        if rpm_public_key:
            agent.run(
                package_command(
                    ["/usr/bin/rpm", "--import", "/mnt/cypherpunk-package/validation-rpm-public-key.asc"], family
                )
            )
            code, out, err = agent.run(
                package_command(["/usr/bin/rpm", "--checksig", "--verbose", guest_package], family), check=False
            )
            (work / "package-signature.log").write_text(out + err)
            if code or not re.search(r"signature[^\n]*: OK", out, re.IGNORECASE):
                raise RuntimeError("RPM candidate signature did not verify with the declared test key")
            result["phases"]["package_signature"] = dict(status="verified", production_key_qualified=False)
        code, out, err = install_candidate(agent, guest_package, family)
        (work / "install.log").write_text(out + err)
        if code:
            raise RuntimeError("native installation failed; see install.log")
        first = agent.run(["/usr/bin/readlink", "/opt/cypherpunk-vpn/current"])[1].strip()
        state = units(agent)
        if any(row["active"] == "active" or row["enabled"] == "enabled" for row in state.values()):
            raise RuntimeError("installation activated a controller or guard")
        versions = {name: agent.run(["/usr/bin/" + name, "--version"])[1].strip() for name in ("cypherpunk",)}
        if not versions["cypherpunk"].startswith("cypherpunk "):
            raise RuntimeError("installed command failed its version check")
        guard.put(agent, "/etc/cypherpunk-vpn/validation-private/monotonic-floor", b"9001\n", "0600")
        result["phases"]["install"] = dict(slot=first, units=state, versions=versions)
        if downgrade_package:
            # dpkg -i bypasses apt's no-downgrade policy; the package's own
            # preinst must refuse before anything is unpacked.
            command = ["/usr/bin/dpkg", "-i", "/mnt/cypherpunk-package/downgrade.deb"]
            if family == "rpm":
                command = ["/usr/bin/rpm", "--upgrade", "--oldpackage", "/mnt/cypherpunk-package/downgrade.rpm"]
            code, out, err = agent.run(package_command(command, family), check=False, timeout=360)
            (work / "downgrade.log").write_text(out + err)
            if not code:
                raise RuntimeError("package downgrade was not refused; see downgrade.log")
            if "Refusing package downgrade" not in (out + err):
                raise RuntimeError("downgrade refusal did not come from the package guard")
            if agent.run(["/usr/bin/readlink", "/opt/cypherpunk-vpn/current"])[1].strip() != first:
                raise RuntimeError("refused downgrade changed the selected slot")
            query = ["/usr/bin/dpkg-query", "-W", "-f", "${Version}", "cypherpunk-vpn"]
            if family == "rpm":
                query = ["/usr/bin/rpm", "--query", "--queryformat", "%{VERSION}-%{RELEASE}", "cypherpunk-vpn"]
            installed = agent.run(package_command(query, family))[1].strip()
            result["phases"]["downgrade_refused"] = dict(
                exit_code=code, slot_unchanged=True, installed_version=installed
            )
        code, out, err = install_candidate(agent, guest_package, family)
        (work / "upgrade.log").write_text(out + err)
        if code:
            raise RuntimeError("native replacement failed; see upgrade.log")
        second = agent.run(["/usr/bin/readlink", "/opt/cypherpunk-vpn/current"])[1].strip()
        if first == second:
            raise RuntimeError("replacement did not select a new slot")
        agent.run(["/usr/bin/test", "-f", "/opt/cypherpunk-vpn/" + first + "/bin/cypherpunk"])
        result["phases"]["replace"] = dict(slot=second, previous_retained=True)
        # Damage only replaceable code; the authenticated package payload is intact.
        agent.sh("printf '\\n# injected VM corruption\\n' >> /opt/cypherpunk-vpn/current/tools/controller_status.py")
        code, out, err = install_candidate(agent, guest_package, family)
        (work / "repair.log").write_text(out + err)
        if code:
            raise RuntimeError("damaged-slot repair failed; see repair.log")
        receipt = json.loads(agent.run(["/bin/cat", "/opt/cypherpunk-vpn/TRANSACTION.json"])[1])
        if receipt.get("unusable_previous") != second.split("/", 1)[1] or receipt.get("phase") != "committed":
            raise RuntimeError("repair did not record damaged-slot exclusion")
        result["phases"]["damaged_slot_repair"] = receipt
        if rpm_checks:
            result["phases"]["rpm_evr_compatibility"] = rpm_version_checks(agent, work)
        boot = guard.reboot(agent, work)
        agent.sh("mkdir -p /mnt/cypherpunk-package && mount -o ro /dev/vdc /mnt/cypherpunk-package")
        state = units(agent)
        if any(row["active"] == "active" for row in state.values()):
            raise RuntimeError("unactivated package started a service after reboot")
        result["phases"]["reboot_without_activation"] = dict(boot_id=boot, units=state)
        if controller_client:
            result["phases"]["controller_boundary"] = controller_checks(agent, work)
        result["phases"]["positive_control"] = probe(agent, work, True)
        interpreter = "/opt/cypherpunk-vpn/current/venv/bin/python3"
        tools = "/opt/cypherpunk-vpn/current/tools"
        prefix = "import sys; sys.path.insert(0," + repr(tools) + "); import guard_policy; "
        agent.run([interpreter, "-B", "-E", "-s", "-c", prefix + "guard_policy.arm(apply=True)"])
        removal = (
            ["/usr/bin/dpkg", "--remove", "cypherpunk-vpn"]
            if family == "deb"
            else ["/usr/bin/rpm", "--erase", "cypherpunk-vpn"]
        )
        code, out, err = agent.run(package_command(removal, family), check=False, timeout=600)
        (work / "guarded-removal.log").write_text(out + err)
        if not code:
            raise RuntimeError("removal succeeded while persistent protection was armed")
        agent.run(["/usr/bin/test", "-x", "/usr/libexec/cypherpunk-vpn-bootguard"])
        agent.run(["/usr/bin/test", "-x", "/opt/cypherpunk-vpn/bin/cypherpunk"])
        result["phases"]["guarded_removal_refused"] = dict(exit_code=code, **probe(agent, work, False))
        # This is the trial's explicit cleanup approval, inside the disposable VM.
        agent.run([interpreter, "-B", "-E", "-s", "-c", prefix + "guard_policy.disarm()"])
        agent.run(["/usr/sbin/nft", "delete", "table", "inet", "cypherpunk_vpn"])
        agent.run(["systemctl", "stop", "cypherpunk-vpn-guard.service", "cypherpunk-vpn-controller.service"])
        code, out, err = agent.run(package_command(removal, family), check=False, timeout=600)
        (work / "removal.log").write_text(out + err)
        if code:
            raise RuntimeError("explicitly recovered package removal failed; see removal.log")
        for path in (
            "/opt/cypherpunk-vpn",
            "/usr/bin/cypherpunk",
            "/usr/libexec/cypherpunk-vpn-bootguard",
            "/etc/dbus-1/system.d/org.cypherpunk_vpn.Controller1.conf",
        ):
            agent.run(["/usr/bin/test", "!", "-e", path])
        if agent.run(["/bin/cat", "/etc/cypherpunk-vpn/validation-private/monotonic-floor"])[1] != "9001\n":
            raise RuntimeError("private state changed during application removal")
        result["phases"]["inactive_removal"] = dict(private_fixture_preserved=True)
        boot = guard.reboot(agent, work)
        result["phases"]["reboot_after_removal"] = dict(boot_id=boot, **probe(agent, work, True))
        if family == "rpm" and agent.run(["/bin/cat", "/sys/fs/selinux/enforce"])[1].strip() != "1":
            raise RuntimeError("guest SELinux enforcement changed during the trial")
        result["status"] = "passed_local_native_" + family + "_lifecycle"
    except BaseException as error:
        result.update(status="failed", error=type(error).__name__ + ": " + str(error)[-1500:])
        if started and "agent" in locals():
            try:
                for name, command in (
                    ("failure-processes.log", ["/bin/ps", "-eo", "pid,etime,args"]),
                    ("failure-dpkg.log", ["/usr/bin/tail", "-n", "100", "/var/log/dpkg.log"]),
                    ("failure-apt.log", ["/usr/bin/tail", "-n", "100", "/var/log/apt/term.log"]),
                ):
                    code, out, err = agent.run(command, timeout=10, check=False)
                    (work / name).write_text(out + err)
            except (OSError, RuntimeError, TimeoutError, ConnectionError, ValueError):
                result["failure_diagnostics"] = "guest unavailable; preserve console and existing phase logs"
        raise
    finally:
        result["stopped"] = time.time()
        result["guest_retained_for_diagnostics"] = bool(started and keep)
        (work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        if started and not keep:
            guard.stop_owned_guest(work)
            for name in ("client.qcow2", "pkg.img"):
                (work / name).unlink(missing_ok=True)
            shutil.rmtree(work / "pkg", ignore_errors=True)
        print(json.dumps(dict(status=result["status"], evidence=str(work / "RESULT.json"))), flush=True)


def main():
    """Run one non-overwriting trial with an existing publisher image and candidate."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--controller-client", type=Path)
    parser.add_argument("--rpm-checks", action="store_true")
    parser.add_argument("--family", choices=("deb", "rpm"), default="deb")
    parser.add_argument("--rpm-test-public-key", type=Path)
    parser.add_argument("--rpm-test-fingerprint")
    parser.add_argument(
        "--downgrade-package",
        type=Path,
        help="an older built candidate; its dpkg -i installation must be refused by preinst",
    )
    options = parser.parse_args()

    def interrupted(*_):
        raise SystemExit("package VM trial interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    run(
        options.base.resolve(strict=True),
        options.package.resolve(strict=True),
        options.work.absolute(),
        options.keep,
        options.controller_client.resolve(strict=True) if options.controller_client else None,
        options.downgrade_package.resolve(strict=True) if options.downgrade_package else None,
        options.rpm_checks,
        options.family,
        options.rpm_test_public_key.resolve(strict=True) if options.rpm_test_public_key else None,
        options.rpm_test_fingerprint,
    )


if __name__ == "__main__":
    main()

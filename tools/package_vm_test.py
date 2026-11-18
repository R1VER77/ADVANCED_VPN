#!/usr/bin/env python3
"""Validate a native candidate's lifecycle in a disposable local KVM guest.

The guest alone installs/removes packages and arms/disarms test protection. No host
network change, hardware forwarding, paid resource or real enrollment is involved.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

import bootguard_vm as guard
import vm_validation as vm

UNITS = ("advanced-vpn.service", "advanced-vpn-guard.service", "cypherpunk-vpn-controller.service")


def controller_checks(agent, work):
    """Actual bus/worker tests with an explicit disposable Polkit authorization fixture."""
    program = "/usr/local/libexec/cypherpunk-bus-validation"
    agent.run(["/usr/bin/install", "-D", "-m", "0755", "/mnt/cypherpunk-package/bus-validation", program])
    guard.put(agent, "/run/cypherpunk-controller-validation.fixture", b"disposable-controller-test-v1\n")
    rule = "/etc/polkit-1/rules.d/00-cypherpunk-disposable-validation.rules"
    try:
        agent.run(["systemctl", "start", "cypherpunk-vpn-controller.service"])
        code, out, err = agent.run(["/usr/sbin/runuser", "-u", "tester", "--", program, "denied"], check=False)
        (work / "controller-denied.log").write_text(out + err)
        if code or json.loads(out).get("status") != "denied_as_expected":
            raise RuntimeError("default inactive-user authorization test failed")
        guard.put(
            agent,
            rule,
            b"""// Only in this disposable validation VM. Not a production policy.
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
            raise RuntimeError("controller live-bus boundary test failed")
        return dict(status="passed_with_test_authorization", native_authentication_agent_qualified=False)
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


def run(base, package, work, keep=False, controller_client=None):
    """Preserve evidence and remove only the owned stopped guest's disposable disks."""
    if os.geteuid() == 0 or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("use the ordinary user's Linux system Python with pidfd support")
    work.mkdir(mode=0o700, exist_ok=False)
    result = dict(
        schema=1,
        status="running",
        scope="local_native_deb_lifecycle_only",
        started=time.time(),
        base_sha256=guard.vm_hash(base),
        package_sha256=guard.vm_hash(package),
        harness_sha256=guard.vm_hash(Path(__file__)),
        controller_client_sha256=guard.vm_hash(controller_client) if controller_client else None,
        phases={},
    )
    started = False
    try:
        payload = work / "pkg"
        payload.mkdir(mode=0o755)
        shutil.copy2(package, payload / "candidate.deb")
        if controller_client:
            shutil.copy2(controller_client, payload / "bus-validation")
        subprocess.run(
            [
                "/usr/sbin/mke2fs",
                "-q",
                "-t",
                "ext4",
                "-L",
                "avpnpkg",
                "-d",
                str(payload),
                str(work / "pkg.img"),
                "256M",
            ],
            check=True,
            timeout=30,
        )
        vm.seed(work, "client", minimal_indexes=True)
        vm.start(work, base, "client")
        started = True
        agent = vm.Agent(work / "client-qga.sock")
        vm.wait_agent(agent, 900, "native package")
        agent.run(["/usr/bin/cloud-init", "status", "--wait"], timeout=360)
        agent.sh("mkdir -p /mnt/cypherpunk-package && mount -o ro /dev/vdc /mnt/cypherpunk-package")
        result["os_release"] = agent.run(["/bin/cat", "/etc/os-release"])[1]
        guest_package = "/mnt/cypherpunk-package/candidate.deb"
        code, out, err = agent.run(
            ["/usr/bin/apt-get", "install", "-y", guest_package],
            timeout=360,
            check=False,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
        (work / "install.log").write_text(out + err)
        if code:
            raise RuntimeError("native installation failed; see install.log")
        first = agent.run(["/usr/bin/readlink", "/opt/advanced-vpn/current"])[1].strip()
        state = units(agent)
        if any(row["active"] == "active" or row["enabled"] == "enabled" for row in state.values()):
            raise RuntimeError("installation activated a controller or guard")
        versions = {name: agent.run(["/usr/bin/" + name, "--version"])[1].strip() for name in ("avpn", "cypherpunk")}
        if versions["avpn"] != versions["cypherpunk"]:
            raise RuntimeError("command aliases changed behavior")
        guard.put(agent, "/etc/advanced-vpn/validation-private/monotonic-floor", b"9001\n", "0600")
        result["phases"]["install"] = dict(slot=first, units=state, versions=versions)
        code, out, err = agent.run(
            ["/usr/bin/apt-get", "install", "--reinstall", "-y", guest_package],
            timeout=360,
            check=False,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
        (work / "upgrade.log").write_text(out + err)
        if code:
            raise RuntimeError("native replacement failed; see upgrade.log")
        second = agent.run(["/usr/bin/readlink", "/opt/advanced-vpn/current"])[1].strip()
        if first == second:
            raise RuntimeError("replacement did not select a new slot")
        agent.run(["/usr/bin/test", "-f", "/opt/advanced-vpn/" + first + "/bin/avpn"])
        result["phases"]["replace"] = dict(slot=second, previous_retained=True)
        # Damage only replaceable code; the authenticated package payload is intact.
        agent.sh("printf '\\n# injected VM corruption\\n' >> /opt/advanced-vpn/current/tools/controller_status.py")
        code, out, err = agent.run(
            ["/usr/bin/apt-get", "install", "--reinstall", "-y", guest_package],
            timeout=360,
            check=False,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
        (work / "repair.log").write_text(out + err)
        if code:
            raise RuntimeError("damaged-slot repair failed; see repair.log")
        receipt = json.loads(agent.run(["/bin/cat", "/opt/advanced-vpn/TRANSACTION.json"])[1])
        if receipt.get("unusable_previous") != second.split("/", 1)[1] or receipt.get("phase") != "committed":
            raise RuntimeError("repair did not record damaged-slot exclusion")
        result["phases"]["damaged_slot_repair"] = receipt
        boot = guard.reboot(agent, work)
        state = units(agent)
        if any(row["active"] == "active" for row in state.values()):
            raise RuntimeError("unactivated package started a service after reboot")
        result["phases"]["reboot_without_activation"] = dict(boot_id=boot, units=state)
        if controller_client:
            result["phases"]["controller_boundary"] = controller_checks(agent, work)
        result["phases"]["positive_control"] = probe(agent, work, True)
        interpreter = "/opt/advanced-vpn/current/venv/bin/python3"
        tools = "/opt/advanced-vpn/current/tools"
        prefix = "import sys; sys.path.insert(0," + repr(tools) + "); import guard_policy; "
        agent.run([interpreter, "-B", "-E", "-s", "-c", prefix + "guard_policy.arm(apply=True)"])
        code, out, err = agent.run(["/usr/bin/dpkg", "--remove", "cypherpunk-vpn"], check=False)
        (work / "guarded-removal.log").write_text(out + err)
        if not code:
            raise RuntimeError("removal succeeded while persistent protection was armed")
        agent.run(["/usr/bin/test", "-x", "/usr/libexec/cypherpunk-vpn-bootguard"])
        agent.run(["/usr/bin/test", "-x", "/opt/advanced-vpn/bin/avpn"])
        result["phases"]["guarded_removal_refused"] = dict(exit_code=code, **probe(agent, work, False))
        # This is the trial's explicit cleanup approval, inside the disposable VM.
        agent.run([interpreter, "-B", "-E", "-s", "-c", prefix + "guard_policy.disarm()"])
        agent.run(["/usr/sbin/nft", "delete", "table", "inet", "advanced_vpn"])
        agent.run(["systemctl", "stop", "advanced-vpn-guard.service", "cypherpunk-vpn-controller.service"])
        code, out, err = agent.run(["/usr/bin/dpkg", "--remove", "cypherpunk-vpn"], check=False)
        (work / "removal.log").write_text(out + err)
        if code:
            raise RuntimeError("explicitly recovered package removal failed; see removal.log")
        for path in (
            "/opt/advanced-vpn",
            "/usr/bin/cypherpunk",
            "/usr/libexec/cypherpunk-vpn-bootguard",
            "/etc/dbus-1/system.d/org.cypherpunk_vpn.Controller1.conf",
        ):
            agent.run(["/usr/bin/test", "!", "-e", path])
        if agent.run(["/bin/cat", "/etc/advanced-vpn/validation-private/monotonic-floor"])[1] != "9001\n":
            raise RuntimeError("private state changed during application removal")
        result["phases"]["inactive_removal"] = dict(private_fixture_preserved=True)
        boot = guard.reboot(agent, work)
        result["phases"]["reboot_after_removal"] = dict(boot_id=boot, **probe(agent, work, True))
        result["status"] = "passed_local_native_deb_lifecycle"
    except BaseException as error:
        result.update(status="failed", error=type(error).__name__ + ": " + str(error)[-1500:])
        raise
    finally:
        result["stopped"] = time.time()
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
    )


if __name__ == "__main__":
    main()

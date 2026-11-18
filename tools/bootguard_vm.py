#!/usr/bin/env python3
"""Validate the static boot guard and missing-guard dependency failure in one disposable VM.

Uses the existing QEMU guest-agent harness and out-of-band WAN capture. No hardware
is forwarded and no host networking is changed. This is a VM test, not a physical
power-loss test or a qualification of every network manager/initramfs configuration.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import struct
import time

import vm_validation as vm

ROOT = Path(__file__).resolve().parents[1]

PROBE = """import json,os,socket,time
payload=b"CYPHERPUNK_BOOTGUARD_VALIDATION_20261117"
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
n=0
while True:
 n+=1
 try:sock.sendto(payload,("10.0.2.2",39091))
 except OSError:pass
 with open("/run/cypherpunk-probe/count.json","w") as f:json.dump(dict(attempts=n),f)
 time.sleep(.1)
"""
PROBE_UNIT = """[Unit]
Description=Disposable non-secret leak probe
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
[Service]
Type=simple
User=tester
ExecStart=/usr/bin/python3 /usr/local/lib/cypherpunk-guard-probe.py
Restart=always
RuntimeDirectory=cypherpunk-probe
RuntimeDirectoryMode=0755
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
"""


def markers(path, start, end):
    """Count complete records between byte cursors, independent of QEMU's clock origin."""
    return sum(
        b"CYPHERPUNK_BOOTGUARD_VALIDATION_20261117" in frame
        for offset, _, frame in packet_records(path)
        if start <= offset < end
    )


def packet_records(path):
    """Bound PCAP records; do not assume their timestamps use the host wall clock."""
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("unexpected QEMU capture header")
        while True:
            start = stream.tell()
            record = stream.read(16)
            if len(record) != 16:
                return
            _, _, size, _ = struct.unpack("<IIII", record)
            if size > 65536:
                raise ValueError("oversized QEMU capture frame")
            frame = stream.read(size)
            if len(frame) != size:
                return
            yield start, stream.tell(), frame


def cursor(path):
    """The end of the last complete packet record, including while QEMU is running."""
    end = 24
    for record in packet_records(path):
        end = record[1]
    return end


def put(agent, path, value, mode="0644"):
    """Pass generated test files through the guest agent, never through exposed SSH."""
    agent.run(["/usr/bin/install", "-D", "-m", mode, "/dev/stdin", path], input=value)


def reboot(agent, work):
    """Require a changed kernel boot identity before evaluating the next boot."""
    old = agent.run(["/bin/cat", "/proc/sys/kernel/random/boot_id"])[1].strip()
    agent.call("guest-shutdown", {"mode": "reboot"}, timeout=5)
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            new = agent.run(["/bin/cat", "/proc/sys/kernel/random/boot_id"], timeout=5)[1].strip()
            if new and new != old:
                return new
        except (OSError, RuntimeError, TimeoutError, ConnectionError, ValueError):
            pass
        time.sleep(2)
    raise TimeoutError("VM did not complete a new boot: " + str(work))


def run(base, work, keep):
    """Retain captures/results; remove only this test's disposable overlay after shutdown."""
    if os.geteuid() == 0:
        raise RuntimeError("run the VM harness as your ordinary user")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("use the Linux system Python with pidfd support before creating a VM")
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = dict(
        schema=1,
        status="running",
        scope="disposable_vm_static_guard",
        base_sha256=vm_hash(base),
        input_sha256={
            name: vm_hash(ROOT / name)
            for name in (
                "tools/bootguard_vm.py",
                "deploy/bootguard-policy.json",
                "deploy/advanced-vpn-guard.service",
                "target/release/cypherpunk-bootguard",
                "target/release/cypherpunk-preflight",
            )
        },
        started=time.time(),
        phases={},
    )
    started = False
    try:
        vm.package_disk(work)
        vm.seed(work, "client")
        vm.start(work, base, "client")
        started = True
        agent = vm.Agent(work / "client-qga.sock")
        vm.wait_agent(agent, 360, "native boot guard")
        agent.run(["/usr/bin/cloud-init", "status", "--wait"], timeout=360)
        agent.sh("mkdir -p /mnt/cypherpunk-payload && mount -o ro /dev/vdc /mnt/cypherpunk-payload")
        for filename in ("cypherpunk-bootguard", "cypherpunk-preflight"):
            agent.run(
                [
                    "/usr/bin/install",
                    "-D",
                    "-m",
                    "0755",
                    "/mnt/cypherpunk-payload/target/release/" + filename,
                    "/usr/libexec/" + ("cypherpunk-vpn-bootguard" if filename == "cypherpunk-bootguard" else filename),
                ]
            )
        put(agent, "/usr/local/lib/cypherpunk-guard-probe.py", PROBE)
        put(agent, "/etc/systemd/system/cypherpunk-leak-probe.service", PROBE_UNIT)
        agent.run(["systemctl", "daemon-reload"])
        start = cursor(work / "client-wan.pcap")
        agent.run(["systemctl", "start", "cypherpunk-leak-probe.service"])
        time.sleep(4)
        agent.run(["systemctl", "stop", "cypherpunk-leak-probe.service"])
        time.sleep(1)
        end = cursor(work / "client-wan.pcap")
        positive = markers(work / "client-wan.pcap", start, end)
        result["phases"]["positive_control"] = dict(marker_frames=positive, passed=positive > 0)
        if not positive:
            raise RuntimeError("leak probe has no positive-control WAN frames")
        agent.run(["systemctl", "stop", "cypherpunk-leak-probe.service"])
        unit = (ROOT / "deploy/advanced-vpn-guard.service").read_bytes()
        put(agent, "/etc/systemd/system/advanced-vpn-guard.service", unit)
        put(agent, "/etc/advanced-vpn/whole-device.guard", b"cypherpunk-vpn whole-device guard v1\n", "0600")
        put(agent, "/etc/advanced-vpn/enrolled/preferences.json", b'{"mode":"whole-device"}\n', "0600")
        policy = json.loads((ROOT / "deploy/bootguard-policy.json").read_text())
        MANAGERS, REQUIRE, DROPIN = policy["managers"], policy["requires"].encode(), policy["dropin"]

        for manager in MANAGERS:
            put(agent, "/etc/systemd/system/" + manager + ".d/" + DROPIN, REQUIRE)
        # No /opt application or Python runtime is installed in this trial.
        code, _, _ = agent.run(["/usr/bin/test", "!", "-e", "/opt/advanced-vpn"], check=False)
        if code:
            raise RuntimeError("VM unexpectedly contains an application runtime")
        agent.run(["systemctl", "daemon-reload"])
        agent.run(["systemctl", "enable", "advanced-vpn-guard.service", "cypherpunk-leak-probe.service"])
        start = cursor(work / "client-wan.pcap")
        boot = reboot(agent, work)
        time.sleep(5)
        active = agent.run(["systemctl", "is-active", "advanced-vpn-guard.service"], check=False)[1].strip()
        managers = {name: agent.run(["systemctl", "is-active", name], check=False)[1].strip() for name in MANAGERS}
        addresses = json.loads(agent.run(["/usr/sbin/ip", "-4", "-j", "address", "show", "dev", "wan"])[1])
        routes = json.loads(agent.run(["/usr/sbin/ip", "-j", "route", "show", "default"])[1])
        network_ready = (
            any(value == "active" for value in managers.values())
            and bool(routes)
            and any(item.get("scope") == "global" for interface in addresses for item in interface.get("addr_info", []))
        )
        probe = json.loads(agent.run(["/bin/cat", "/run/cypherpunk-probe/count.json"])[1])
        rules = agent.run(["/usr/sbin/nft", "-j", "list", "table", "inet", "advanced_vpn"])[1]
        (work / "missing-runtime-rules.json").write_text(rules)
        agent.run(["systemctl", "stop", "cypherpunk-leak-probe.service"])
        time.sleep(1)
        leaked = markers(work / "client-wan.pcap", start, cursor(work / "client-wan.pcap"))
        passed = active == "active" and network_ready and probe["attempts"] > 0 and leaked == 0
        result["phases"]["missing_application_runtime"] = dict(
            boot_id=boot,
            guard=active,
            network_ready=network_ready,
            generated_attempts=probe["attempts"],
            marker_frames=leaked,
            passed=passed,
        )
        if not passed:
            raise RuntimeError("missing-runtime boot protection failed")
        # The second fault removes the independent component itself. A network
        # manager must fail its Requires dependency rather than start unguarded.
        agent.run(
            ["/bin/mv", "/usr/libexec/cypherpunk-vpn-bootguard", "/usr/libexec/cypherpunk-vpn-bootguard.unavailable"]
        )
        start = cursor(work / "client-wan.pcap")
        boot = reboot(agent, work)
        time.sleep(5)
        guard = agent.run(["systemctl", "is-failed", "advanced-vpn-guard.service"], check=False)[1].strip()
        managers = {name: agent.run(["systemctl", "is-active", name], check=False)[1].strip() for name in MANAGERS}
        probe = json.loads(agent.run(["/bin/cat", "/run/cypherpunk-probe/count.json"])[1])
        agent.run(["systemctl", "stop", "cypherpunk-leak-probe.service"])
        time.sleep(1)
        leaked = markers(work / "client-wan.pcap", start, cursor(work / "client-wan.pcap"))
        passed = (
            guard == "failed"
            and all(state != "active" for state in managers.values())
            and probe["attempts"] > 0
            and leaked == 0
        )
        result["phases"]["missing_guard_component"] = dict(
            boot_id=boot,
            guard=guard,
            managers=managers,
            generated_attempts=probe["attempts"],
            marker_frames=leaked,
            passed=passed,
        )
        if not passed:
            raise RuntimeError("missing-guard dependency failure did not stay blocked")
        result["status"] = "passed_ipv4_local_vm_only"
    except BaseException as error:
        result.update(status="failed", error=type(error).__name__ + ": " + str(error)[-1500:])
        raise
    finally:
        result["stopped"] = time.time()
        (work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        if started and not keep:
            stop_owned_guest(work)
            # The immutable publisher image, evidence and captures stay intact.
            for name in ("client.qcow2", "pkg.img"):
                (work / name).unlink(missing_ok=True)
            shutil.rmtree(work / "pkg", ignore_errors=True)
        print(json.dumps(dict(status=result["status"], evidence=str(work / "RESULT.json"))), flush=True)


def vm_hash(path):
    """Bind the trial to the existing publisher image without reading it into memory."""
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def stop_owned_guest(work):
    """Check the owned QEMU identity before shutdown; never signal an unrelated PID."""
    pidfile = work / "client.pid"
    if not pidfile.exists():
        return
    pid = int(pidfile.read_text())
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        args = (Path("/proc") / str(pid) / "cmdline").read_bytes()
        if b"qemu-system-x86_64" not in args or os.fsencode(str(work / "client.qcow2")) not in args:
            raise RuntimeError("VM PID identity changed; guest/overlay cleanup refused")
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        if not select.select([descriptor], [], [], 10)[0]:
            raise RuntimeError("owned VM has not stopped; overlay retained")
    finally:
        os.close(descriptor)


def main():
    """Run one new, non-overwriting trial on an existing verified local image."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--keep", action="store_true")
    options = parser.parse_args()

    def interrupted(*_):
        raise SystemExit("VM trial interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    run(options.base.resolve(strict=True), options.work.absolute(), options.keep)


if __name__ == "__main__":
    main()

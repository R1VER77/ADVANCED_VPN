#!/usr/bin/env python3
"""Exercise an offline release in one disposable KVM guest; never install on the host.

Supply a clean Debian/Ubuntu cloud-image base, a built package and a new work
directory. Guest-agent access stays available while installation runs in a network
namespace with no external interface. No cloud resources or physical keys are used.
"""

import argparse
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess

import bundled_runtime
import vm_validation as vm

SCRIPT = r"""set -eux
mkdir -p /mnt/pkg /tmp/offline-release
mount -o ro LABEL=cpvpnpkg /mnt/pkg
tar -xzf /mnt/pkg/release.tar.gz -C /tmp/offline-release
cd /tmp/offline-release
modprobe tun
modprobe nf_tables
# All install and upgrade subprocesses inherit an isolated network namespace.
# systemd communicates over the local Unix socket; it is never asked to activate.
unshare -n ./install.sh --apply
/opt/cypherpunk-vpn/venv/bin/python3 -B -E -s -c 'import sys; assert sys.version.split()[0] == "@PYTHON_VERSION@"'
/opt/cypherpunk-vpn/bin/cypherpunk --version
/opt/cypherpunk-vpn/bin/cypherpunk --json --state /tmp/not-enrolled hops > /tmp/offline-hops.json
/opt/cypherpunk-vpn/venv/bin/python3 -B -E -s -c 'import json; assert json.load(open("/tmp/offline-hops.json"))["ok"]'
/opt/cypherpunk-vpn/bin/cypherpunk --json preflight > /tmp/offline-preflight.json
/opt/cypherpunk-vpn/bin/cypherpunk --json doctor > /tmp/offline-doctor.json || true
/opt/cypherpunk-vpn/venv/bin/python3 -B -E -s -c '
import json
assert json.load(open("/tmp/offline-preflight.json"))["preflight"]["ready"]
rows = json.load(open("/tmp/offline-doctor.json"))["checks"]
host = [row for row in rows if row["check"].startswith("host: ")]
assert host and all(row["ok"] for row in host), host
'
for unit in cypherpunk-vpn.service cypherpunk-vpn-guard.service; do
    test "$(systemctl is-enabled "$unit" || true)" = disabled
    test "$(systemctl is-active "$unit" || true)" = inactive
done
test -z "$(nft list tables)"
printf '%s\n' 'preserve existing private state' > /etc/cypherpunk-vpn/offline-test-state
unshare -n ./install.sh --apply
test "$(cat /etc/cypherpunk-vpn/offline-test-state)" = 'preserve existing private state'
for unit in cypherpunk-vpn.service cypherpunk-vpn-guard.service; do
    test "$(systemctl is-enabled "$unit" || true)" = disabled
    test "$(systemctl is-active "$unit" || true)" = inactive
done
test -z "$(nft list tables)"
# User/operator installation is also offline and keeps its configuration on removal.
install -d -m 700 -o tester -g tester /home/tester/.config/cypherpunk-vpn
printf '{"schema":1,"resources":{}}\n' > /home/tester/.config/cypherpunk-vpn/cloud.json
chown tester:tester /home/tester/.config/cypherpunk-vpn/cloud.json
unshare -n runuser -u tester -- ./install.sh --user
unshare -n runuser -u tester -- ./install.sh --user
runuser -u tester -- /home/tester/.local/bin/cypherpunk --json cloud status > /tmp/offline-cloud.json
./runtime/bin/python3 -B -E -s -c 'import json; assert json.load(open("/tmp/offline-cloud.json"))["ok"]'
runuser -u tester -- ./install.sh --user --uninstall
test ! -e /home/tester/.local/bin/cypherpunk
test -f /home/tester/.config/cypherpunk-vpn/cloud.json
./runtime/bin/python3 -B -E -s tools/bundled_runtime.py --verify /opt/cypherpunk-vpn/venv
# Corruption refuses before creating the requested stage, keeping the installed tree.
cp runtime/lib/python3.13/colorsys.py /tmp/original-colorsys.py
printf 'corrupt' >> runtime/lib/python3.13/colorsys.py
if ./install.sh --out /tmp/should-not-exist > /tmp/refusal.log 2>&1; then
    echo 'corrupt runtime was accepted' >&2; exit 1
fi
test ! -e /tmp/should-not-exist
grep -q 'runtime files differ' /tmp/refusal.log
test "$(cat /etc/cypherpunk-vpn/offline-test-state)" = 'preserve existing private state'
cp /tmp/original-colorsys.py runtime/lib/python3.13/colorsys.py
for unit in cypherpunk-vpn.service cypherpunk-vpn-guard.service; do
    test "$(systemctl is-enabled "$unit" || true)" = disabled
    test "$(systemctl is-active "$unit" || true)" = inactive
done
test -z "$(nft list tables)"
# Removal never disables an enabled guard, even when no tunnel has been started.
systemctl enable cypherpunk-vpn-guard.service
if ./install.sh --apply --uninstall > /tmp/remove-enabled.log 2>&1; then
    echo 'removed an enabled guard' >&2; exit 1
fi
test -d /opt/cypherpunk-vpn
test "$(systemctl is-enabled cypherpunk-vpn-guard.service)" = enabled
systemctl disable cypherpunk-vpn-guard.service
# A synthetic, hookless table tests refusal without restricting guest networking.
nft add table inet cypherpunk_vpn
if ./install.sh --apply --uninstall > /tmp/remove-table.log 2>&1; then
    echo 'removed files beneath a retained guard' >&2; exit 1
fi
nft list table inet cypherpunk_vpn
test -d /opt/cypherpunk-vpn
nft delete table inet cypherpunk_vpn
# Foreground programs count even though both services are inactive.
/opt/cypherpunk-vpn/venv/bin/python3 -B -E -s -c 'import time; time.sleep(300)' &
test_pid=$!
if ./install.sh --apply --uninstall > /tmp/remove-running.log 2>&1; then
    kill "$test_pid"; echo 'removed a running installed program' >&2; exit 1
fi
test -d /opt/cypherpunk-vpn
kill "$test_pid"
wait "$test_pid" || true
./install.sh --apply --uninstall
test ! -e /opt/cypherpunk-vpn
test ! -e /etc/systemd/system/cypherpunk-vpn.service
test ! -e /etc/systemd/system/cypherpunk-vpn-guard.service
test ! -e /usr/local/bin/cypherpunk
test ! -e /usr/local/bin/cypherpunkctl
test "$(cat /etc/cypherpunk-vpn/offline-test-state)" = 'preserve existing private state'
test -f /home/tester/.config/cypherpunk-vpn/cloud.json
test -z "$(nft list tables)"
printf '%s\n' SYSTEM_REMOVAL_PASS
cat /etc/os-release
printf '%s\n' OFFLINE_PACKAGE_PASS
"""


def run(base, package, work):
    """Create an overlay, exercise real installed paths and always stop the owned VM."""
    work.mkdir(mode=0o700, parents=False, exist_ok=False)
    payload = work / "payload"
    payload.mkdir()
    shutil.copy2(package, payload / "release.tar.gz")
    disk_mb = max(256, (package.stat().st_size >> 20) * 2 + 64)
    subprocess.run(["/usr/sbin/mke2fs", "-q", "-t", "ext4", "-L", "cpvpnpkg", "-d", str(payload),
                    str(work / "pkg.img"), str(disk_mb) + "M"], check=True)  # fmt: skip
    # Save module settings when imported by another harness in the same process.
    previous_vms, previous_packages = vm.VMS, vm.PACKAGES
    vm.VMS = {"client": dict(n=1, links={})}
    vm.PACKAGES = ["qemu-guest-agent", "nftables", "iproute2", "kmod", "util-linux"]
    agent = vm.Agent(work / "client-qga.sock")
    started = False
    try:
        vm.seed(work, "client")
        vm.start(work, base, "client")
        started = True
        vm.wait_agent(agent, 900, "client")
        agent.sh("cloud-init status --wait >/dev/null 2>&1; true", timeout=900)
        code, out, err = agent.sh(
            SCRIPT.replace("@PYTHON_VERSION@", bundled_runtime.VERSION), timeout=1500, check=False
        )
        (work / "guest-test.log").write_text(out + "\n" + err)
        result = dict(schema=1, date_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                      base_name=base.name, base_sha256=bundled_runtime.sha256(base),
                      package_sha256=bundled_runtime.sha256(package),
                      scope="system/user install/upgrade/removal; enabled-guard, retained-table and running-process refusal; corruption refusal",
                      install_network="isolated guest network namespace", physical_hardware=False,
                      system_removal_tested="SYSTEM_REMOVAL_PASS" in out, reboot_protection_tested=False,
                      passed=code == 0 and "OFFLINE_PACKAGE_PASS" in out, exit_code=code)  # fmt: skip
        (work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return result["passed"]
    finally:
        if started:
            try:
                agent.call("guest-shutdown")
            except (OSError, ConnectionError, ValueError, RuntimeError):
                # Kill only the QEMU process created by this invocation, via its
                # pidfile. Do not affect any other running project VM.
                pidfile = work / "client.pid"
                if pidfile.exists():
                    pid = int(pidfile.read_text())
                    cmdline = Path("/proc/%d/cmdline" % pid)
                    if cmdline.exists() and str(work / "client.qcow2").encode() in cmdline.read_bytes():
                        import os
                        import signal

                        os.kill(pid, signal.SIGTERM)
        vm.VMS, vm.PACKAGES = previous_vms, previous_packages


def main():
    """Run a single distribution so the caller can build an explicit validation matrix."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, required=True)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    a = p.parse_args()
    if not a.base.is_file() or not a.package.is_file():
        p.error("base and package must be existing regular files")
    return 0 if run(a.base.resolve(), a.package.resolve(), a.work.resolve()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

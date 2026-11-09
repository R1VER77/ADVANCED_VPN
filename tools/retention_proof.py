#!/usr/bin/env python3
"""Raw-disk proof that a hardened server writes no identifying log to disk.

Boots a fresh cloud image with cloud-init user data, with or without the hardening from
tools/retention.py. Makes a failed SSH login with a unique username and a successful one
with a unique key, powers the VM off cleanly, then scans every byte the VM wrote for
both markers. The qcow2 overlay holds all of them, deleted blocks included, since
discard is not passed through. A stock image keeps the markers; a hardened one must not.

usage: retention_proof.py BASE WORK hardened|control USER
  BASE  an official cloud image (Debian 13 genericcloud, Ubuntu 24.04 server cloudimg)
  USER  its default login user (debian, ubuntu)
Needs KVM, qemu-system-x86_64, qemu-img, genisoimage and OpenSSH. Not run in CI.
"""

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import retention  # noqa: E402


def need(name):
    """The full path of a required program."""
    found = shutil.which(name)
    if not found:
        raise SystemExit("%s is required" % name)
    return found


def free_port():
    """A free TCP port on the loopback interface."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    """Run one proof and print its result as JSON."""
    if len(sys.argv) != 5 or sys.argv[3] not in ("hardened", "control"):
        raise SystemExit(__doc__)
    base, work, mode, user = Path(sys.argv[1]).resolve(), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
    qemu_img, keygen, iso, qemu, ssh_exe = map(
        need, ["qemu-img", "ssh-keygen", "genisoimage", "qemu-system-x86_64", "ssh"]
    )
    work.mkdir(parents=True)
    overlay = work / "disk.qcow2"
    subprocess.run(
        [qemu_img, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay), "8G"], check=True
    )
    for k in ("control", "marker"):
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(work / k)], check=True)
    bad_user = "x" + secrets.token_hex(12)
    fingerprint = subprocess.run(
        [keygen, "-lf", str(work / "marker.pub")], capture_output=True, text=True, check=True
    ).stdout.split()[1]

    ud = retention.cloud_init() if mode == "hardened" else "#cloud-config\n"
    ud += "ssh_pwauth: false\nssh_authorized_keys:\n"
    ud += "".join("  - %s\n" % (work / (k + ".pub")).read_text().strip() for k in ("control", "marker"))
    seed = work / "seed"
    seed.mkdir()
    (seed / "user-data").write_text(ud)
    (seed / "meta-data").write_text("instance-id: proof-%s\nlocal-hostname: proof\n" % secrets.token_hex(4))
    subprocess.run([iso, "-quiet", "-output", str(work / "seed.iso"), "-volid", "cidata", "-joliet", "-rock",
                    str(seed / "user-data"), str(seed / "meta-data")], check=True)  # fmt: skip

    port = free_port()
    subprocess.run([qemu, "-enable-kvm", "-cpu", "host", "-smp", "2", "-m", "1024", "-display", "none",
                    "-daemonize", "-pidfile", str(work / "pid"), "-serial", "file:" + str(work / "console.log"),
                    "-drive", "file=%s,if=virtio,format=qcow2" % overlay,
                    "-drive", "file=%s,if=virtio,format=raw,readonly=on" % (work / "seed.iso"),
                    "-netdev", "user,id=n,ipv6=off,hostfwd=tcp:127.0.0.1:%d-:22" % port,
                    "-device", "virtio-net-pci,netdev=n"], check=True)  # fmt: skip
    pid = int((work / "pid").read_text())
    opts = ["-p", str(port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR"]  # fmt: skip

    def ssh(key, who, cmd, check=True, stdin=None):
        """Run `cmd` on the VM as `who`, authenticating with `key`."""
        return subprocess.run([ssh_exe, "-i", str(work / key), *opts, "%s@127.0.0.1" % who, cmd],
                              capture_output=True, text=True, check=check, input=stdin, timeout=120)  # fmt: skip

    end = time.monotonic() + 420
    while time.monotonic() < end:
        if (
            ssh("control", user, "cloud-init status --wait >/dev/null 2>&1; echo up", check=False).stdout.strip()
            == "up"
        ):
            break
        time.sleep(5)
    else:
        raise SystemExit("VM never became reachable over SSH")

    # The real checks, on the real host.
    code = (ROOT / "tools/retention.py").read_text() + "\nimport json\nprint(json.dumps(checks()))\n"
    checks = json.loads(ssh("control", user, "sudo python3 -", stdin=code).stdout)

    # The identifying activity.
    for _ in range(3):
        ssh("control", bad_user, "true", check=False)
    ok = ssh("marker", user, "echo marker-login-ok").stdout.strip()
    time.sleep(3)
    ssh("control", user, "sudo sync; (sleep 1; sudo systemctl poweroff) >/dev/null 2>&1 &", check=False)
    for _ in range(120):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(1)
    else:
        raise SystemExit("VM did not power off")

    data = overlay.read_bytes()
    found = {
        name: data.count(m.encode())
        for name, m in [("failed-login username", bad_user), ("accepted key fingerprint", fingerprint)]
    }
    print(json.dumps(dict(mode=mode, image=base.name, marker_login=ok, checks=checks, written_bytes=len(data),
                          markers_on_disk=found), indent=1))  # fmt: skip


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Prove the assistant package works where unprivileged user namespaces are restricted.

    assistant_vm_test.py --image noble-server-cloudimg-amd64.img --deb cypherpunk-vpn-assistant_*.deb \
        --work DIR [--out evidence.json]

Boots a disposable Ubuntu 24.04 KVM guest from its unmodified cloud image (the kernel's
default `apparmor_restrict_unprivileged_userns=1`), and checks, in order:
1. the restriction is on: an ordinary user's `unshare -rn` fails;
2. installing the package loads the launcher's AppArmor profile;
3. the real assistant answers as that ordinary user, through the launcher;
4. the running model's network namespace has no interface but loopback;
5. without the profile (unloaded), the same request falls back to the rules and says
   why (`no_network_isolation`): the profile is what makes it work;
6. removing the package unloads and deletes the profile.

The guest reaches the network only to install qemu-guest-agent at first boot; the
package and the tools come on a separate disk image.
"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import vm_validation as vm  # noqa: E402

USER = "tester"
PROBE = r"""
set -eu
cd /payload/tools
python3 -I - <<'PY'
import json, sys
sys.path.insert(0, ".")
import assistant, troubleshoot
line = "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 489333 (apt-get)"
f = troubleshoot.diagnose("Install cpvpn-relay as the relay", [line], server="cpvpn-relay")
print(json.dumps(assistant.explain(f)))
PY
"""
NETNS = r"""
set -eu
d=$(mktemp -d); /usr/lib/cypherpunk-vpn/assistant/isolate -m /usr/lib/cypherpunk-vpn/assistant/gemma-3-1b-it-Q8_0.gguf \
  --host "$d/s.sock" --offline -c 512 -t 1 --log-disable >/dev/null 2>&1 &
pid=$!; for i in $(seq 120); do [ -S "$d/s.sock" ] && break; sleep 0.5; done
awk 'NR>2 {print $1}' /proc/$pid/net/dev | tr -d ':' | tr '\n' ' '
[ "$(readlink /proc/$pid/ns/net)" != "$(readlink /proc/self/ns/net)" ] && echo own-netns
kill $pid
"""


def seed(work):
    d = work / "seed"
    d.mkdir()
    (d / "meta-data").write_text("instance-id: cpvpn-assistant\nlocal-hostname: cpvpn-assistant\n")
    (d / "user-data").write_text("\n".join([
        "#cloud-config",
        "users:",
        "  - name: " + USER,
        "    uid: 1500",
        "    shell: /bin/bash",
        "    lock_passwd: true",
        "package_update: true",
        "packages: [qemu-guest-agent]",
        "mounts:",
        "  - [LABEL=cpvpnassist, /payload, ext4, 'ro,nofail', '0', '0']",
        "runcmd:",
        "  - [mkdir, -p, /payload]",
        "  - [mount, -a]",
        "  - [systemctl, enable, --now, qemu-guest-agent]",
    ]) + "\n")  # fmt: skip
    iso = work / "seed.iso"
    subprocess.run(["genisoimage", "-quiet", "-output", str(iso), "-volid", "cidata", "-joliet", "-rock",
                    str(d / "user-data"), str(d / "meta-data")], check=True)  # fmt: skip
    return iso


def payload(work, deb):
    p = work / "payload"
    (p / "tools").mkdir(parents=True)
    for name in ("assistant.py", "troubleshoot.py"):
        shutil.copy2(TOOLS / name, p / "tools" / name)
    shutil.copy2(deb, p / "assistant.deb")
    img = work / "payload.img"
    size = "%dM" % (deb.stat().st_size // (1 << 20) + 256)
    subprocess.run(["/usr/sbin/mke2fs", "-q", "-t", "ext4", "-L", "cpvpnassist", "-d", str(p), str(img), size],
                   check=True)  # fmt: skip
    return img


def boot(work, image, iso, disk):
    overlay = work / "guest.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image.resolve()),
                    str(overlay), "12G"], check=True)  # fmt: skip
    agent = work / "qga.sock"
    subprocess.run([
        "qemu-system-x86_64", "-name", "cpvpn-assistant", "-enable-kvm", "-cpu", "host", "-smp", "4", "-m", "4096",
        "-display", "none", "-daemonize", "-pidfile", str(work / "guest.pid"),
        "-serial", "file:" + str(work / "serial.log"),
        "-drive", "file=%s,if=virtio,format=qcow2" % overlay,
        "-drive", "file=%s,if=virtio,format=raw,readonly=on" % disk,
        "-drive", "file=%s,media=cdrom" % iso,
        "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
        "-chardev", "socket,path=%s,server=on,wait=off,id=qga0" % agent,
        "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
    ], check=True)  # fmt: skip
    return vm.Agent(agent)


def main(argv=None):
    """Run the checks; write the evidence record."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--deb", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--out", type=Path)
    a = p.parse_args(argv)
    a.work.mkdir(parents=True)
    agent = boot(a.work, a.image, seed(a.work), payload(a.work, a.deb))
    record = dict(schema=1, date=time.strftime("%Y-%m-%d"), image=a.image.name, package=a.deb.name)
    try:
        vm.wait_agent(agent, 900, "the Ubuntu 24.04 guest agent")

        def run(script, user=None, timeout=300):
            argv = (
                ["/usr/sbin/runuser", "-u", user, "--", "/bin/sh", "-c", script] if user else ["/bin/sh", "-c", script]
            )
            return agent.run(argv, timeout=timeout, check=False)

        def wait(script, seconds):
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                if run(script)[0] == 0:
                    return True
                time.sleep(3)
            return False

        if not wait("test -f /payload/assistant.deb && cloud-init status --wait >/dev/null", 900):
            raise SystemExit("payload never mounted")
        record["os"] = run(". /etc/os-release; echo $PRETTY_NAME")[1].strip()
        record["restrict_userns"] = run("cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns")[1].strip()
        code, out, err = run("unshare -rn true", user=USER)
        record["plain_unshare_refused"] = code != 0
        code, out, err = run("dpkg -i /payload/assistant.deb", timeout=900)
        record["install"] = dict(code=code, messages=[x for x in (out + err).splitlines() if "cypherpunk" in x][-4:])
        record["profile_loaded"] = "cypherpunk-vpn-assistant" in run("aa-status 2>/dev/null || true")[1]
        code, out, err = run(PROBE, user=USER, timeout=900)
        reply = json.loads(out.strip().splitlines()[-1]) if code == 0 and out.strip() else dict(error=err[-400:])
        record["reply"] = reply
        record["interfaces_in_model_namespace"] = run(NETNS, user=USER, timeout=600)[1].strip()
        # The counter-check: unload the profile and ask again.
        run("apparmor_parser -R /etc/apparmor.d/cypherpunk-vpn-assistant")
        code, out, err = run(PROBE, user=USER, timeout=900)
        record["reply_without_profile"] = (
            json.loads(out.strip().splitlines()[-1]) if code == 0 and out.strip() else dict(error=err[-400:])
        )
        run("apparmor_parser -r -W /etc/apparmor.d/cypherpunk-vpn-assistant")
        run("dpkg -r cypherpunk-vpn-assistant", timeout=300)
        record["profile_after_remove"] = dict(
            file=run("test -e /etc/apparmor.d/cypherpunk-vpn-assistant")[0] == 0,
            loaded="cypherpunk-vpn-assistant" in run("aa-status 2>/dev/null || true")[1],
        )
    finally:
        try:
            agent.call("guest-shutdown", {"mode": "powerdown"}, timeout=10)
        except Exception as e:  # noqa: BLE001 (the guest is disposable; it is killed below)
            print("guest shutdown request failed: %s" % e, file=sys.stderr)
        time.sleep(5)
        pid = (a.work / "guest.pid").read_text().strip() if (a.work / "guest.pid").exists() else ""
        if pid:
            subprocess.run(["kill", pid], check=False)
    passed = (record.get("restrict_userns") == "1" and record.get("plain_unshare_refused")
              and record.get("profile_loaded") and record.get("reply", {}).get("source") == "assistant"
              and record.get("interfaces_in_model_namespace", "").startswith("lo own-netns")
              and record.get("reply_without_profile", {}).get("why") == "no_network_isolation"
              and record.get("profile_after_remove") == dict(file=False, loaded=False))  # fmt: skip
    record["passed"] = bool(passed)
    text = json.dumps(record, indent=1) + "\n"
    if a.out:
        a.out.write_text(text)
    print(text)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Upgrade from the previous release's package in a disposable KVM guest.

    upgrade_vm_test.py --image debian-13-genericcloud-amd64.qcow2 --old OLD.deb --new NEW.deb \
        [--assistant ASSISTANT.deb] --work DIR [--out evidence.json]

Installs OLD as a user would, then upgrades with NEW the way the owner did on 23 Nov
2026 (`apt install --reinstall`, same version number), and checks the result:
- the upgrade configures without error;
- the pre-rename install (/opt/advanced-vpn, its units, its command links) is gone and the
  new one (/opt/cypherpunk-vpn) is in place;
- the I2P router's AppArmor fragment carries the new block and none of the old paths;
- the new command line answers.

The guest installs dependencies from its distribution's archive; the packages come on a
separate disk image. Nothing is enrolled and no tunnel is started.
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

import assistant_vm_test as guest  # noqa: E402
import vm_validation as vm  # noqa: E402


def payload(work, files):
    p = work / "payload"
    p.mkdir()
    for name, src in files.items():
        shutil.copy2(src, p / name)
    img = work / "payload.img"
    size = "%dM" % (sum(f.stat().st_size for f in p.iterdir()) // (1 << 20) + 256)
    subprocess.run(["/usr/sbin/mke2fs", "-q", "-t", "ext4", "-L", "cpvpnassist", "-d", str(p), str(img), size],
                   check=True)  # fmt: skip
    shutil.rmtree(p)  # the image holds them; a second copy of a 1 GB package filled the disk once
    return img


def main(argv=None):
    """Run the upgrade; write the evidence record."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--old", type=Path, required=True)
    p.add_argument("--new", type=Path, required=True)
    p.add_argument("--assistant", type=Path)
    p.add_argument("--failed-first", type=Path, help="a package whose upgrade fails first (half-configured)")
    p.add_argument(
        "--with",
        dest="tool",
        choices=("apt", "dpkg"),
        default="apt",
        help="upgrade with apt-get install --reinstall, or dpkg -i (for a half-configured package)",
    )
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--out", type=Path)
    a = p.parse_args(argv)
    a.work.mkdir(parents=True)
    files = {"old.deb": a.old, "new.deb": a.new}
    if a.failed_first:
        files["failed.deb"] = a.failed_first
    if a.assistant:
        files["assistant.deb"] = a.assistant
    agent = guest.boot(a.work, a.image, guest.seed(a.work), payload(a.work, files))
    record = dict(schema=1, date=time.strftime("%Y-%m-%d"), image=a.image.name,
                  old=a.old.name, new=a.new.name, assistant=a.assistant.name if a.assistant else None)  # fmt: skip
    try:
        vm.wait_agent(agent, 900, "the guest agent")

        def run(script, timeout=900):
            return agent.run(["/bin/sh", "-c", script], timeout=timeout, check=False,
                             env={"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})  # fmt: skip

        end = time.monotonic() + 900
        while run("test -f /payload/new.deb && cloud-init status --wait >/dev/null")[0] != 0:
            if time.monotonic() > end:
                raise SystemExit("payload never mounted")
            time.sleep(3)
        record["os"] = run(". /etc/os-release; echo $PRETTY_NAME")[1].strip()
        code, out, err = run("cp /payload/*.deb /root/ && apt-get install -y -q /root/old.deb 2>&1 | tail -5")
        record["old_install"] = dict(code=code, tail=out.strip().splitlines()[-3:])
        record["old_state"] = run("ls -d /opt/advanced-vpn /opt/cypherpunk-vpn 2>&1; grep -c advanced-vpn "
                                  "/etc/apparmor.d/local/usr.bin.i2pd 2>&1")[1].split("\n")  # fmt: skip
        if a.failed_first:
            # The laptop's own path: a failed upgrade leaves the package half-configured first.
            out = run("apt-get install -y -q --reinstall /root/failed.deb 2>&1; echo apt-exit=$?")[1]
            record["failed_first"] = dict(exit=out.strip().splitlines()[-1], status=run(
                "dpkg-query -W -f '${db:Status-Abbrev}' cypherpunk-vpn")[1].strip())  # fmt: skip
        debs = "/root/new.deb" + (" /root/assistant.deb" if a.assistant else "")
        if a.tool == "dpkg":
            code, out, err = run("dpkg -i " + debs + " 2>&1; echo apt-exit=$?")
        else:
            code, out, err = run("apt-get install -y -q --reinstall " + debs + " 2>&1; echo apt-exit=$?")
        record["upgrade_with"] = a.tool
        record["upgrade"] = dict(exit=out.strip().splitlines()[-1],
                                 errors=[x for x in out.splitlines() if "rror" in x or "Traceback" in x][-6:],
                                 notices=[x for x in out.splitlines() if "previous version" in x or "cypherpunk-vpn" in x
                                          and ("Removed" in x or "Refusing" in x)][-4:])  # fmt: skip
        packages = "cypherpunk-vpn" + (
            " cypherpunk-vpn-assistant" if a.assistant else ""
        )  # only what this run installs
        record["dpkg_status"] = run("dpkg-query -W -f '${db:Status-Abbrev} ${Package}\\n' " + packages
                                    + " 2>&1")[1].strip().splitlines()  # fmt: skip
        record["after"] = dict(
            old_root=run("test -e /opt/advanced-vpn")[0] == 0,
            new_root=run("test -d /opt/cypherpunk-vpn")[0] == 0,
            old_units=run("ls /etc/systemd/system/advanced-vpn*.service 2>/dev/null | wc -l")[1].strip(),
            old_commands=run("ls /usr/bin/avpn /usr/bin/avpnctl 2>/dev/null | wc -l")[1].strip(),
            fragment_old_paths=run("grep -c advanced-vpn /etc/apparmor.d/local/usr.bin.i2pd || true")[1].strip(),
            fragment_new_paths=run("grep -c cypherpunk-vpn-runtime /etc/apparmor.d/local/usr.bin.i2pd || true")[1].strip(),
            cli=run("cypherpunkctl --help >/dev/null 2>&1 && echo ok || echo failed")[1].strip(),
        )  # fmt: skip
    finally:
        try:
            agent.call("guest-shutdown", {"mode": "powerdown"}, timeout=10)
        except Exception as e:  # noqa: BLE001 (the guest is disposable; it is killed below)
            print("guest shutdown request failed: %s" % e, file=sys.stderr)
        time.sleep(5)
        pid = (a.work / "guest.pid").read_text().strip() if (a.work / "guest.pid").exists() else ""
        if pid:
            subprocess.run(["kill", pid], check=False)
    after = record.get("after", {})
    record["passed"] = bool(
        record.get("upgrade", {}).get("exit") == "apt-exit=0"
        and all(line.startswith("ii ") for line in record.get("dpkg_status", []))
        and not after.get("old_root") and after.get("new_root")
        and after.get("old_units") == "0" and after.get("old_commands") == "0"
        and after.get("fragment_old_paths") == "0" and after.get("fragment_new_paths") not in ("", "0")
        and after.get("cli") == "ok"
    )  # fmt: skip
    text = json.dumps(record, indent=1) + "\n"
    if a.out:
        a.out.write_text(text)
    print(text)
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

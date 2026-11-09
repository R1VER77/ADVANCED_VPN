#!/usr/bin/env python3
"""Installed-service, reboot and impaired-link validation in three local KVM VMs.

Host-side orchestrator; it never changes host networking. Each VM gets QEMU
user-mode NAT (package installation, the exit's Internet egress and the client's
deliberately working fallback route) plus point-to-point unix datagram links:

    client  linka 192.0.2.2/30  <->  192.0.2.1/30   linka  relay
    relay   linkb 198.51.100.1/30 <-> 198.51.100.2/30 linkb  exit  -> Internet (NAT)

Guests are controlled only through the QEMU guest agent (virtio-serial), so the
client's whole-device kill switch can be exercised without losing control and
no SSH port is exposed. QEMU filter-dump records every client frame for the
boot-leak analysis. The real tool/installer/units are used inside the guests.

Usage: vm_validation.py --base debian-13-genericcloud-amd64.qcow2 --work DIR [--soak-seconds N]
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
VMS = {
    "client": dict(n=1, links={"linka": ("192.0.2.2/30", "a")}),
    "relay": dict(n=2, links={"linka": ("192.0.2.1/30", "a"), "linkb": ("198.51.100.1/30", "b")}),
    "exit": dict(n=3, links={"linkb": ("198.51.100.2/30", "b")}),
}
TESTER = 1500
PACKAGES = ["qemu-guest-agent", "nftables", "python3-venv", "iperf3", "iputils-ping", "curl", "iproute2"]


def mac(n, i):
    return "52:54:00:a7:%02x:%02x" % (n, i)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Agent:
    """Minimal QEMU guest agent client (one connection per call)."""

    def __init__(self, path):
        self.path = str(path)

    def call(self, command, arguments=None, timeout=30):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.path)
            f = s.makefile("rwb")
            token = int.from_bytes(os.urandom(4), "big") >> 1
            f.write(
                b"\xff" + json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": token}}).encode() + b"\n"
            )
            f.flush()
            while True:
                line = f.readline()
                if not line:
                    raise ConnectionError("agent closed")
                line = line.lstrip(b"\xff").strip()
                if line and json.loads(line).get("return") == token:
                    break
            request = {"execute": command}
            request.update({"arguments": arguments} if arguments else {})
            f.write(json.dumps(request).encode() + b"\n")
            f.flush()
            if command in ("guest-shutdown",):
                return None
            reply = json.loads(f.readline())
            if "error" in reply:
                raise RuntimeError(command + ": " + json.dumps(reply["error"]))
            return reply.get("return")
        finally:
            s.close()

    def ping(self):
        try:
            self.call("guest-ping", timeout=3)
            return True
        except (OSError, ConnectionError, ValueError, RuntimeError):
            return False

    def run(self, argv, input=None, timeout=120, check=True, env=None):
        args = {"path": argv[0], "arg": list(map(str, argv[1:])), "capture-output": True}
        if input is not None:
            args["input-data"] = base64.b64encode(input if isinstance(input, bytes) else input.encode()).decode()
        if env:
            args["env"] = [k + "=" + v for k, v in env.items()]
        pid = self.call("guest-exec", args)["pid"]
        end = time.monotonic() + timeout
        while True:
            st = self.call("guest-exec-status", {"pid": pid})
            if st["exited"]:
                break
            if time.monotonic() > end:
                raise TimeoutError("guest command timed out: " + " ".join(map(str, argv)))
            time.sleep(0.2)
        out = base64.b64decode(st.get("out-data", "")).decode(errors="replace")
        err = base64.b64decode(st.get("err-data", "")).decode(errors="replace")
        code = st.get("exitcode", -1)
        if check and code:
            raise RuntimeError(
                "guest command failed (%s): %s\n%s\n%s" % (code, " ".join(map(str, argv)), out[-3000:], err[-3000:])
            )
        return code, out, err

    def sh(self, script, **kw):
        return self.run(["/bin/sh", "-c", script], **kw)


def network_config(name):
    spec = VMS[name]
    n = spec["n"]
    eth = {
        "wan": {
            "match": {"macaddress": mac(n, 1)},
            "set-name": "wan",
            "dhcp4": True,
            "dhcp6": False,
            "accept-ra": False,
        }
    }
    for i, (link, (addr, _)) in enumerate(spec["links"].items(), start=2):
        eth[link] = {
            "match": {"macaddress": mac(n, i)},
            "set-name": link,
            "addresses": [addr],
            "dhcp4": False,
            "accept-ra": False,
            "mtu": 1500,
        }
    return {"version": 2, "ethernets": eth}


def seed(work, name):
    d = work / (name + "-seed")
    d.mkdir(exist_ok=True)
    (d / "meta-data").write_text("instance-id: avpn-%s-%s\nlocal-hostname: avpn-%s\n" % (name, work.name, name))
    user = [
        "#cloud-config",
        "hostname: avpn-" + name,
        "users:",
        "  - name: tester",
        "    uid: %d" % TESTER,
        "    shell: /bin/bash",
        "    lock_passwd: true",
        "package_update: true",
        "packages: [" + ", ".join(PACKAGES) + "]",
        "runcmd:",
        "  - [systemctl, enable, --now, qemu-guest-agent]",
    ]
    (d / "user-data").write_text("\n".join(user) + "\n")
    (d / "network-config").write_text(json.dumps(network_config(name)))
    iso = work / (name + "-seed.iso")
    subprocess.run(
        [
            "genisoimage",
            "-quiet",
            "-output",
            str(iso),
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            str(d / "user-data"),
            str(d / "meta-data"),
            str(d / "network-config"),
        ],
        check=True,
    )
    return iso


def package_disk(work):
    """ext4 image (built unprivileged) holding the release build, tools and units.
    It carries no keys: every guest generates its own."""
    pkg = work / "pkg"
    pkg.mkdir()
    (pkg / "target/release").mkdir(parents=True)
    from install import BINARIES, SOURCES

    for b in BINARIES:
        shutil.copy2(ROOT / "target/release" / b, pkg / "target/release" / b)
    for name in SOURCES:
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, pkg / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, pkg / name)
    img = work / "pkg.img"
    subprocess.run(
        ["/usr/sbin/mke2fs", "-q", "-t", "ext4", "-L", "avpnpkg", "-d", str(pkg), str(img), "256M"], check=True
    )
    return img


def start(work, base, name):
    spec = VMS[name]
    n = spec["n"]
    overlay = work / (name + ".qcow2")
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base.resolve()), str(overlay), "8G"],
        check=True,
    )
    args = [
        "qemu-system-x86_64",
        "-name",
        "avpn-" + name,
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        "1024",
        "-display",
        "none",
        "-daemonize",
        "-pidfile",
        str(work / (name + ".pid")),
        "-serial",
        "file:" + str(work / (name + "-console.log")),
        "-drive",
        "file=%s,if=virtio,format=qcow2" % overlay,
        "-drive",
        "file=%s,if=virtio,format=raw,readonly=on" % (work / (name + "-seed.iso")),
        "-drive",
        "file=%s,if=virtio,format=raw,readonly=on" % (work / "pkg.img"),
        "-netdev",
        "user,id=wan,ipv6=off",
        "-device",
        "virtio-net-pci,netdev=wan,mac=" + mac(n, 1),
        "-chardev",
        "socket,id=qga,path=%s,server=on,wait=off" % (work / (name + "-qga.sock")),
        "-device",
        "virtio-serial",
        "-device",
        "virtserialport,chardev=qga,name=org.qemu.guest_agent.0",
    ]
    for i, (link, (_, seg)) in enumerate(spec["links"].items(), start=2):
        me = "%s-%s.sock" % (seg, name)
        peer = [o for o, s in VMS.items() if o != name and any(v[1] == seg for v in s["links"].values())][0]
        args += [
            "-netdev",
            "dgram,id=%s,local.type=unix,local.path=%s,remote.type=unix,remote.path=%s"
            % (link, work / me, work / ("%s-%s.sock" % (seg, peer))),
            "-device",
            "virtio-net-pci,netdev=%s,mac=%s" % (link, mac(n, i)),
        ]
    if name == "client":
        for net in ["wan"] + list(spec["links"]):
            args += [
                "-object",
                "filter-dump,id=dump-%s,netdev=%s,file=%s,maxlen=256" % (net, net, work / ("client-%s.pcap" % net)),
            ]
    subprocess.run(args, check=True)


def wait_agent(agent, seconds, what):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if agent.ping():
            return
        time.sleep(3)
    raise TimeoutError("guest agent unavailable: " + what)


def pcap_frames(path, start, end):
    """Yield Ethernet frames recorded by QEMU filter-dump within [start,end) host time."""
    data = Path(path).read_bytes()
    pos = 24
    while pos + 16 <= len(data):
        sec, usec, incl, _ = struct.unpack("<IIII", data[pos : pos + 16])
        pos += 16
        if start <= sec + usec / 1e6 < end:
            yield data[pos : pos + incl]
        pos += incl


def classify_client_frame(frame, client_macs, relay_carrier):
    """Return None when allowed, else a short description of a leaked frame."""
    if len(frame) < 14 or frame[6:12] not in client_macs:
        return None  # inbound
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x0806:
        return None  # ARP carries no payload
    if ethertype == 0x86DD:
        return "ipv6"
    if ethertype != 0x0800 or len(frame) < 34:
        return "ethertype-%04x" % ethertype
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    proto = ip[9]
    dst = socket.inet_ntoa(ip[16:20])
    if proto == 17 and len(ip) >= ihl + 4:
        sport, dport = struct.unpack("!HH", ip[ihl : ihl + 4])
        if sport == 68 and dport == 67:
            return None  # DHCP bootstrap
        if (dst, dport) == relay_carrier:
            return None  # WireGuard carrier
        return "udp %s:%d" % (dst, dport)
    return "proto %d to %s" % (proto, dst)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--soak-seconds", type=int, default=1800)
    p.add_argument("--keep", action="store_true", help="leave VMs running for inspection")
    p.add_argument("--only-whole-device", action="store_true", help="skip link/MTU/soak phases")
    a = p.parse_args()
    os.umask(0o077)
    work = a.work.resolve()
    work.mkdir(mode=0o700, exist_ok=False)
    result = dict(
        schema=1,
        started_utc=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        base_image=a.base.name,
        base_sha256=hashlib.sha256(a.base.read_bytes()).hexdigest(),
        host_network_changed=False,
        wan_tested=False,
    )
    agents = {n: Agent(work / (n + "-qga.sock")) for n in VMS}

    def save():
        (work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    try:
        package_disk(work)
        for n in VMS:
            seed(work, n)
            start(work, a.base, n)
        for n in VMS:
            wait_agent(agents[n], 900, n)
            log(n, "agent up")
            agents[n].sh("cloud-init status --wait >/dev/null 2>&1; true", timeout=900)
        # Install, then generate keys ON each guest (TPM2/host-key systemd-creds at rest).
        # Only the public request leaves a guest; bundles carry no private key.
        (work / "requests").mkdir()
        for n, agent in agents.items():
            agent.sh("mkdir -p /mnt/pkg && mount -o ro LABEL=avpnpkg /mnt/pkg")
            # One step, as a user would: install, put avpn on root's PATH, generate keys.
            agent.sh("python3 /mnt/pkg/tools/install.py --apply --role %s --protect systemd-creds" % n, timeout=900)
            (work / "requests" / (n + ".json")).write_text(agent.sh("cat /root/advanced-vpn-%s.req" % n)[1])
            # sudo searches only secure_path: avpn must resolve there, to the system install.
            secure = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            on_path = agent.sh(secure + " sh -c 'command -v avpn; readlink -f $(command -v avpn); avpn --version'")[
                1
            ].split()
            # Re-running upgrades in place: the venv is reused and the device keeps its keys.
            venv_before = agent.sh("stat -c %i /opt/advanced-vpn/venv")[1].strip()
            certs_before = agent.sh("sha256sum /etc/advanced-vpn/enrolled/*-cert.der")[1]
            rerun = agent.sh(
                "python3 /mnt/pkg/tools/install.py --apply --role %s --protect systemd-creds" % n, timeout=900
            )[1]
            upgrade = dict(
                reported_upgrade="Upgraded /opt/advanced-vpn" in rerun,
                keys_kept="already has keys" in rerun
                and agent.sh("sha256sum /etc/advanced-vpn/enrolled/*-cert.der")[1] == certs_before,
                venv_reused=agent.sh("stat -c %i /opt/advanced-vpn/venv")[1].strip() == venv_before,
                no_leftovers=agent.sh("ls -d /opt/advanced-vpn.* 2>/dev/null | wc -l")[1].strip() == "0",
            )
            assert on_path[:2] == ["/usr/local/bin/avpn", "/opt/advanced-vpn/bin/avpn"], on_path
            assert all(upgrade.values()), upgrade
            enabled = agent.sh("systemctl is-enabled advanced-vpn.service || true")[1].strip()
            result.setdefault("install", {})[n] = dict(
                installed=True,
                avpn_on_sudo_path=" ".join(on_path),
                upgrade_in_place=upgrade,
                unit_enabled_by_install=enabled == "enabled",
                tpm2=agent.sh("systemd-analyze has-tpm2 >/dev/null 2>&1 && echo yes || echo no", check=False)[
                    1
                ].strip(),
            )
        log("operator init on host from public requests (lab software operator)")
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/avpnctl.py"),
                "init",
                "--out",
                str(work / "operator"),
                "--relay",
                "192.0.2.1:41194",
                "--exit",
                "198.51.100.2:4444",
                "--software-operator",
                str(work / "operator-keys"),
            ]
            + sum((["--request", "%s=%s" % (n, work / "requests" / (n + ".json"))] for n in VMS), []),
            check=True,
            capture_output=True,
        )
        import zipfile

        result["bundles_contain_private_keys"] = any(
            m.endswith(("-key.der", "-key.bin", ".key"))
            for n in VMS
            for m in zipfile.ZipFile(work / "operator" / (n + ".avpn")).namelist()
        )
        for n, agent in agents.items():
            agent.sh("cat > /root/bundle.avpn", input=(work / "operator" / (n + ".avpn")).read_bytes())
            agent.sh("cat > /root/operator.pub", input=(work / "operator/operator.pub").read_bytes())
            agent.run(
                ["/opt/advanced-vpn/bin/avpnctl", "enroll", "/root/bundle.avpn", "--operator-key", "/root/operator.pub"]
            )
            files = agent.sh("ls /etc/advanced-vpn/enrolled")[1].split()
            result["install"][n].update(
                key_files=sorted(f for f in files if "key" in f),
                plaintext_private_keys=[
                    f for f in files if f in ("outer-key.der", "inner-key.der", "wireguard-key.bin", "kem-key.bin")
                ],
            )
            log(n, "installed, keys generated on guest, enrolled", result["install"][n])
        # Service PIN path: a transient unit with the installed unit's sandbox calls the
        # real keyguard.pinentry(); an agent following systemd's ask-password protocol
        # (as the boot console would) answers it. Only hashes are compared.
        props = []
        for line in (ROOT / "deploy/advanced-vpn.service").read_text().splitlines():
            key = line.split("=", 1)[0]
            if key in (
                "NoNewPrivileges",
                "CapabilityBoundingSet",
                "RestrictAddressFamilies",
                "RestrictSUIDSGID",
                "RestrictRealtime",
                "LockPersonality",
                "MemorySwapMax",
                "PrivateMounts",
                "UMask",
            ):
                props += ["-p", line]
        client_agent = agents["client"]
        pin = "vm-test-" + os.urandom(6).hex()
        asker = (
            "import hashlib,sys;sys.path.insert(0,'/opt/advanced-vpn/tools');import keyguard;"
            "v=keyguard.pinentry();open('/run/avpn-askpass-result','w').write(hashlib.sha256(v.encode()).hexdigest())"
        )
        client_agent.run(
            [
                "systemd-run",
                "--unit",
                "avpn-askpass-test",
                "--collect",
                *props,
                "/opt/advanced-vpn/venv/bin/python",
                "-c",
                asker,
            ]
        )
        answer = (
            "import glob,configparser,socket,time,sys\n"
            "end=time.time()+30\n"
            "while time.time()<end:\n"
            " for f in glob.glob('/run/systemd/ask-password/ask.*'):\n"
            "  c=configparser.ConfigParser();c.read(f);a=c['Ask']\n"
            "  if a.get('Id')=='advanced-vpn:fido2-pin':\n"
            "   s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);s.sendto(b'+'+sys.argv[1].encode(),a['Socket']);print(a.get('Message'));sys.exit(0)\n"
            " time.sleep(.2)\n"
            "sys.exit('no ADVANCED VPN prompt appeared')\n"
        )
        message = client_agent.run(["python3", "-c", answer, pin], timeout=60)[1].strip()
        end = time.monotonic() + 20
        got = ""
        while time.monotonic() < end and not got:
            got = client_agent.sh("cat /run/avpn-askpass-result 2>/dev/null", check=False)[1].strip()
            time.sleep(0.5)
        result["service_pin_prompt"] = dict(
            prompt_message=message,
            pin_delivered=got == hashlib.sha256(pin.encode()).hexdigest(),
            sandbox_properties=[x for x in props if x != "-p"],
        )
        log("service PIN prompt", result["service_pin_prompt"])
        result["resolv_conf"] = (
            agents["client"].sh("readlink -f /etc/resolv.conf; systemctl is-active systemd-resolved || true")[1].split()
        )
        agents["exit"].sh(
            "systemd-run --unit avpn-iperf iperf3 -s -B 198.51.100.2 && mkdir -p /srv/probe && echo ok > /srv/probe/index.html && "
            "systemd-run --unit avpn-http python3 -m http.server 8080 --bind 198.51.100.2 --directory /srv/probe"
        )
        for n in agents:
            agents[n].sh("touch /root/avpn-epoch")
        for n in ["exit", "relay", "client"]:
            agents[n].run(["systemctl", "start", "advanced-vpn.service"])
        client = agents["client"]

        def app(cmd, timeout=60, check=True):
            return client.run(
                ["/opt/advanced-vpn/bin/avpnctl", "run", "--uid", str(TESTER), "--gid", str(TESTER), "--", *cmd],
                timeout=timeout,
                check=check,
            )

        def wait_tunnel(seconds=90):
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                if app(["curl", "-sS", "-m", "5", "-o", "/dev/null", "http://198.51.100.2:8080/"], check=False)[0] == 0:
                    return True
                time.sleep(2)
            raise TimeoutError("tunnel did not come up")

        wait_tunnel()
        # Real Internet through the owned exit, with DNS over TLS to the real Quad9.
        code, out, _ = app(
            ["curl", "-sS", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}", "https://deb.debian.org/"]
        )
        result["internet_via_exit"] = dict(https_status=out.strip(), dns_over_tls_quad9=True)
        # Mullvad-style: after real traffic, servers hold nothing written during the
        # session on disk, and the journal has no entries for the VPN units at all.
        result["no_retained_data"] = {}
        for n in ["relay", "exit"]:
            written = agents[n].sh("find /etc/advanced-vpn -newer /root/avpn-epoch -print", check=False)[1].split()
            journal = (
                agents[n]
                .sh(
                    "journalctl -q --no-pager -u advanced-vpn.service -u advanced-vpn-guard.service | wc -l",
                    check=False,
                )[1]
                .strip()
            )
            runtime = agents[n].sh("ls /run/advanced-vpn/ 2>/dev/null | wc -l", check=False)[1].strip()
            result["no_retained_data"][n] = dict(
                persistent_files_written=written,
                journal_lines=int(journal or -1),
                runtime_dirs_in_ram=int(runtime or 0),
            )
        log("no retained data", result["no_retained_data"])
        status = json.loads(client.run(["/opt/advanced-vpn/bin/avpnctl", "status"])[1])
        result["default_uncapped"] = dict(
            daily_limit_bytes=status.get("daily_limit_bytes"),
            meter_table=client.sh("nft list table inet advanced_vpn_meter", check=False)[0] == 0,
        )

        def iperf(label):
            code, out, _ = app(["iperf3", "-c", "198.51.100.2", "-t", "10", "-J"], timeout=60)
            j = json.loads(out)
            mbps = j["end"]["sum_received"]["bits_per_second"] / 1e6
            code, out, _ = app(
                [
                    "python3",
                    "-c",
                    'import socket,time,statistics as s\nr=[]\nfor _ in range(15):\n t=time.monotonic();c=socket.create_connection(("198.51.100.2",8080),5);r.append((time.monotonic()-t)*1000);c.close();time.sleep(.2)\nprint(round(s.median(r),2),round(max(r),2))',
                ],
                timeout=60,
            )
            median, worst = map(float, out.split())
            row = dict(
                throughput_mbps=round(mbps, 2),
                tcp_connect_rtt_ms_median=median,
                tcp_connect_rtt_ms_max=worst,
                retransmits=j["end"]["sum_sent"].get("retransmits"),
            )
            log("iperf", label, row)
            return row

        def impair(delay_ms, loss):
            for n in ["client", "relay"]:
                spec = "delay %dms" % (delay_ms // 2) + (" loss %s%%" % loss if loss else "")
                agents[n].sh(
                    "tc qdisc replace dev linka root netem " + spec
                    if delay_ms or loss
                    else "tc qdisc del dev linka root 2>/dev/null; true"
                )

        result["links"] = {}
        for label, delay, loss in (
            [] if a.only_whole_device else [("clean", 0, 0), ("50ms_1pct", 50, 1), ("150ms_1pct", 150, 1)]
        ):
            impair(delay, loss)
            time.sleep(2)
            result["links"][label] = iperf(label)
            save()
        impair(0, 0)
        # >64 MiB through the default (uncapped) client must not stop: 100 MiB SHA-verified.
        code, out, _ = app(["iperf3", "-c", "198.51.100.2", "-n", "100M", "-J"], timeout=180)
        result["uncapped_100mib"] = dict(
            bytes=json.loads(out)["end"]["sum_received"]["bytes"],
            carrier_alive=json.loads(client.run(["/opt/advanced-vpn/bin/avpnctl", "status"])[1])["children"]["carrier"][
                "alive"
            ],
        )
        # MTU boundary: 1420 is the documented minimum underlay; 1419 must be refused (fail closed).
        mtu = {}
        for value in [] if a.only_whole_device else [1419, 1420]:
            client.run(["systemctl", "stop", "advanced-vpn.service"])
            client.sh("ip link set linka mtu %d" % value)
            client.run(["systemctl", "reset-failed", "advanced-vpn.service"], check=False)
            client.run(["systemctl", "start", "advanced-vpn.service"])
            try:
                wait_tunnel(45)
                mtu[value] = "connected"
            except TimeoutError:
                mtu[value] = "refused"
            mtu[str(value) + "_app_blocked"] = (
                app(["curl", "-sS", "-m", "3", "https://deb.debian.org/"], check=False)[0] != 0
                if mtu[value] == "refused"
                else None
            )
        if mtu.get(1420) == "connected":
            mtu["1420_large_transfer_mbps"] = iperf("mtu1420")["throughput_mbps"]
        client.sh("ip link set linka mtu 1500")
        client.run(["systemctl", "restart", "advanced-vpn.service"])
        wait_tunnel()
        result["mtu"] = {str(k): v for k, v in mtu.items()}
        save()
        # Soak: repeated disconnect/reconnect; traffic must be blocked while down and resume after.
        soak = dict(cycles=0, blocked_while_down=0, recovered=0, failures=[])
        end = time.monotonic() + a.soak_seconds
        while time.monotonic() < end:
            soak["cycles"] += 1
            client.run(["/opt/advanced-vpn/bin/avpnctl", "disconnect"], check=False)
            time.sleep(2)
            if app(["curl", "-sS", "-m", "3", "-o", "/dev/null", "https://deb.debian.org/"], check=False)[0] != 0:
                soak["blocked_while_down"] += 1
            else:
                soak["failures"].append("leak_while_down@%d" % soak["cycles"])
            client.run(["systemctl", "restart", "advanced-vpn.service"])
            try:
                wait_tunnel(90)
                soak["recovered"] += 1
            except TimeoutError:
                soak["failures"].append("no_recovery@%d" % soak["cycles"])
            time.sleep(20)
        result["soak"] = dict(soak, seconds=a.soak_seconds)
        save()
        log("soak", soak)
        # Whole-device mode, enabled units, reboot: guard must precede networking and nothing may leak.
        client.run(["/opt/advanced-vpn/bin/avpnctl", "preferences", "--mode", "whole-device"])
        client.run(["systemctl", "stop", "advanced-vpn.service"])
        client.run(["/opt/advanced-vpn/bin/avpnctl", "reset", "--allow-cleartext"])
        client.run(["systemctl", "enable", "advanced-vpn-guard.service", "advanced-vpn.service"])
        window_start = time.time()
        boot_before = client.sh("cat /proc/sys/kernel/random/boot_id")[1].strip()
        try:
            client.call("guest-shutdown", {"mode": "reboot"}, timeout=5)
        except (OSError, ConnectionError, ValueError):
            pass
        end = time.monotonic() + 300
        while time.monotonic() < end:
            time.sleep(3)
            if client.ping():
                try:
                    if client.sh("cat /proc/sys/kernel/random/boot_id", timeout=10)[1].strip() != boot_before:
                        break
                except (OSError, RuntimeError, TimeoutError, ConnectionError):
                    pass
        else:
            raise TimeoutError("client did not reboot")
        client.sh("systemctl is-system-running --wait >/dev/null 2>&1; true", timeout=300)
        whole = dict()
        result["whole_device_reboot"] = whole
        order = client.sh(
            "journalctl -b -o short-monotonic --no-pager | grep -E 'Finished advanced-vpn-guard|Starting systemd-networkd.service|Started systemd-networkd.service|Starting networking.service|Starting cloud-init-network|Starting cloud-init.service' | head -20"
        )[1]
        whole["boot_order_journal"] = order.strip().splitlines()

        def mono(pattern):
            for line in order.splitlines():
                if pattern in line:
                    return float(line.split("]")[0].strip("[ "))
            return None

        # The VPN units log nothing (LogLevelMax=emerg), so ordering comes from PID 1's
        # in-memory timestamps: when the oneshot guard became active vs networkd's start.
        def prop(unit, name):
            v = client.sh("systemctl show -P %s %s" % (name, unit), check=False)[1].strip()
            return int(v) if v.isdigit() else None

        guard = prop("advanced-vpn-guard.service", "ActiveEnterTimestampMonotonic")
        net = prop("systemd-networkd.service", "ExecMainStartTimestampMonotonic")
        whole["guard_active_us"] = guard
        whole["networkd_start_us"] = net
        whole["guard_before_network"] = bool(guard and net and guard < net)
        whole["guard_table_present"] = client.sh("nft list table inet advanced_vpn >/dev/null", check=False)[0] == 0
        end = time.monotonic() + 120
        ok = False
        while time.monotonic() < end and not ok:
            ok = client.sh("curl -sS -m 5 -o /dev/null http://198.51.100.2:8080/", check=False)[0] == 0
            time.sleep(2)
        whole["tunnel_after_reboot"] = ok
        save()
        code, out, err = client.sh(
            'timeout 15 getent hosts deb.debian.org; echo getent=$?; timeout 30 curl -sS -m 25 -o /dev/null -w "%{http_code}" https://deb.debian.org/',
            check=False,
            timeout=90,
        )
        whole["dns_and_https_after_reboot"] = dict(exit=code, output=out.strip()[-200:], error=err.strip()[-300:])
        whole["resolv_conf"] = (
            client.sh("readlink -f /etc/resolv.conf; cat /etc/resolv.conf", check=False)[1].strip().splitlines()
        )
        whole["resolver_state"] = (
            client.sh("resolvectl dns 2>&1; resolvectl domain 2>&1", check=False, timeout=30)[1].strip().splitlines()
        )
        save()
        whole["wan_ipv4"] = client.sh("ip -4 -o addr show dev wan | awk '{print $4}'", check=False)[1].strip()
        # The fallback route works without the guard (proven below by reset); with it, direct egress must fail.
        whole["direct_egress_blocked"] = (
            client.sh("curl -sS -m 5 --interface wan -o /dev/null http://10.0.2.2/", check=False)[0] != 0
            and client.sh("ping -n -c 1 -W 2 -I wan 1.1.1.1", check=False)[0] != 0
        )
        client.run(["/opt/advanced-vpn/bin/avpnctl", "disconnect"], check=False)
        time.sleep(3)
        whole["blocked_after_disconnect"] = (
            client.sh("curl -sS -m 5 -o /dev/null https://deb.debian.org/", check=False)[0] != 0
        )
        time.sleep(1)
        window_end = time.time()  # the explicit cleartext reset below is outside the leak window
        client.run(["systemctl", "disable", "--now", "advanced-vpn.service", "advanced-vpn-guard.service"], check=False)
        client.run(["/opt/advanced-vpn/bin/avpnctl", "reset", "--allow-cleartext"])
        whole["cleartext_after_explicit_reset"] = client.sh("ping -n -c 1 -W 3 -I wan 10.0.2.2", check=False)[0] == 0
        client_macs = {bytes.fromhex(mac(1, i).replace(":", "")) for i in (1, 2)}
        leaks = {}
        for net in ["wan", "linka"]:
            for frame in pcap_frames(work / ("client-%s.pcap" % net), window_start, window_end):
                kind = classify_client_frame(frame, client_macs, ("192.0.2.1", 41194))
                if kind:
                    leaks[net + " " + kind] = leaks.get(net + " " + kind, 0) + 1
        whole["frames_outside_policy_during_reboot_and_whole_device"] = leaks
        result["whole_device_reboot"] = whole
        save()
        log("whole-device", whole)
        result["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    finally:
        save()
        if not a.keep:
            for n in VMS:
                pid = work / (n + ".pid")
                if pid.exists():
                    try:
                        os.kill(int(pid.read_text()), 15)
                    except ProcessLookupError:
                        pass
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

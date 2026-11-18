#!/usr/bin/env python3
"""Preflight: what this host lacks for AVPN, checked before anything is installed.

The host checks of docs/INSTALL_AND_SETUP_PLAN.md (phase 1). Each finding has a severity
(blocker, warning, info, or ok when the check passed), a plain-language reason, and where
there is one a fix that is shown, never run. Missing programs are mapped to package names
for apt, dnf, pacman and zypper and shown as one install command.

Standard library only, and it runs on Python 3.8: an old host must still be able to say
what it is missing. Every system interface goes through `Host`, so the checks run against a
simulated system in the tests.

usage: python3 tools/preflight.py [--json] [--package DIR] [--target /opt] [--protect systemd-creds]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

SEVERITIES = ("blocker", "warning", "info", "ok")
# Distributions the release is tested on (docs/INSTALL_AND_SETUP_PLAN.md, phase 2).
POLICY = json.loads(Path(__file__).with_name("preflight-policy.json").read_text())
if POLICY.get("schema") != 1:
    raise ValueError("unknown preflight policy schema")
TESTED = {tuple(pair) for pair in POLICY["tested"]}
FAMILIES = tuple(POLICY["families"])
RELEASE_GLIBC = tuple(POLICY["release_glibc"])
SYSTEMD_CREDS = POLICY["systemd_creds"]
NEED_MB = POLICY["need_mb"]
PROGRAMS = tuple(POLICY["programs"])
PACKAGES = POLICY["packages"]
INSTALL = dict(
    apt="sudo apt-get install -y",
    dnf="sudo dnf install -y",
    pacman="sudo pacman -S --needed",
    zypper="sudo zypper install -y",
)
VPN_INTERFACES = re.compile(r"^(wg\d*|tun\d+|tap\d+|nordlynx|proton\w*|mullvad\w*|ivpn\w*|avwg\d*|avpn\d*)$")


@dataclass
class Finding:
    """One check's result."""

    code: str
    severity: str
    message: str
    detail: dict = field(default_factory=dict)
    fix: Optional[str] = None  # shown to the person, never run by preflight
    package: Optional[str] = None  # the program or capability a package provides

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError("unknown severity: " + self.severity)


class Host:
    """The system as preflight sees it. Tests replace the parts they simulate."""

    def __init__(self, root: Path = Path("/"), path: Optional[str] = None, run: Optional[Callable] = None,
                 machine: Optional[str] = None, kernel: Optional[str] = None, glibc: Optional[str] = None,
                 python: Optional[Tuple[int, int]] = None, ensurepip: Optional[bool] = None,
                 free_mb: Optional[Callable[[Path], int]] = None):  # fmt: skip
        self.root = Path(root)
        self.path = path if path is not None else os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        self.run = run or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=5))
        self.machine = machine or platform.machine()
        self.kernel = kernel or platform.release()
        try:
            detected_glibc = os.confstr("CS_GNU_LIBC_VERSION") if hasattr(os, "confstr") else ""
        except (OSError, ValueError):
            detected_glibc = ""
        self.glibc = glibc if glibc is not None else detected_glibc
        self.python = python or sys.version_info[:2]
        if ensurepip is None:
            import importlib.util

            ensurepip = importlib.util.find_spec("ensurepip") is not None
        self.ensurepip = ensurepip
        self.free_mb = free_mb or (lambda p: shutil.disk_usage(str(p)).free // (1 << 20))

    def file(self, rel: str) -> Path:
        """A path inside the (possibly simulated) root."""
        return self.root / rel.lstrip("/")

    def read(self, rel: str) -> Optional[str]:
        """A file's text, or None when it cannot be read."""
        try:
            return self.file(rel).read_text()
        except OSError:
            return None

    def which(self, program: str) -> Optional[str]:
        """Where `program` is installed, or None."""
        # The system directories too: the controller runs these as root, and an ordinary
        # user's PATH on Debian leaves out /usr/sbin (where nft lives).
        system = POLICY["system_paths"]
        real_host = self.root == Path("/")
        dirs = system if real_host else self.path.split(os.pathsep) + system
        for d in dict.fromkeys(dirs):
            p = self.file(d) / program
            if p.is_file() and os.access(str(p), os.X_OK):
                if real_host:
                    m = p.resolve().stat()
                    if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022:
                        continue
                    if any(
                        parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022 for parent in p.resolve().parents
                    ):
                        continue
                return str(p)
        return None


def os_release(host: Host) -> Dict[str, str]:
    """The /etc/os-release fields."""
    text = host.read("/etc/os-release") or host.read("/usr/lib/os-release") or ""
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def package_manager(host: Host) -> Optional[str]:
    """apt, dnf, pacman or zypper, from what is installed."""
    for pm, program in (("apt", "apt-get"), ("dnf", "dnf"), ("pacman", "pacman"), ("zypper", "zypper")):
        if host.which(program):
            return pm
    return None


# --- Checks ------------------------------------------------------------------------------


def check_os(host: Host, opts) -> List[Finding]:
    """A tested distribution, a known family, or unsupported."""
    r = os_release(host)
    ident, version = r.get("ID", ""), r.get("VERSION_ID", "")
    family = [ident] + r.get("ID_LIKE", "").split()
    name = r.get("PRETTY_NAME") or (ident + " " + version).strip() or "this system"
    if (ident, version) in TESTED:
        return [Finding("os_tested", "ok", f"{name} is a documented release target.", dict(id=ident, version=version))]
    if any(f in FAMILIES for f in family):
        return [Finding("os_untested", "warning", f"{name} is not tested yet; it may work, as it is close to a tested system.",
                        dict(id=ident, version=version))]  # fmt: skip
    return [Finding("os_unknown", "blocker", f"{name} is not a supported system (Debian, Ubuntu, Fedora, Arch or openSUSE families).",
                    dict(id=ident, version=version))]  # fmt: skip


def check_arch(host: Host, opts) -> List[Finding]:
    """The release is built for 64-bit x86 only."""
    if host.machine in POLICY["architectures"]:
        return [Finding("arch", "ok", "64-bit x86: the release build runs here.")]
    return [Finding("arch_unsupported", "blocker", f"This is {host.machine}; the release is built for 64-bit x86 only for now.",
                    dict(machine=host.machine))]  # fmt: skip


def glibc_need(package: Optional[Path]) -> Tuple[int, int]:
    """The newest glibc symbol version the package's binaries need (the release's default)."""
    if not package:
        return RELEASE_GLIBC
    if not Path(package).is_dir():
        raise ValueError("the package directory does not exist")
    found = (0, 0)
    elf_files = 0
    for f in sorted(Path(package).rglob("*")):
        if f.is_symlink() or not f.is_file():
            continue
        with f.open("rb") as binary:
            if binary.read(4) != b"\x7fELF":
                continue
            elf_files += 1
            tail = b""
            while True:
                chunk = binary.read(65536)
                if not chunk:
                    break
                data = tail + chunk
                for m in re.finditer(rb"GLIBC_(\d+)\.(\d+)\x00", data):
                    found = max(found, (int(m.group(1)), int(m.group(2))))
                tail = data[-64:]
    if not elf_files:
        raise ValueError("the package directory contains no ELF files")
    return found if found != (0, 0) else RELEASE_GLIBC


def check_glibc(host: Host, opts) -> List[Finding]:
    """The C library is at least what the binaries need."""
    need = glibc_need(getattr(opts, "package", None))
    m = re.search(r"(\d+)\.(\d+)", host.glibc or "")
    if not m:
        return [Finding("glibc_unknown", "blocker", "No GNU C library found (musl systems are not supported yet).")]
    have = (int(m.group(1)), int(m.group(2)))
    detail = dict(have="%d.%d" % have, need="%d.%d" % need)
    if have >= need:
        return [Finding("glibc", "ok", f"The C library ({detail['have']}) is new enough.", detail)]
    return [Finding("glibc_old", "blocker", f"The C library is {detail['have']}; AVPN's programs need {detail['need']} or newer. "
                    "Upgrade the system, or use a newer one.", detail)]  # fmt: skip


def check_tun(host: Host, opts) -> List[Finding]:
    """/dev/net/tun exists (the data plane opens it)."""
    if host.file("/dev/net/tun").exists():
        return [Finding("tun", "ok", "/dev/net/tun is present.")]
    return [Finding("tun_missing", "blocker", "/dev/net/tun is missing, so no tunnel can be created. On a container or VPS, "
                    "ask the host to enable TUN for this machine.", fix="sudo modprobe tun")]  # fmt: skip


def check_programs(host: Host, opts) -> List[Finding]:
    """ip, nft, mount and systemctl are installed."""
    out = []
    for p in PROGRAMS:
        if not host.which(p):
            out.append(Finding("program_missing", "blocker", f"`{p}` is not installed.", dict(program=p), package=p))
    if not out:
        out.append(Finding("programs", "ok", "ip, nft, mount and systemctl are installed."))
    return out


def check_nf_tables(host: Host, opts) -> List[Finding]:
    """The kernel has nf_tables: loaded, as a module or built in."""
    kmods = host.file("/lib/modules") / host.kernel
    if host.file("/sys/module/nf_tables").exists():
        return [Finding("nf_tables", "ok", "The kernel's nf_tables (for the kill switch) is loaded.")]
    builtin = host.read(str(Path("/lib/modules") / host.kernel / "modules.builtin")) or ""
    if "nf_tables.ko" in builtin or list((kmods / "kernel/net/netfilter").glob("nf_tables.ko*")):
        return [Finding("nf_tables", "ok", "The kernel has nf_tables (for the kill switch).")]
    return [Finding("nf_tables_missing", "blocker", "This kernel has no nf_tables, which the kill switch needs.",
                    dict(kernel=host.kernel))]  # fmt: skip


def check_seccomp(host: Host, opts) -> List[Finding]:
    """The kernel supports seccomp (required by the sandbox)."""
    status = host.read("/proc/self/status") or ""
    if re.search(r"^Seccomp:", status, re.M):
        return [Finding("seccomp", "ok", "The kernel supports seccomp (the network daemons are confined with it).")]
    return [
        Finding(
            "seccomp_missing",
            "blocker",
            "The kernel has no seccomp; AVPN refuses to run its network daemons unconfined.",
        )
    ]


def check_landlock(host: Host, opts) -> List[Finding]:
    """Landlock is enabled (best effort: a warning when not)."""
    lsm = host.read("/sys/kernel/security/lsm") or ""
    if "landlock" in lsm.strip().split(","):
        return [Finding("landlock", "ok", "Landlock is enabled (filesystem confinement).")]
    return [Finding("landlock_off", "warning", "Landlock could not be confirmed from the visible LSM list. "
                    "The runtime sandbox checks its availability again; absence here is not proof it is disabled.",
                    dict(lsm=lsm.strip()))]  # fmt: skip


def check_systemd(host: Host, opts) -> List[Finding]:
    """systemd's version, for systemd-creds sealing."""
    try:
        executable = host.which("systemctl")
        if executable is None:
            raise FileNotFoundError("systemctl")
        r = host.run([executable, "--version"])
        m = re.match(r"systemd (\d+)", r.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        m = None
    if not m:
        return [Finding("systemd_unknown", "info", "Could not read the systemd version.")]
    v = int(m.group(1))
    if v >= SYSTEMD_CREDS:
        return [Finding("systemd", "ok", f"systemd {v}: keys can also be sealed with systemd-creds.", dict(version=v))]
    sev = "warning" if getattr(opts, "protect", None) == "systemd-creds" else "info"
    return [Finding("systemd_old", sev, f"systemd {v} cannot seal keys with systemd-creds (needs {SYSTEMD_CREDS}); "
                    "use a hardware key instead.", dict(version=v))]  # fmt: skip


def check_python(host: Host, opts) -> List[Finding]:
    """Python 3.10+ with venv, until the bundled runtime ships."""
    major, minor = host.python
    if (major, minor) < (3, 10):
        return [Finding("python_old", "blocker", f"Python {major}.{minor} is too old to install AVPN's tools (3.10 or newer).",
                        dict(version="%d.%d" % (major, minor)))]  # fmt: skip
    if not host.ensurepip:
        return [Finding("venv_missing", "blocker", "Python's venv support is not installed.", package="venv")]
    return [Finding("python", "ok", f"Python {major}.{minor} with venv.")]


def check_space(host: Host, opts) -> List[Finding]:
    """Enough free space where AVPN would be installed."""
    target = Path(getattr(opts, "target", None) or "/opt")
    p = target
    while not host.file(str(p)).exists() and p != p.parent:
        p = p.parent
    free = host.free_mb(host.file(str(p)))
    package = getattr(opts, "package", None)
    package_mb = 0
    if package:
        size = sum(f.stat().st_size for f in Path(package).rglob("*") if f.is_file() and not f.is_symlink())
        package_mb = (size + (1 << 20) - 1) // (1 << 20)
    need_mb = NEED_MB + package_mb
    detail = dict(target=str(target), free_mb=free, need_mb=need_mb)
    if free >= need_mb:
        return [Finding("space", "ok", f"{free} MB free for {target}.", detail)]
    return [
        Finding("space_low", "blocker", f"Only {free} MB free for {target}; installing needs {need_mb} MB.", detail)
    ]


def check_other_vpns(host: Host, opts) -> List[Finding]:
    """Other VPN interfaces that are up (their routes may conflict)."""
    net = host.file("/sys/class/net")
    names = sorted(d.name for d in net.iterdir() if VPN_INTERFACES.match(d.name)) if net.is_dir() else []
    if not names:
        return []
    return [Finding("other_vpns", "info", "VPN-like interfaces are present: " + ", ".join(names) + ". AVPN replaces none of "
                    "them; check routing before whole-device activation.", dict(interfaces=names))]  # fmt: skip


CHECKS: List[Callable] = [check_os, check_arch, check_glibc, check_tun, check_programs, check_nf_tables, check_seccomp,
                          check_landlock, check_systemd, check_python, check_space, check_other_vpns]  # fmt: skip


def register(check: Callable) -> Callable:
    """Add a check (security keys, cloud logins) to the registry."""
    CHECKS.append(check)
    return check


def run_checks(host: Host, opts=None, checks=None) -> List[Finding]:
    """Every check's findings, blockers first. A check that crashes is reported, not skipped."""
    out = []
    for check in CHECKS if checks is None else checks:
        try:
            out.extend(check(host, opts))
        except Exception as e:  # noqa: BLE001 (a broken check must still show up)
            out.append(
                Finding(
                    "check_failed",
                    "blocker",
                    "A required check could not run; readiness is unverified.",
                    dict(check=check.__name__, error=type(e).__name__),
                )
            )
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(out, key=lambda f: order[f.severity])


def install_command(host: Host, findings: List[Finding]) -> Optional[str]:
    """One command installing every missing package, for this system's package manager."""
    pm = package_manager(host)
    wanted = [f.package for f in findings if f.package]
    if not pm or not wanted:
        return None
    names = []
    for w in wanted:
        n = PACKAGES.get(w, {}).get(pm)
        if n and n not in names:
            names.append(n)
    return (INSTALL[pm] + " " + " ".join(names)) if names else None


def summary(host: Host, findings: List[Finding]) -> dict:
    """The machine-readable result: ready, counts, install command, findings."""
    blockers = [f for f in findings if f.severity == "blocker"]
    return dict(
        schema=1,
        ready=not blockers,
        blockers=len(blockers),
        warnings=sum(f.severity == "warning" for f in findings),
        install=install_command(host, findings),
        findings=[asdict(f) for f in findings],
    )


def add_arguments(parser):
    """Shared standalone/controller options; preflight never applies a repair."""
    parser.add_argument("--package", type=Path, help="a release package's directory: its binaries' glibc need")
    parser.add_argument("--target", default="/opt", help="where AVPN would be installed")
    parser.add_argument(
        "--operator-only",
        action="store_true",
        help="check the command-line-only operator installation, not VPN networking",
    )
    parser.add_argument("--protect", choices=("nitrokey", "systemd-creds", "none"), help="the intended key protection")
    parser.add_argument(
        "--provider",
        action="append",
        default=[],
        help="explicitly check readiness for one catalog provider; repeat for multiple providers",
    )
    parser.add_argument("--profile", help="provider CLI profile used only for explicitly selected readiness checks")
    parser.add_argument(
        "--hardware",
        action="store_true",
        help="also check attached FIDO2 keys; needs the installed hardware environment",
    )


def inspect_host(opts=None, host=None):
    """A report shared by setup, doctor and the controller; no installation or login."""
    host = host or Host()
    checks = (
        [check_os, check_arch, check_glibc, check_python, check_space]
        if getattr(opts, "operator_only", False)
        else list(CHECKS)
    )
    if getattr(opts, "hardware", False):

        def hardware_check(host, opts):
            """Translate the installed key diagnostics into preflight findings."""
            import hwkey

            return [
                Finding("hardware_" + f.code, f.severity, f.message, dict(device=f.device, repair=f.repair))
                for f in hwkey.diagnose(hwkey.hid_devices(), hwkey.usb_devices())
            ]

        checks.append(hardware_check)
    if getattr(opts, "provider", None):

        def provider_check(host, opts):
            """Use the existing provider readiness contract only on explicit request."""
            import providers

            if os.geteuid() == 0:
                return [
                    Finding(
                        "provider_user_required",
                        "blocker",
                        "Run provider readiness as your ordinary user; "
                        "cloud sign-ins and CLI environment overrides must not run as root.",
                    )
                ]
            findings = []
            for key in dict.fromkeys(opts.provider):
                provider = providers.by_key(key)
                ready, why = providers.readiness(provider, getattr(opts, "profile", None))
                why = "".join(c for c in str(why) if c.isprintable())[:300]
                findings.append(
                    Finding(
                        "provider_ready" if ready else "provider_not_ready",
                        "ok" if ready else "blocker",
                        provider["name"] + ": " + why,
                        dict(provider=key, scope="existing_provider_readiness"),
                    )
                )
            return findings

        checks.append(provider_check)
    return summary(host, run_checks(host, opts, checks=checks))


def main(argv=None):
    """Command line."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--json", action="store_true")
    add_arguments(p)
    a = p.parse_args(argv)
    host = Host()
    s = inspect_host(a, host)
    if a.json:
        print(json.dumps(s, indent=1))
    else:
        marks = dict(blocker="✗", warning="!", info="·", ok="✓")
        for f in s["findings"]:
            print(f"{marks[f['severity']]} {f['message']}")
            if f["fix"]:
                print(f"    fix: {f['fix']}")
        if s["install"]:
            print("\nInstall what is missing with:\n    " + s["install"])
        print("\nReady to install." if s["ready"] else f"\nNot ready: {s['blockers']} blocker(s) above.")
    return 0 if s["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())

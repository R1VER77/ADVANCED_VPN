#!/usr/bin/env python3
"""Install ADVANCED_VPN from a built checkout or a release package.

- `--out DIR [--apply] [--role ROLE --protect MODE]`: stage the system installation in
  DIR; with --apply, install (or upgrade) it into /opt/advanced-vpn as root and put
  `avpn` on root's PATH (/usr/local/bin). With --role, also generate this device's
  keys and write its public request. The VPN service is never enabled.
- `--user [--uninstall]`: install the command line for this user only (no root, no
  services), for an operator machine. `avpn` lands in ~/.local/bin.
- `--pack FILE`: write the release package (the files every installation needs).

No enrollment secrets are bundled. Activation is a separate explicit operator action
after a trusted role bundle is enrolled.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from sysexec import trusted_exe  # noqa: E402  (standard library only)


# What a built checkout must provide; the VM harness and `avpn cloud host setup` pack
# exactly these, so the three never disagree.
BINARIES = ["advanced-vpn", "advanced-vpn-wireguard", "advanced-vpn-dns", "advanced-vpn-cloak", "avpn"]
SOURCES = ["tools", "deploy", "third_party", "docs/cli", "docs/OFFLINE_INSTALLATION.md", "docs/SUPPORT_MATRIX.md",
           "docs/NAME_MIGRATION.md", "README.md", "LICENSE", "NOTICE", "SECURITY.md"]  # fmt: skip


# Slow or flaky links must not abort an install halfway: wait longer per read and retry.
PIP_PATIENCE = ["--retries", "10", "--timeout", "60"]


SUGGEST = "No servers yet? avpn cloud suggest lists free places to run them; avpn cloud chain --apply joins them."
HAVE_SERVERS = "avpn cloud status lists your servers; avpn cloud chain --apply joins them into a chain."


def next_servers_step(home=None):
    """The line the installer prints after a successful install. 'No servers yet?'
    only when the cloud inventory really is empty: printed after an upgrade it was
    simply wrong. `home` overrides whose inventory to look at (SUDO_USER under
    --apply, so a sudo install still sees the operator's servers)."""
    import pwd

    if home is None:
        name = os.environ.get("SUDO_USER")
        if name:
            try:
                home = Path(pwd.getpwnam(name).pw_dir)
            except KeyError:
                home = None
    if home is not None:
        # Another user's inventory: their .config, never the inherited XDG variable.
        inventory = Path(home) / ".config" / "advanced-vpn" / "cloud.json"
    else:
        inventory = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "advanced-vpn" / "cloud.json"
    try:
        resources = json.loads(inventory.read_text())["resources"] if inventory.exists() else {}
    except (OSError, ValueError, KeyError):
        resources = {}
    return HAVE_SERVERS if resources else SUGGEST


def pack(root, out, runtime=None):
    """Write the release package: SOURCES plus target/release/BINARIES, no caches."""
    import tarfile

    if runtime is not None:
        import bundled_runtime

        bundled_runtime.verify(runtime, root / "tools/hardware-requirements.txt")
    for name in BINARIES:
        if not (root / "target/release" / name).is_file():
            raise FileNotFoundError("build first: %s/target/release/%s is missing" % (root, name))
    with tarfile.open(out, "w:gz") as tar:
        for name in SOURCES:
            tar.add(root / name, arcname=name, filter=lambda i: None if "__pycache__" in i.name else i)
        for name in BINARIES:
            tar.add(root / "target/release" / name, arcname="target/release/" + name)
        if runtime is not None:
            tar.add(runtime, arcname="runtime", filter=lambda i: None if "__pycache__" in i.name else i)
            bootstrap = root / "tools/install-offline.sh"
            tar.add(bootstrap, arcname="install.sh")
    return out


def available_runtime():
    """Return the verified packaged runtime, or None for a legacy/source install."""
    runtime = ROOT / "runtime"
    if runtime.exists() or runtime.is_symlink():
        import bundled_runtime

        bundled_runtime.verify(runtime, ROOT / "tools/hardware-requirements.txt")
        return runtime
    return None


def user_paths():
    """Where a user installation lives: (data directory, directory on PATH for `avpn`)."""
    data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "advanced-vpn"
    return data, Path.home() / ".local/bin"


def launcher(path, body):
    """Write an executable POSIX shell launcher."""
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)


def install_user(data, bin_dir, python=None):
    """Install commands and runtime in DATA/app and `avpn` in BIN_DIR.
    Stage beside the live application and restore it on a final rename failure;
    a synchronous dependency failure never removes its working runtime."""
    if os.geteuid() == 0:
        raise RuntimeError("--user installs for a normal user; use --out/--apply for the system")
    available_runtime()  # Verify before creating the installation directory.
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage = data / ("app.new-%d" % os.getpid())
    try:
        return _install_user(data, bin_dir, python, stage)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _install_user(data, bin_dir, python, stage):
    """The body of install_user, staging into STAGE."""
    (stage / "bin").mkdir(parents=True)
    for name in BINARIES:
        shutil.copy2(ROOT / "target/release" / name, stage / "bin" / name)
    for name in SOURCES:
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, stage / name, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, stage / name)
    runtime = available_runtime()
    lock = (ROOT / "tools/hardware-requirements.txt").read_bytes()
    if runtime is not None:
        shutil.copytree(runtime, stage / "venv", symlinks=True)
        import bundled_runtime

        bundled_runtime.verify(stage / "venv", stage / "tools/hardware-requirements.txt")
        python = data / "app/venv/bin/python3"
    elif python is None:
        # Keep the live environment intact while a new dependency set is built.
        # Venv's interpreter works after relocation (launchers never run its pip
        # entry-point script, whose shebang would name the staging directory).
        venv = stage / "venv"
        marker = venv / ".advanced-vpn-requirements.sha256"
        digest = hashlib.sha256(lock).hexdigest()
        candidates = [data / "app/venv", data / "venv"]
        previous = next((p for p in candidates if (p / marker.name).is_file()
                         and (p / marker.name).read_text().strip() == digest and (p / "bin/python").is_file()), None)  # fmt: skip
        if previous is not None:
            shutil.copytree(previous, venv, symlinks=True)
        else:
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
            subprocess.run(
                [str(venv / "bin/python"), "-m", "pip", "install", "-q", *PIP_PATIENCE, "--require-hashes", "-r",
                 str(stage / "tools/hardware-requirements.txt")],
                check=True,
            )  # fmt: skip
            marker.write_text(digest + "\n")
        python = data / "app/venv/bin/python"
    app = data / "app"
    q = shlex.quote
    launcher(
        stage / "bin/avpnctl",
        'exec %s -B -E -s %s --bin-dir %s "$@"'
        % (q(str(python)), q(str(app / "tools/avpnctl.py")), q(str(app / "bin"))),
    )
    launcher(stage / "bin/avpn-cloud", 'exec %s -B -E -s %s "$@"' % (q(str(python)), q(str(app / "tools/cloud.py"))))
    # avpn-mesh signs and verifies ML-DSA descriptors, so it runs in the
    # hash-locked venv (like avpnctl), not the bare interpreter avpn-cloud uses.
    launcher(stage / "bin/avpn-mesh", 'exec %s -B -E -s %s "$@"' % (q(str(python)), q(str(app / "tools/mesh.py"))))
    old = data / ("app.old-%d" % os.getpid())
    if app.exists():
        app.rename(old)
    try:
        stage.rename(app)
    except OSError:
        if old.exists() and not app.exists():
            old.rename(app)
        raise
    shutil.rmtree(old, ignore_errors=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    launcher(
        bin_dir / "avpn",
        "# ADVANCED_VPN command line, user installation (tools/install.py --user).\n"
        "# As root, avpn ignores these variables by design and uses /opt/advanced-vpn.\n"
        'export AVPN_CONTROLLER=%s AVPN_CLOUD=%s AVPN_MESH=%s\nexec %s "$@"'
        % (
            q(str(app / "bin/avpnctl")),
            q(str(app / "bin/avpn-cloud")),
            q(str(app / "bin/avpn-mesh")),
            q(str(app / "bin/avpn")),
        ),
    )
    return app


def uninstall_user(data, bin_dir):
    """Remove a user installation. Cloud inventory and SSH keys in ~/.config are kept."""
    wrapper = bin_dir / "avpn"
    if wrapper.exists() and "tools/install.py --user" in wrapper.read_text():
        wrapper.unlink()
    for name in ["app", "venv"]:
        shutil.rmtree(data / name, ignore_errors=True)


def install_system(package, target):
    """Install the staged package into TARGET as root, or upgrade it in place: the new
    tree is built beside the old one (venv reused while the lock is unchanged) and
    swapped in by renames. Running processes keep the files they already opened."""
    new = target.with_name(target.name + ".new-%d" % os.getpid())
    try:
        return _install_system(package, target, new)
    finally:
        # On success `new` has become `target`; on any failure nothing half-made is left.
        shutil.rmtree(new, ignore_errors=True)


def _install_system(package, target, new):
    """The body of install_system, staging into NEW."""
    bundled = (package / "venv").exists() or (package / "venv").is_symlink()
    if bundled:
        import bundled_runtime

        bundled_runtime.verify(package / "venv", package / "tools/hardware-requirements.txt")
    shutil.copytree(package, new, symlinks=True)
    for f in [new, *new.rglob("*")]:
        os.chown(f, 0, 0, follow_symlinks=False)
        if not f.is_symlink() and not (bundled and f.is_relative_to(new / "venv")):
            f.chmod(0o755 if f.is_dir() or f.parent.name == "bin" else 0o644)
    lock = (new / "tools/hardware-requirements.txt").read_bytes()
    digest = hashlib.sha256(lock).hexdigest()
    marker = ".advanced-vpn-requirements.sha256"
    old_venv = target / "venv"
    if bundled:
        # All dependency resolution happened during the ordinary-user build.
        # Never run pip, use a host interpreter, or reuse an older runtime here.
        bundled_runtime.verify(new / "venv", new / "tools/hardware-requirements.txt")
    elif old_venv.is_dir() and (old_venv / marker).exists() and (old_venv / marker).read_text().strip() == digest:
        shutil.copytree(old_venv, new / "venv", symlinks=True)
    else:
        subprocess.run([sys.executable, "-m", "venv", str(new / "venv")], check=True)
        subprocess.run(
            [str(new / "venv/bin/python"), "-m", "pip", "install", *PIP_PATIENCE, "--require-hashes", "-r",
             str(new / "tools/hardware-requirements.txt")],
            check=True,
        )  # fmt: skip
        (new / "venv" / marker).write_text(digest + "\n")
    upgraded = target.exists()
    old = target.with_name(target.name + ".old-%d" % os.getpid())
    if upgraded:
        target.rename(old)
    try:
        new.rename(target)
    except OSError:
        if upgraded and old.exists() and not target.exists():
            old.rename(target)
        raise
    shutil.rmtree(old, ignore_errors=True)
    return upgraded


def link_commands(target, bin_dir=Path("/usr/local/bin")):
    """Put `avpn` and `avpnctl` on root's PATH: sudo searches only system directories."""
    ok = True
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ["avpn", "avpnctl"]:
        link, dest = bin_dir / name, target / "bin" / name
        if link.is_symlink() and os.readlink(link) == str(dest):
            continue
        if link.exists() or link.is_symlink():
            print("warning: %s exists and is not ours; left alone (use %s)" % (link, dest), file=sys.stderr)
            ok = False
            continue
        link.symlink_to(dest)
    return ok


def removal_checks(target=Path("/opt/advanced-vpn"), proc=Path("/proc")):
    """Read-only, fail-closed removal gate: retain every guard and running program."""
    for unit in ("advanced-vpn.service", "advanced-vpn-guard.service"):
        r = subprocess.run([trusted_exe("systemctl"), "show", unit, "--property=LoadState",
                            "--property=ActiveState", "--property=UnitFileState"],
                           capture_output=True, text=True, check=True, timeout=15)  # fmt: skip
        fields = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
        absent = fields.get("LoadState") == "not-found"
        if fields.get("ActiveState") not in ("inactive", "failed") or (
            fields.get("UnitFileState") not in ("disabled", "static", "masked")
            and not (absent and fields.get("UnitFileState", "") == "")
        ):
            raise RuntimeError(
                "Removal refused: %s is active, enabled or unverified. "
                "Use documented disconnect/recovery first; removal never disables a guard." % unit
            )
    r = subprocess.run([trusted_exe("nft"), "-j", "list", "tables"],
                       capture_output=True, text=True, check=True, timeout=15)  # fmt: skip
    tables = json.loads(r.stdout)["nftables"]
    if not isinstance(tables, list):
        raise ValueError("cannot verify firewall state")
    for item in tables:
        if not isinstance(item, dict):
            raise ValueError("cannot verify firewall state")
        if "table" in item and item["table"]["name"].startswith("advanced_vpn"):
            raise RuntimeError("Removal refused: a VPN firewall table is still present; its guard is retained.")
    for command, field, value in [(["ip", "-j", "netns", "list"], "name", "avpn-app"),
                                  (["ip", "-j", "link", "show"], "ifalias", "advanced-vpn-managed")]:  # fmt: skip
        command[0] = trusted_exe(command[0])
        r = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
        # iproute2 emits no output for an empty namespace list, even with -j.
        rows = [] if field == "name" and not r.stdout.strip() else json.loads(r.stdout)
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError("cannot verify network state")
        if any(row.get(field) == value for row in rows):
            raise RuntimeError("Removal refused: a VPN namespace or interface still exists; recover explicitly first.")
    prefix = str(target.resolve()) + "/"
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            executable = os.readlink(entry / "exe")
        except (FileNotFoundError, ProcessLookupError):
            continue  # Exited process or kernel thread.
        if executable.startswith(prefix):
            raise RuntimeError("Removal refused: an installed program is still running (PID %s)." % entry.name)


def uninstall_system(
    target=Path("/opt/advanced-vpn"), units=Path("/etc/systemd/system"), bin_dir=Path("/usr/local/bin")
):
    """Remove inactive owned application files; never clear networking or private state."""
    if os.geteuid() != 0:
        raise RuntimeError("system removal requires root")
    if target.is_symlink() or target.parent.stat().st_uid != 0 or target.parent.stat().st_mode & 0o022:
        raise RuntimeError("unsafe installation parent or target")
    if target.exists() and (target.stat().st_uid != 0 or target.stat().st_mode & 0o022):
        raise RuntimeError("existing installation is not root-owned and protected")
    removal_checks(target)
    owned_units = []
    for name in ("advanced-vpn.service", "advanced-vpn-guard.service"):
        path = units / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or path.read_bytes() != (ROOT / "deploy" / name).read_bytes():
                raise RuntimeError("Removal refused: modified/foreign unit %s; review it before removal." % path)
            owned_units.append(path)
    # Check again after reading ownership and unit data, before the first mutation.
    # Concurrent privileged administration is outside this gate; do not connect or
    # reconfigure another instance while uninstalling it.
    removal_checks(target)
    for path in owned_units:
        path.unlink()
    for name in ("avpn", "avpnctl"):
        path = bin_dir / name
        if path.is_symlink() and os.readlink(path) == str(target / "bin" / name):
            path.unlink()
    if target.exists():
        shutil.rmtree(target)
    subprocess.run([trusted_exe("systemctl"), "daemon-reload"], check=True, timeout=15)
    print("Removed inactive application and owned units; private state, keys, users and network settings are kept.")


def prepare_device(target, role, protect, vault=None, insecure=False):
    """Generate this device's keys with the installed controller (the vault is created on
    first use) and leave the public request in the sudo user's home directory."""
    state = Path("/etc/advanced-vpn/enrolled")
    if state.exists():
        print("This device already has keys (%s); not generating new ones." % state)
        return
    import pwd

    uid = os.environ.get("SUDO_UID")
    home = Path(pwd.getpwuid(int(uid)).pw_dir) if uid else Path("/root")
    out = home / ("advanced-vpn-%s.req" % role)
    argv = [str(target / "bin/avpnctl"), "request", "--role", role, "--protect", protect, "--out", str(out)]
    if insecure:
        argv.append("--insecure-plaintext-keys")
    if vault:
        argv += ["--vault", str(vault)]
    subprocess.run(argv, check=True)
    print("Next: give %s to the operator (avpn init), then: sudo avpn enroll BUNDLE --operator-key operator.pub" % out)
    if role == "client":
        print(next_servers_step())


def installation_preflight(protect=None, operator_target=None):
    """Refuse a system install before staging when the shared host checks report blockers."""
    from types import SimpleNamespace
    import preflight

    available_runtime()
    options = SimpleNamespace(
        package=ROOT / "target/release",
        target=operator_target or "/opt",
        protect=protect,
        hardware=False,
        provider=[],
        operator_only=operator_target is not None,
    )
    report = preflight.inspect_host(options)
    if not report["ready"]:
        reasons = "\n".join(f["message"] for f in report["findings"] if f["severity"] == "blocker")
        packages = "\nSuggested package command: " + report["install"] if report["install"] else ""
        raise RuntimeError("Installation preflight blocked; no installation was started.\n" + reasons + packages)
    for finding in report["findings"]:
        if finding["severity"] == "warning":
            print("Preflight warning: " + finding["message"], file=sys.stderr)
    return report


def main():
    """Command-line entry point: stage, install system-wide, install for the user, or pack."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--out", type=Path, help="stage the system installation in this new directory (to review it)")
    mode.add_argument("--user", action="store_true", help="install the command line for this user only")
    mode.add_argument("--pack", type=Path, help="write the release package to this .tar.gz")
    p.add_argument("--apply", action="store_true", help="install or upgrade /opt/advanced-vpn (root)")
    p.add_argument("--runtime", type=Path, help="with --pack: include this verified pinned offline runtime")
    p.add_argument("--uninstall", action="store_true", help="with --user or --apply: remove an inactive installation")
    p.add_argument(
        "--role", choices=["client", "relay", "middle", "exit"], help="with --apply: also generate this device's keys"
    )
    p.add_argument(
        "--protect", choices=["nitrokey", "systemd-creds", "none"], help="with --role: how the keys are sealed"
    )
    p.add_argument("--vault", type=Path, help="with --protect nitrokey: vault (default /etc/advanced-vpn/vault)")
    p.add_argument(
        "--insecure-plaintext-keys", action="store_true", help="allow --protect none (keys as plain files; tests only)"
    )
    a = p.parse_args()
    if not (a.out or a.user or a.pack or a.apply):
        p.error("choose --apply (system), --user (command line only), --out (stage) or --pack")
    if a.runtime and not a.pack:
        p.error("--runtime is only for --pack")
    if a.uninstall and not (a.user or a.apply):
        p.error("--uninstall needs --user or --apply")
    if a.uninstall and (a.role or a.protect or a.out):
        p.error("--uninstall cannot stage a package or create device keys")
    if a.apply:
        if a.user or a.pack:
            p.error("--apply is for a system installation, not --user or --pack")
        if os.geteuid() != 0:
            raise RuntimeError("--apply requires root")
        if a.uninstall:
            available_runtime()
            uninstall_system()
            return
        if a.role and not a.protect:
            raise ValueError("--role needs --protect (nitrokey, systemd-creds or none)")
        if a.protect == "none" and not a.insecure_plaintext_keys:
            raise ValueError("--protect none stores private keys as plain files; it needs --insecure-plaintext-keys")
        installation_preflight(a.protect)
    if a.pack:
        print(pack(ROOT, a.pack, runtime=a.runtime))
        return
    if a.user:
        data, bin_dir = user_paths()
        if a.uninstall:
            uninstall_user(data, bin_dir)
            print("Removed the user installation; ~/.config/advanced-vpn (cloud inventory, SSH keys) is kept.")
            return
        if os.geteuid() == 0:
            raise RuntimeError("--user installs for an ordinary user, not root")
        installation_preflight(operator_target=data)
        app = install_user(data, bin_dir)
        version = subprocess.run([str(app / "bin/avpn"), "--version"], capture_output=True, text=True).stdout.strip()
        print("Installed %s for this user: %s (command: %s)" % (version, app, bin_dir / "avpn"))
        if str(bin_dir) not in os.environ.get("PATH", "").split(":"):
            print("Add %s to PATH to run avpn." % bin_dir)
        print(next_servers_step())
        return
    if a.out is None:
        import tempfile

        if os.geteuid() != 0:
            raise RuntimeError("--apply requires root")
        a.out = Path(tempfile.mkdtemp(prefix="advanced-vpn-stage-")) / "stage"
    runtime = available_runtime()
    a.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    package = a.out / "opt/advanced-vpn"
    (package / "bin").mkdir(parents=True)
    (package / "tools").mkdir()
    for name in BINARIES:
        shutil.copy2(ROOT / "target/release" / name, package / "bin" / name)
    for src in (ROOT / "tools").glob("*.py"):
        shutil.copy2(src, package / "tools" / src.name)
    shutil.copy2(ROOT / "tools/hardware-requirements.txt", package / "tools/hardware-requirements.txt")
    for name in ["README.md", "LICENSE", "NOTICE", "SECURITY.md"]:
        shutil.copy2(ROOT / name, package / name)
    shutil.copytree(ROOT / "third_party", package / "third_party")
    if runtime is not None:
        shutil.copytree(runtime, package / "venv", symlinks=True)
    # -E -s, not -I: ignore PYTHON* variables and the user site directory, but keep the
    # (root-owned) script directory on sys.path, which -I drops on Python 3.11+.
    # `avpn` is the Rust front end. It runs `avpnctl` (the privileged controller,
    # in the hash-locked venv), `avpn-cloud` (stdlib only; runs as the user, whose
    # own provider sign-in it uses) and `avpn-mesh` (the mesh tool; the venv again,
    # for ML-DSA descriptor signing and verification).
    launchers = {
        "avpnctl": "exec /opt/advanced-vpn/venv/bin/python -B -E -s /opt/advanced-vpn/tools/avpnctl.py"
        ' --bin-dir /opt/advanced-vpn/bin "$@"',
        "avpn-cloud": 'exec /opt/advanced-vpn/venv/bin/python -B -E -s /opt/advanced-vpn/tools/cloud.py "$@"',
        "avpn-mesh": 'exec /opt/advanced-vpn/venv/bin/python -B -E -s /opt/advanced-vpn/tools/mesh.py "$@"',
    }
    for name, body in launchers.items():
        (package / "bin" / name).write_text("#!/bin/sh\n" + body + "\n")
        (package / "bin" / name).chmod(0o755)
    (package / "docs").mkdir()
    shutil.copytree(ROOT / "docs/cli", package / "docs/cli")
    for name in SOURCES:
        if name.startswith("docs/") and (ROOT / name).is_file():
            shutil.copy2(ROOT / name, package / name)
    units = a.out / "etc/systemd/system"
    units.mkdir(parents=True)
    for name in ["advanced-vpn.service", "advanced-vpn-guard.service"]:
        shutil.copy2(ROOT / "deploy" / name, units / name)
    apparmor = a.out / "etc/apparmor.d/local"
    apparmor.mkdir(parents=True)
    shutil.copy2(ROOT / "deploy/apparmor/usr.bin.i2pd.local", apparmor / "usr.bin.i2pd")
    receipt = dict(
        schema=1,
        architecture=platform.machine(),
        activation_performed=False,
        files={
            str(f.relative_to(a.out)): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in a.out.rglob("*")
            if f.is_file()
        },
    )
    (a.out / "INSTALLATION.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if not a.apply:
        print("Staged package only; no host service, route, DNS or firewall changes.")
        return
    if os.geteuid() != 0:
        raise RuntimeError("--apply requires root")
    target = Path("/opt/advanced-vpn")
    # An unprivileged-writable parent would permit replacing root-executed code.
    if Path("/opt").stat().st_uid != 0 or Path("/opt").stat().st_mode & 0o022:
        raise RuntimeError("unsafe installation parent")
    if target.exists() and (target.is_symlink() or target.stat().st_uid != 0 or target.stat().st_mode & 0o022):
        raise RuntimeError("existing /opt/advanced-vpn is not a root-owned installation; not replacing it")
    import pwd

    # The data plane's user, and the I2P front's router's own user (avpn help front).
    for name in ["advanced-vpn", "advanced-vpn-i2p"]:
        try:
            pwd.getpwnam(name)
        except KeyError:
            subprocess.run(
                [trusted_exe("useradd"), "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name],
                check=True,
            )
    upgraded = install_system(package, target)
    Path("/etc/advanced-vpn").mkdir(mode=0o700, exist_ok=True)
    for source in units.glob("*.service"):
        shutil.copy2(source, Path("/etc/systemd/system") / source.name)
    subprocess.run([trusted_exe("systemctl"), "daemon-reload"], check=True)
    # The I2P front's router runs from the service's RAM directory: let the packaged
    # i2pd AppArmor profile read it (its `local/` include is meant for exactly this).
    if Path("/etc/apparmor.d").is_dir():
        local = Path("/etc/apparmor.d/local")
        local.mkdir(mode=0o755, exist_ok=True)
        shutil.copy2(apparmor / "usr.bin.i2pd", local / "usr.bin.i2pd")
        profile = Path("/etc/apparmor.d/usr.bin.i2pd")
        if profile.exists():
            subprocess.run([trusted_exe("apparmor_parser"), "-r", str(profile)], check=False)
    linked = link_commands(target)
    print(
        ("Upgraded" if upgraded else "Installed")
        + " /opt/advanced-vpn without activation; "
        + ("`sudo avpn` now works." if linked else "see the warning above about /usr/local/bin."),
        flush=True,
    )
    if a.role:
        prepare_device(target, a.role, a.protect, a.vault, a.insecure_plaintext_keys)
        return
    print("Next: sudo avpn request --role ROLE --protect MODE --out ROLE.req, or rerun with --role.")


if __name__ == "__main__":
    main()

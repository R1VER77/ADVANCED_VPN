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
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from sysexec import trusted_exe  # noqa: E402  (standard library only)


# What a built checkout must provide; the VM harness and `avpn cloud host setup` pack
# exactly these, so the three never disagree.
BINARIES = [
    "advanced-vpn",
    "advanced-vpn-wireguard",
    "advanced-vpn-dns",
    "advanced-vpn-cloak",
    "avpn",
    "cypherpunk-preflight",
    "cypherpunk-controller",
    "cypherpunk-bootguard",
]
SOURCES = ["tools", "deploy", "third_party", "docs/cli", "docs/OFFLINE_INSTALLATION.md", "docs/SIGNED_REPOSITORY.md", "docs/SUPPORT_MATRIX.md",
           "docs/NAME_MIGRATION.md", "README.md", "LICENSE", "NOTICE", "SECURITY.md"]  # fmt: skip
PACKAGE_OWNER = Path("/var/lib/cypherpunk-vpn/package-owner")
PACKAGE_OWNER_BYTES = b"cypherpunk-vpn package ownership v1\n"


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


def legacy_quiescent(path, proc=Path("/proc")):
    """Legacy paths cannot be moved while a program still imports/runs through them."""
    prefix = os.fsencode(str(path.absolute())) + b"/"
    if str(Path(__file__).resolve()).startswith(str(path.absolute()) + "/"):
        raise RuntimeError("adopt from the newly verified external package, not the old installed tree")
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            if os.geteuid() != 0 and entry.stat().st_uid != os.geteuid():
                continue
            command = (entry / "cmdline").read_bytes()
            try:
                executable = os.fsencode(os.readlink(entry / "exe"))
            except (FileNotFoundError, PermissionError):
                executable = b""
            if prefix in command or executable.startswith(prefix):
                raise RuntimeError("legacy application is in use; stop it before explicitly adopting its paths")
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise RuntimeError("legacy process use could not be verified; adoption refused") from None
    # A non-dumpable same-user process may hide /proc/PID/exe. The kernel still
    # refuses a write-open of an executable in use (ETXTBSY). Do not truncate,
    # chmod or write any byte while checking the supported native entry points.
    for program in path.rglob("*"):
        if program.is_symlink() or not program.is_file() or not program.stat().st_mode & 0o111:
            continue
        try:
            fd = os.open(program, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            if error.errno == errno.ETXTBSY:
                raise RuntimeError("legacy executable is still in use; stop it before adoption") from None
            raise RuntimeError("legacy executable use could not be verified") from None
        else:
            os.close(fd)


def clone_legacy(source, stage, names=None, python=None):
    """Copy application-only bytes; preserve all originals and never copy external state."""
    paths = [source / name for name in names] if names is not None else list(source.iterdir())
    for path in paths:
        for entry in [path, *path.rglob("*")] if path.is_dir() and not path.is_symlink() else [path]:
            if entry.lstat().st_uid != os.geteuid():
                raise ValueError("foreign-owned legacy application entry")
        if path.is_dir() and not path.is_symlink():
            shutil.copytree(path, stage / path.name, symlinks=True)
        elif path.is_symlink():
            (stage / path.name).symlink_to(os.readlink(path))
        else:
            shutil.copy2(path, stage / path.name)
    if (stage / "bin").is_dir():
        write_tool_launchers(stage, python)
    for path in stage.rglob("*"):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & 0o777 & ~0o022)


def install_user(data, bin_dir, python=None, adopt_legacy=False):
    """Build and verify a release, then atomically select it under an upgrade lock."""
    if os.geteuid() == 0:
        raise RuntimeError("--user installs for a normal user; use --out/--apply for the system")
    available_runtime()  # Verify before creating the installation directory.
    from release_slots import Store

    wrapper = bin_dir / "avpn"
    if wrapper.exists() or wrapper.is_symlink():
        if (
            wrapper.is_symlink()
            or not wrapper.is_file()
            or not wrapper.read_text().startswith(
                "#!/bin/sh\n# ADVANCED_VPN command line, user installation (tools/install.py --user).\n"
            )
        ):
            raise ValueError("foreign avpn command; user installation refused without overwriting it")
    app = data / "app"
    legacy = app.exists() and not app.is_symlink()
    if legacy:
        if not adopt_legacy:
            raise RuntimeError(
                "legacy user application detected; stop it and use --adopt-legacy with the verified package"
            )
        legacy_quiescent(app)
    with Store(data).transaction() as store:
        if legacy and store.current() is None:
            previous = store.prepare(lambda stage: clone_legacy(app, stage, python=python))
            store.adopt(previous, ["app"])
        compatibility_link(app, "current")
        name = store.prepare(lambda stage: _build_user(data, python, stage))
        store.activate(name, check_application)
        bin_dir.mkdir(parents=True, exist_ok=True)
        # Resolve once before exporting all three tools, so an activation between
        # child launches cannot mix their application/runtime paths.
        q = shlex.quote
        launcher(
            bin_dir / "avpn",
            "# ADVANCED_VPN command line, user installation (tools/install.py --user).\n"
            "slot=$(CDPATH= cd -P %s && pwd -P) || exit 1\n"
            'export AVPN_CONTROLLER="$slot/bin/avpnctl" AVPN_CLOUD="$slot/bin/avpn-cloud" '
            'AVPN_MESH="$slot/bin/avpn-mesh"\nexec "$slot/bin/avpn" "$@"' % q(str(app)),
        )
        alias = bin_dir / "cypherpunk"
        if not alias.exists() and not alias.is_symlink():
            alias.symlink_to("avpn")
        elif not (alias.is_symlink() and os.readlink(alias) == "avpn"):
            print("warning: foreign cypherpunk command retained: " + str(alias), file=sys.stderr)
        return app


def _build_user(data, python, stage):
    """Populate a private slot without selecting it or changing a launcher."""
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
        python = None
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
        python = None
    write_tool_launchers(stage, python)
    # Source trees may be group writable under a developer's umask. Copying them
    # must not publish writable executable code in an installed application slot.
    for path in stage.rglob("*"):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & 0o777 & ~0o022)


def write_tool_launchers(stage, python=None):
    """Pin script, interpreter and binaries to the same resolved release slot."""
    # Resolve the launcher itself first: /usr/local/bin/avpnctl is a symlink to it, and
    # dirname of that link would name /usr/local instead of this slot.
    header = 'slot=$(CDPATH= cd -P "$(dirname -- "$(readlink -f -- "$0")")/.." && pwd -P) || exit 1\n'
    interpreter = shlex.quote(str(python)) if python is not None else '"$slot/venv/bin/python3"'
    for name, script in (("avpnctl", "avpnctl.py"), ("avpn-cloud", "cloud.py"), ("avpn-mesh", "mesh.py")):
        arguments = ' --bin-dir "$slot/bin"' if name == "avpnctl" else ""
        launcher(
            stage / "bin" / name, header + 'exec %s -B -E -s "$slot/tools/%s"%s "$@"' % (interpreter, script, arguments)
        )


def compatibility_link(path, destination):
    """Keep stable command paths without silently replacing a foreign/legacy tree."""
    if path.is_symlink() and os.readlink(path) == destination:
        return
    if path.exists() or path.is_symlink():
        raise RuntimeError("legacy or foreign installation entry requires offline migration: " + str(path))
    path.symlink_to(destination)
    from release_slots import sync_directory

    sync_directory(path.parent)


def check_application(slot):
    """Check inert commands only; installation never activates networking/services."""
    result = subprocess.run(
        [str(slot / "bin/avpn"), "--version"], capture_output=True, text=True, check=True, timeout=30
    )
    if not result.stdout.startswith("avpn "):
        raise ValueError("installed command failed its version check")


def uninstall_user(data, bin_dir):
    """Remove a user installation. Cloud inventory and SSH keys in ~/.config are kept."""
    wrapper = bin_dir / "avpn"
    alias = bin_dir / "cypherpunk"
    if alias.is_symlink() and os.readlink(alias) == "avpn":
        alias.unlink()
    if wrapper.exists() and "tools/install.py --user" in wrapper.read_text():
        wrapper.unlink()
    from release_slots import Store

    with Store(data).transaction():
        app = data / "app"
        if app.is_symlink():
            if os.readlink(app) != "current":
                raise ValueError("foreign application link; removal refused")
            app.unlink()
        else:
            shutil.rmtree(app, ignore_errors=True)
        for name in ("current",):
            path = data / name
            if path.is_symlink():
                path.unlink()
        for name in ("releases", "venv", "legacy-flat"):
            shutil.rmtree(data / name, ignore_errors=True)
        (data / "TRANSACTION.json").unlink(missing_ok=True)
        (data / "ADOPTION.json").unlink(missing_ok=True)


def install_system(package, target, adopt_legacy=False):
    """Select verified application slots without starting services or deleting old code."""
    from release_slots import Store

    # Reject a damaged bundled runtime before even creating lock/journal files.
    if (package / "venv").exists() or (package / "venv").is_symlink():
        import bundled_runtime

        bundled_runtime.verify(package / "venv", package / "tools/hardware-requirements.txt")
    names = {p.name for p in package.iterdir()} | {"venv"}
    allowed = {"bin", "tools", "venv", "third_party", "docs", "deploy", "README.md", "LICENSE", "NOTICE", "SECURITY.md"}
    if not names <= allowed:
        raise ValueError("unexpected application package entries")
    legacy = []
    if target.exists():
        metadata = {"releases", "current", ".upgrade.lock", "TRANSACTION.json", "ADOPTION.json", "legacy-flat"}

        def recovery_temporary(path):
            if not re.fullmatch(r"\.(?:current-[a-f0-9]{32}|adopt-[a-f0-9]{32}|metadata-[A-Za-z0-9_]{8})", path.name):
                return False
            info = path.lstat()
            import stat

            return info.st_uid == os.geteuid() and (
                stat.S_ISLNK(info.st_mode)
                or (stat.S_ISREG(info.st_mode) and not info.st_mode & 0o7022)
                or (path.name.startswith(".adopt-") and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o7022)
            )

        if any(p.name not in allowed | metadata and not recovery_temporary(p) for p in target.iterdir()):
            raise RuntimeError("foreign entries in the application directory; adoption refused")
        legacy = [
            p.name
            for p in target.iterdir()
            if p.name in allowed and not (p.is_symlink() and os.readlink(p) == "current/" + p.name)
        ]
        if legacy:
            if not adopt_legacy:
                raise RuntimeError(
                    "legacy system application detected; stop it and use --adopt-legacy with the verified package"
                )
            legacy_quiescent(target)
    upgraded = target.exists()
    with Store(target).transaction() as store:
        # Application code is public; root ownership, rather than secrecy of its
        # pathname, protects it. Ordinary-user diagnostics need to execute it.
        target.chmod(0o755)
        store.releases.chmod(0o755)
        if legacy and store.current() is None:
            previous = store.prepare(lambda stage: clone_legacy(target, stage, names=legacy))
            label_system_slot(store.releases / previous)
            store.adopt(previous, legacy)
        # These stable compatibility paths resolve through one atomic pointer.
        # Legacy flat directories need an explicit, inactive migration first.
        for name in sorted(names):
            compatibility_link(target / name, "current/" + name)
        name = store.prepare(lambda stage: _build_system(package, target, stage))
        label_system_slot(store.releases / name)
        store.activate(name, check_application, repair_damaged=True)
    return upgraded


def label_system_slot(slot):
    """Apply this host's SELinux file contexts before publishing copied code.

    copytree/copy2 can retain the package staging tree's security.selinux xattr.
    That label is not authoritative for /opt application executables. Respect the
    administrator's installed file-context mappings; never install an allow rule,
    change enforcing mode or relabel external private state.
    """
    try:
        enforcing = Path("/sys/fs/selinux/enforce").read_bytes().strip()
    except FileNotFoundError:
        return
    if enforcing not in (b"0", b"1"):
        raise RuntimeError("SELinux status could not be verified; application activation refused")
    from release_slots import sync_tree

    subprocess.run(
        # restorecon is a setfiles symlink on RPM distributions. Preserve its
        # dispatch name while executing the resolved, ownership-checked binary.
        ["restorecon", "-RF", "--", str(slot)],  # noqa: S607 -- executable is pinned below; argv[0] selects setfiles mode
        executable=trusted_exe("restorecon"),
        check=True,
        timeout=120,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        capture_output=True,
    )
    sync_tree(slot)


def _build_system(package, target, new):
    """Populate an unselected application slot; external state is never copied."""
    bundled = (package / "venv").exists() or (package / "venv").is_symlink()
    if bundled:
        import bundled_runtime

        bundled_runtime.verify(package / "venv", package / "tools/hardware-requirements.txt")
    shutil.copytree(package, new, symlinks=True, dirs_exist_ok=True)
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
    write_tool_launchers(new)


def link_commands(target, bin_dir=Path("/usr/local/bin")):
    """Put `avpn` and `avpnctl` on root's PATH: sudo searches only system directories."""
    ok = True
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ["avpn", "avpnctl", "cypherpunk"]:
        link, dest = bin_dir / name, target / "bin" / ("avpn" if name == "cypherpunk" else name)
        if link.is_symlink() and os.readlink(link) == str(dest):
            continue
        if link.exists() or link.is_symlink():
            print("warning: %s exists and is not ours; left alone (use %s)" % (link, dest), file=sys.stderr)
            ok = False
            continue
        link.symlink_to(dest)
    return ok


def install_stable_file(source, destination, mode=0o755, known_hashes=()):
    """Durably publish an owned system artifact outside replaceable application slots."""
    from release_slots import checked_directory, digest, durable_json, read_json, sync_directory

    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    checked_directory(destination.parent)
    receipt = destination.with_name("." + destination.name + ".json")
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.stat().st_uid != os.geteuid()
            or destination.stat().st_mode & 0o022
        ):
            raise ValueError("foreign system artifact path")
        if receipt.exists() or receipt.is_symlink():
            previous = read_json(receipt)
            if previous.get("schema") != 1 or previous.get("destination") != destination.name:
                raise ValueError("system artifact ownership is unverified")
            if mode == 0o644 and digest(destination) not in (previous.get("sha256"), previous.get("pending_sha256")):
                raise ValueError("installed system policy was modified; review it before replacement")
        elif digest(destination) not in known_hashes:
            raise ValueError("existing system artifact is not a known owned installation")
    expected = digest(source)
    fd, name = tempfile.mkstemp(prefix=".install-", dir=destination.parent)
    pending = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream, source.open("rb") as original:
            shutil.copyfileobj(original, stream, 1 << 20)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        if digest(pending) != expected or digest(source) != expected:
            raise ValueError("system artifact changed during staging")
        # Persist intent before replacing the artifact. A crash between the two
        # renames accepts only the old or this already-verified new content.
        old_digest = digest(destination) if destination.exists() else None
        durable_json(receipt, dict(schema=1, destination=destination.name, sha256=old_digest, pending_sha256=expected))
        os.replace(pending, destination)
        sync_directory(destination.parent)
        durable_json(receipt, dict(schema=1, destination=destination.name, sha256=expected))
    finally:
        pending.unlink(missing_ok=True)


APPARMOR_BEGIN = b"# BEGIN cypherpunk_vpn managed I2P access\n"
APPARMOR_END = b"# END cypherpunk_vpn managed I2P access\n"


def apparmor_update(source, existing):
    """Preserve administrator policy around one exactly recognized managed block."""
    block = APPARMOR_BEGIN + source.rstrip(b"\n") + b"\n" + APPARMOR_END
    if APPARMOR_BEGIN in existing or APPARMOR_END in existing:
        if existing.count(APPARMOR_BEGIN) != 1 or existing.count(APPARMOR_END) != 1:
            raise ValueError("ambiguous AppArmor managed block; review the local policy")
        start, end = existing.index(APPARMOR_BEGIN), existing.index(APPARMOR_END) + len(APPARMOR_END)
        if end < start or existing[start:end] != block:
            raise ValueError("modified AppArmor managed block; review the local policy")
        return existing
    if existing == source:
        return block  # Exact prior installer content: adopt without duplication.
    return existing + (b"\n" if existing and not existing.endswith(b"\n") else b"") + block


def install_apparmor_fragment(source, destination):
    """Append owned I2P permissions without replacing unrelated local AppArmor rules."""
    from release_slots import checked_directory, sync_directory
    import stat

    destination.parent.mkdir(mode=0o755, exist_ok=True)
    checked_directory(destination.parent)
    existing = b""
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("unsafe local AppArmor fragment")
        if info.st_size > 1 << 20:
            raise ValueError("local AppArmor fragment exceeds review bound")
        existing = destination.read_bytes()
    result = apparmor_update(source.read_bytes(), existing)
    if result == existing:
        return
    descriptor, name = tempfile.mkstemp(prefix=".apparmor-", dir=destination.parent)
    pending = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(result)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(pending, destination)
        sync_directory(destination.parent)
    finally:
        pending.unlink(missing_ok=True)


@contextlib.contextmanager
def system_installation_lock():
    """Serialize the complete install/removal, including stable guard and unit files."""
    import stat

    fd = os.open("/run/cypherpunk-vpn-install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("unsafe system installation lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def removal_checks(target=Path("/opt/advanced-vpn"), proc=Path("/proc")):
    """Read-only, fail-closed removal gate: retain every guard and running program."""
    import guard_policy

    if guard_policy.MARKER.exists() or guard_policy.MARKER.is_symlink():
        raise RuntimeError(
            "Removal refused: persistent whole-device guard intent is retained; recover explicitly first."
        )
    for manager in guard_policy.MANAGERS:
        dependency = guard_policy.UNITS / (manager + ".d") / guard_policy.DROPIN
        if dependency.exists() or dependency.is_symlink():
            raise RuntimeError("Removal refused: a network manager still requires the independent guard.")
    for unit in ("advanced-vpn.service", "advanced-vpn-guard.service", "cypherpunk-vpn-controller.service"):
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
    from release_slots import digest, read_json, sync_directory

    owned_units = []
    for name in ("advanced-vpn.service", "advanced-vpn-guard.service", "cypherpunk-vpn-controller.service"):
        path = units / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or path.read_bytes() != (ROOT / "deploy" / name).read_bytes():
                raise RuntimeError("Removal refused: modified/foreign unit %s; review it before removal." % path)
            owned_units.append(path)
    artifacts = []
    for path in (
        Path("/usr/libexec/cypherpunk-vpn-bootguard"),
        Path("/etc/dbus-1/system.d/org.cypherpunk_vpn.Controller1.conf"),
        Path("/usr/share/dbus-1/system-services/org.cypherpunk_vpn.Controller1.service"),
        Path("/usr/share/polkit-1/actions/org.cypherpunk_vpn.policy"),
        *owned_units,
    ):
        receipt = path.with_name("." + path.name + ".json")
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                raise RuntimeError("Removal refused: unsafe system artifact " + str(path))
            if receipt.exists() or receipt.is_symlink():
                info = read_json(receipt)
                if (
                    info.get("schema") != 1
                    or info.get("destination") != path.name
                    or digest(path) not in (info.get("sha256"), info.get("pending_sha256"))
                ):
                    raise RuntimeError("Removal refused: changed system artifact " + str(path))
            elif path not in owned_units:
                raise RuntimeError("Removal refused: unverified system artifact " + str(path))
            artifacts.append((path, receipt))
    package_owned = False
    if PACKAGE_OWNER.exists() or PACKAGE_OWNER.is_symlink():
        from keyguard import read_private

        if read_private(PACKAGE_OWNER) != PACKAGE_OWNER_BYTES:
            raise RuntimeError("Removal refused: foreign package ownership marker")
        package_owned = True
    # Check again after reading ownership and unit data, before the first mutation.
    # Concurrent privileged administration is outside this gate; do not connect or
    # reconfigure another instance while uninstalling it.
    removal_checks(target)
    for path, receipt in artifacts:
        path.unlink()
        receipt.unlink(missing_ok=True)
        sync_directory(path.parent)
    for name in ("avpn", "avpnctl", "cypherpunk"):
        path = bin_dir / name
        destination = target / "bin" / ("avpn" if name == "cypherpunk" else name)
        if path.is_symlink() and os.readlink(path) == str(destination):
            path.unlink()
    if target.exists():
        shutil.rmtree(target)
    if package_owned:
        PACKAGE_OWNER.unlink()
        sync_directory(PACKAGE_OWNER.parent)
    subprocess.run([trusted_exe("systemctl"), "daemon-reload"], check=True, timeout=15)
    print("Removed inactive application and owned units; private state, keys, users and network settings are kept.")


def prepare_device(target, role, protect, vault=None, insecure=False, unlock_key=None):
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
    if unlock_key:
        argv += ["--unlock-key", str(unlock_key.resolve())]
    subprocess.run(argv, check=True)
    print("Next: give %s to the operator (avpn init), then: sudo avpn enroll BUNDLE --operator-key operator.pub" % out)
    if protect == "operator":
        print(
            "This server's keys are locked to the operator's Nitrokey: it cannot open them after a reboot "
            "until the operator unlocks it (avpn cloud unlock NAME, or avpn unwrap + avpn server-unlock)."
        )
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
    p.add_argument("--package-managed", action="store_true", help="with --apply: package-owned /usr/bin commands")
    p.add_argument(
        "--adopt-legacy",
        action="store_true",
        help="explicitly adopt a stopped flat installation using atomic exchanges",
    )
    p.add_argument("--uninstall", action="store_true", help="with --user or --apply: remove an inactive installation")
    p.add_argument(
        "--role", choices=["client", "relay", "middle", "exit"], help="with --apply: also generate this device's keys"
    )
    p.add_argument(
        "--protect",
        choices=["nitrokey", "systemd-creds", "operator", "none"],
        help="with --role: how the keys are sealed (a server: systemd-creds needs a usable TPM2, else operator)",
    )
    p.add_argument(
        "--unlock-key", type=Path, help="with --protect operator: the operator's unlock public key (avpn unlock-key)"
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
    if a.package_managed and not a.apply:
        p.error("--package-managed requires --apply")
    if a.adopt_legacy and (not (a.user or a.apply) or a.uninstall):
        p.error("--adopt-legacy needs a user/system installation and cannot remove it")
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
            with system_installation_lock():
                uninstall_system(bin_dir=Path("/usr/bin") if a.package_managed else Path("/usr/local/bin"))
            return
        if a.role and not a.protect:
            raise ValueError("--role needs --protect (nitrokey, systemd-creds, operator or none)")
        if a.role:
            # A server's keys: TPM2-sealed, or locked to the operator's Nitrokey; never the
            # host key alone. Refused here, before anything is staged (tools/sealing.py).
            import sealing

            sealing.check_server_protection(a.role, a.protect, a.unlock_key)
            if a.unlock_key is not None and not a.unlock_key.is_file():
                raise ValueError("no unlock key at %s" % a.unlock_key)
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
        app = install_user(data, bin_dir, adopt_legacy=a.adopt_legacy)
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
    shutil.copy2(ROOT / "tools/preflight-policy.json", package / "tools/preflight-policy.json")
    shutil.copytree(ROOT / "tools/provider_data", package / "tools/provider_data")
    for name in ["README.md", "LICENSE", "NOTICE", "SECURITY.md"]:
        shutil.copy2(ROOT / name, package / name)
    shutil.copytree(ROOT / "third_party", package / "third_party")
    shutil.copytree(ROOT / "deploy", package / "deploy", ignore=shutil.ignore_patterns("__pycache__"))
    if runtime is not None:
        shutil.copytree(runtime, package / "venv", symlinks=True)
    # -E -s, not -I: ignore PYTHON* variables and the user site directory, but keep the
    # (root-owned) script directory on sys.path, which -I drops on Python 3.11+.
    # `avpn` is the Rust front end. It runs `avpnctl` (the privileged controller,
    # in the hash-locked venv), `avpn-cloud` (stdlib only; runs as the user, whose
    # own provider sign-in it uses) and `avpn-mesh` (the mesh tool; the venv again,
    # for ML-DSA descriptor signing and verification).
    write_tool_launchers(package)
    (package / "docs").mkdir()
    shutil.copytree(ROOT / "docs/cli", package / "docs/cli")
    for name in SOURCES:
        if name.startswith("docs/") and (ROOT / name).is_file():
            shutil.copy2(ROOT / name, package / name)
    units = a.out / "etc/systemd/system"
    units.mkdir(parents=True)
    for name in ["advanced-vpn.service", "advanced-vpn-guard.service", "cypherpunk-vpn-controller.service"]:
        shutil.copy2(ROOT / "deploy" / name, units / name)
    stable = a.out / "usr/libexec"
    stable.mkdir(parents=True)
    shutil.copy2(ROOT / "target/release/cypherpunk-bootguard", stable / "cypherpunk-vpn-bootguard")
    for source, destination in (
        ("dbus/org.cypherpunk_vpn.Controller1.conf", "etc/dbus-1/system.d/org.cypherpunk_vpn.Controller1.conf"),
        (
            "dbus/org.cypherpunk_vpn.Controller1.service",
            "usr/share/dbus-1/system-services/org.cypherpunk_vpn.Controller1.service",
        ),
        ("polkit/org.cypherpunk_vpn.policy", "usr/share/polkit-1/actions/org.cypherpunk_vpn.policy"),
    ):
        path = a.out / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "deploy" / source, path)
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
    with system_installation_lock():
        apply_system(a, package, units, apparmor, stable)


def apply_system(a, package, units, apparmor, stable):
    """Root-only deployment under the global installation lock; never activate a tunnel."""
    if os.geteuid() != 0:
        raise RuntimeError("system deployment requires root")
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
    install_stable_file(stable / "cypherpunk-vpn-bootguard", Path("/usr/libexec/cypherpunk-vpn-bootguard"))
    history = json.loads((ROOT / "deploy/installation-history.json").read_text())
    if history.get("schema") != 1:
        raise ValueError("unrecognized installation ownership history")
    pins = history["owned_unit_sha256"]
    # Make boot protection independent before changing any application path.
    # Known signed-version hashes permit exact adoption, never foreign units.
    guard_unit = Path("/etc/systemd/system/advanced-vpn-guard.service")
    install_stable_file(units / guard_unit.name, guard_unit, mode=0o644, known_hashes=pins.get(guard_unit.name, ()))
    subprocess.run([trusted_exe("systemctl"), "daemon-reload"], check=True, timeout=15)
    import guard_policy

    preferences = guard_policy.STATE / "preferences.json"
    if (
        guard_policy.MARKER.exists()
        or guard_policy.MARKER.is_symlink()
        or (
            (preferences.exists() or preferences.is_symlink())
            and json.loads(guard_policy.read_private(preferences)).get("mode") == "whole-device"
        )
    ):
        guard_policy.arm()
    upgraded = install_system(package, target, adopt_legacy=a.adopt_legacy)
    Path("/etc/advanced-vpn").mkdir(mode=0o700, exist_ok=True)
    for source in units.glob("*.service"):
        install_stable_file(
            source, Path("/etc/systemd/system") / source.name, mode=0o644, known_hashes=pins.get(source.name, ())
        )
    for relative in (
        "etc/dbus-1/system.d/org.cypherpunk_vpn.Controller1.conf",
        "usr/share/dbus-1/system-services/org.cypherpunk_vpn.Controller1.service",
        "usr/share/polkit-1/actions/org.cypherpunk_vpn.policy",
    ):
        install_stable_file(a.out / relative, Path("/") / relative, mode=0o644)
    subprocess.run([trusted_exe("systemctl"), "daemon-reload"], check=True)
    # The I2P front's router runs from the service's RAM directory: let the packaged
    # i2pd AppArmor profile read it (its `local/` include is meant for exactly this).
    if Path("/etc/apparmor.d").is_dir():
        local = Path("/etc/apparmor.d/local")
        local.mkdir(mode=0o755, exist_ok=True)
        install_apparmor_fragment(apparmor / "usr.bin.i2pd", local / "usr.bin.i2pd")
        profile = Path("/etc/apparmor.d/usr.bin.i2pd")
        if profile.exists():
            subprocess.run([trusted_exe("apparmor_parser"), "-r", str(profile)], check=False)
    linked = link_commands(target, Path("/usr/bin") if a.package_managed else Path("/usr/local/bin"))
    if a.package_managed:
        from keyguard import atomic, read_private
        from release_slots import checked_directory

        PACKAGE_OWNER.parent.mkdir(mode=0o700, exist_ok=True)
        checked_directory(PACKAGE_OWNER.parent)
        if PACKAGE_OWNER.exists() or PACKAGE_OWNER.is_symlink():
            if read_private(PACKAGE_OWNER) != PACKAGE_OWNER_BYTES:
                raise ValueError("foreign package ownership marker")
        else:
            atomic(PACKAGE_OWNER, PACKAGE_OWNER_BYTES)
    print(
        ("Upgraded" if upgraded else "Installed")
        + " /opt/advanced-vpn without activation; "
        + ("`sudo avpn` now works." if linked else "see the warning above about /usr/local/bin."),
        flush=True,
    )
    if a.role:
        prepare_device(target, a.role, a.protect, a.vault, a.insecure_plaintext_keys, a.unlock_key)
        return
    print("Next: sudo avpn request --role ROLE --protect MODE --out ROLE.req, or rerun with --role.")


if __name__ == "__main__":
    main()

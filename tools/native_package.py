#!/usr/bin/env python3
"""Build offline native Linux packages as an ordinary user, without activation.

Package-manager signatures/provenance must authenticate the output before root
installation. Local checksums and runtime manifests are damage checks, not signatures.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile

import bundled_runtime
import install
import preflight
from release_slots import inventory
from sysexec import trusted_exe

PAYLOAD = "/usr/lib/cypherpunk-vpn/payload"
COMMANDS = {"cypherpunk": "cypherpunk", "cypherpunkctl": "cypherpunkctl"}
ROOT = Path(__file__).resolve().parents[1]
# The desktop app ships beside the payload, owned by the package manager rather than by
# the application slots: it runs as the ordinary desktop user and holds no privilege. It
# reaches the root controller only over the system bus (deploy/dbus, deploy/polkit).
GUI = "/usr/lib/cypherpunk-vpn/gui/cypherpunk-vpn-gui"
GUI_COMMAND = "cypherpunk-vpn-gui"
GUI_ICON = "apps/cypherpunk-vpn/src-tauri/icons/128x128.png"
GUI_DEB_DEPENDS = "libwebkit2gtk-4.1-0, libgtk-3-0"
GUI_RPM_REQUIRES = "webkit2gtk4.1, gtk3"
DESKTOP_ENTRY = (
    "[Desktop Entry]\nType=Application\nName=Cypherpunk VPN\n"
    "Comment=Connect and check your cypherpunk_vpn protection\n"
    "Exec=" + GUI_COMMAND + "\nIcon=cypherpunk-vpn\nTerminal=false\n"
    "Categories=Network;Security;\nStartupWMClass=cypherpunk-vpn-gui\n"
)


def version(root):
    """A bounded upstream version cannot inject package metadata or shell syntax."""
    found = re.search(r'^version\s*=\s*"([^"]+)"', (root / "Cargo.toml").read_text(), re.MULTILINE)
    if not found or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?", found[1]):
        raise ValueError("invalid package version")
    return found[1]


DEB_NUMBER = r"[0-9]+\.[0-9]+\.[0-9]+(?:~[A-Za-z0-9.]+)?-1"
RPM_NUMBER = r"[0-9]+\.[0-9]+\.[0-9]+"
REFUSAL = (
    "printf '%s\\n' \"Refusing package downgrade: installed $OLD is newer than {number}.\" >&2\n"
    "printf '%s\\n' 'Package downgrades are not supported; roll back via the retained"
    " application slot (docs/OFFLINE_INSTALLATION.md).' >&2\n"
    "exit 1\n"
)


def rpm_compare_expression():
    """Native RPM comparison expression, separately executable in compatibility tests."""
    return r"""%{lua:
local verdict, count = "allowed", 0
for line in (os.getenv("CYPHERPUNK_RPM_INSTALLED") or ""):gmatch("[^\n]+") do
  count = count + 1
  local epoch, version, release = line:match("^(%d+)\t([^\t]+)\t([^\t]+)$")
  if not epoch or #version > 128 or #release > 128 then
    verdict = "invalid"
  else
    local comparison = rpm.vercmp(epoch, "0")
    if comparison == 0 then comparison = rpm.vercmp(version, os.getenv("CYPHERPUNK_RPM_TARGET")) end
    if comparison == 0 then comparison = rpm.vercmp(release, "1") end
    if comparison > 0 and verdict ~= "invalid" then verdict = "newer" end
  end
end
if count == 0 then verdict = "invalid" end
print(verdict)
}"""


def rpm_upgrade_guard(number):
    """Use RPM's installed database and native epoch/version/release comparison.

    Scriptlet $1 is a package count; $2 is not an installed version. Passing
    database rows in an environment variable keeps them outside Lua/macro code.
    """
    lua = rpm_compare_expression()
    return (
        'case "${1:-}" in ""|*[!0-9]*) exit 1 ;; esac\n'
        "if installed=$(/usr/bin/rpm -q --qf '%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\n' cypherpunk-vpn 2>/dev/null); then\n"
        '    verdict=$(CYPHERPUNK_RPM_INSTALLED="$installed" CYPHERPUNK_RPM_TARGET='
        + shlex.quote(number)
        + " /usr/bin/rpm --eval "
        + shlex.quote(lua)
        + ") || exit 1\n"
        '    case "$verdict" in\n'
        "      allowed) ;;\n"
        "      newer) OLD='installed RPM epoch/version/release'; " + REFUSAL.format(number=number) + "      ;;\n"
        "      *) printf '%s\\n' 'Refusing package replacement: cannot compare installed RPM metadata.' >&2; exit 1 ;;\n"
        "    esac\n"
        'elif [ "$1" -ne 1 ]; then\n'
        "    printf '%s\\n' 'Refusing replacement: installed RPM database could not be queried.' >&2\n"
        "    exit 1\n"
        "fi\n"
    )


def debian_upgrade_guard(number):
    """Generate the exact native dpkg ordering gate independently of host paths."""
    if not re.fullmatch(DEB_NUMBER, number):
        raise ValueError("invalid Debian package version")
    return (
        'if [ "${1:-}" = upgrade ]; then\n'
        "    OLD=${2:-}\n"
        '    if [ -z "$OLD" ]; then exit 1; fi\n'
        '    if /usr/bin/dpkg --compare-versions "$OLD" gt \''
        + number
        + "'; then\n"
        + REFUSAL.format(number=number)
        + '    elif /usr/bin/dpkg --compare-versions "$OLD" le \''
        + number
        + "'; then :\n"
        "    else printf '%s\\n' 'Refusing replacement: cannot compare installed Debian version.' >&2; exit 1\n"
        "    fi\nfi\n"
    )


def preinstall(number, debian=True):
    """Refuse downgrades, foreign commands and unreviewed adoption before extraction.

    A package downgrade would replace the retained, verified rollback slot with older
    code and is refused. Reinstalling the same version (package-managed replacement)
    stays allowed; rolling back application code is the slot system's transaction.
    """
    if debian and not re.fullmatch(DEB_NUMBER, number):
        raise ValueError("invalid Debian package version")
    if not debian and not re.fullmatch(RPM_NUMBER, number):
        raise ValueError("invalid RPM package version")
    if debian:
        guard = 'case "${1:-}" in abort-upgrade) exit 0 ;; esac\n' + debian_upgrade_guard(number)
    else:
        guard = rpm_upgrade_guard(number)
    return (
        "#!/bin/sh\nset -eu\n"
        + guard
        + legacy_running_guard()
        + """if [ -e /opt/cypherpunk-vpn ] || [ -L /opt/cypherpunk-vpn ] || [ -e /opt/advanced-vpn ] || [ -L /opt/advanced-vpn ]; then
    marker=/var/lib/cypherpunk-vpn/package-owner
    if [ ! -f "$marker" ] || [ -L "$marker" ] ||
       [ "$(/usr/bin/stat -c '%u:%a' /var/lib/cypherpunk-vpn)" != 0:700 ] ||
       [ "$(/usr/bin/stat -c '%u:%a' "$marker")" != 0:600 ] ||
       [ "$(/usr/bin/cat "$marker")" != 'cypherpunk-vpn package ownership v1' ]; then
        printf '%s\\n' 'Unmanaged installation retained. Explicitly adopt using a verified offline release with --apply --adopt-legacy --package-managed before package installation.' >&2
        exit 1
    fi
fi
for name in cypherpunk cypherpunkctl; do
    command=/usr/bin/$name
    target=/opt/cypherpunk-vpn/bin/$name
    legacy=/opt/advanced-vpn/bin/$name
    [ "$name" != cypherpunk ] || legacy=/opt/advanced-vpn/bin/avpn
    if [ -e "$command" ] || [ -L "$command" ]; then
        if [ ! -L "$command" ] || { [ "$(/usr/bin/readlink "$command")" != "$target" ] && [ "$(/usr/bin/readlink "$command")" != "$legacy" ]; }; then
            printf '%s\\n' "Foreign command retained: $command" >&2
            exit 1
        fi
    fi
done
"""
    )


SYSTEMCTL = "/usr/bin/systemctl"
CONTROLLER_UNIT = "cypherpunk-vpn-controller.service"
NFT = "/usr/sbin/nft"
SYSTEMD_UNITS = "/etc/systemd/system"
# The install from before the clean-break rename (D019).
LEGACY_ROOT = "/opt/advanced-vpn"
LEGACY_UNITS = ("advanced-vpn.service", "advanced-vpn-guard.service")
LEGACY_TABLE = "inet advanced_vpn"


def legacy_running_guard():
    """Refuse to install over the previous version while its VPN or kill switch is on.

    The upgrade removes the old install. Doing that under a running tunnel or a loaded
    kill switch would leave either running with nothing installed that can stop it, so the
    owner stops them first, knowingly (22 Nov 2026).
    """
    units = " ".join(LEGACY_UNITS)
    return (
        "if [ -x " + SYSTEMCTL + " ]; then\n"
        "    for unit in " + units + "; do\n"
        "        if " + SYSTEMCTL + ' is-active --quiet "$unit"; then\n'
        "            printf '%s\\n' \"Refusing upgrade: the previous version's $unit is running.\" "
        "'Stop it first: sudo systemctl stop " + units + "' "
        "'Traffic is not protected by a VPN until you connect again after the upgrade.' >&2\n"
        "            exit 1\n"
        "        fi\n"
        "    done\n"
        "fi\n"
        "if [ -x " + NFT + " ] && " + NFT + " list table " + LEGACY_TABLE + " >/dev/null 2>&1; then\n"
        "    printf '%s\\n' 'Refusing upgrade: the previous version'\\''s kill switch is still loaded.' "
        "'Lift it first: sudo nft delete table " + LEGACY_TABLE + "' >&2\n"
        "    exit 1\n"
        "fi\n"
    )


def legacy_cleanup():
    """Remove the stopped previous install (the pre-install refused a running one), and say so."""
    units = " ".join(LEGACY_UNITS)
    return (
        "if [ -e " + LEGACY_ROOT + " ] || [ -L " + LEGACY_ROOT + " ]; then\n"
        "    if [ -x " + SYSTEMCTL + " ]; then " + SYSTEMCTL + " disable " + units + " >/dev/null 2>&1 || true; fi\n"
        "    rm -f /usr/bin/avpn /usr/bin/avpnctl "
        + SYSTEMD_UNITS
        + "/advanced-vpn*.service "
        + SYSTEMD_UNITS
        + "/.advanced-vpn*.service.json\n"
        "    rm -rf " + LEGACY_ROOT + "\n"
        "    if [ -x " + SYSTEMCTL + " ]; then " + SYSTEMCTL + " daemon-reload || true; fi\n"
        "    printf '%s\\n' 'Removed the previous version (" + LEGACY_ROOT + ") and its stopped services.' "
        "'Set this device up again in the app; nothing is connected until you do.' >&2\n"
        "fi\n"
    )


def configure(debian=True):
    """The verified bundled runtime installs slots and units without starting them.

    A controller already running from the previous install keeps its old worker loaded,
    so once the new slot is in place it is stopped (never started): the app's next
    request starts the new version through D-Bus activation. The VPN and guard run in
    their own units and are untouched. Without this the user had to stop it by hand.
    """
    action = (
        PAYLOAD
        + "/install.sh --apply --package-managed\n"
        + legacy_cleanup()
        + "if [ -x "
        + SYSTEMCTL
        + " ] && "
        + SYSTEMCTL
        + " is-active --quiet "
        + CONTROLLER_UNIT
        + "; then\n"
        "    " + SYSTEMCTL + " stop " + CONTROLLER_UNIT + "\n"
        "fi\n"
    )
    if debian:
        action = 'case "${1:-}" in configure)\n' + action + ";; esac\n"
    return "#!/bin/sh\nset -eu\n" + action


def remove(debian=True):
    """Removal never disables a guard or stops a running operation implicitly."""
    condition = 'case "${1:-}" in remove|deconfigure)' if debian else 'if [ "${1:-1}" -eq 0 ]; then'
    end = ";; esac" if debian else "fi"
    return (
        "#!/bin/sh\nset -eu\n"
        + condition
        + "\n"
        + PAYLOAD
        + "/install.sh --apply --package-managed --uninstall\n"
        + end
        + "\n"
    )


def stage_gui(root, gui, destination):
    """Add the built desktop app, its launcher entry and icon; never privileged files."""
    gui = Path(gui)
    if gui.is_symlink() or not gui.is_file():
        raise ValueError("the desktop app must be a regular file")
    with gui.open("rb") as binary:
        if binary.read(4) != b"\x7fELF":
            raise ValueError("the desktop app is not an ELF executable")
    target = destination / GUI.lstrip("/")
    target.parent.mkdir(mode=0o755, parents=True)
    shutil.copy2(gui, target)
    target.chmod(0o755)
    # The app is checked against the same declared baseline as the core binaries: a GUI
    # built on a newer distribution would install and then fail to start on an older one.
    needed = preflight.glibc_need(target.parent)
    if needed > preflight.RELEASE_GLIBC:
        raise ValueError(
            "desktop app ABI "
            + ".".join(map(str, needed))
            + " exceeds the declared release baseline "
            + ".".join(map(str, preflight.RELEASE_GLIBC))
            + "; build the desktop app on the baseline distribution"
        )
    applications = destination / "usr/share/applications"
    applications.mkdir(mode=0o755, parents=True)
    (applications / "cypherpunk-vpn.desktop").write_text(DESKTOP_ENTRY)
    icons = destination / "usr/share/icons/hicolor/128x128/apps"
    icons.mkdir(mode=0o755, parents=True)
    shutil.copy2(root / GUI_ICON, icons / "cypherpunk-vpn.png")
    for path in [*applications.iterdir(), *icons.iterdir()]:
        path.chmod(0o644)
    for path in (destination / "usr/share").rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    (destination / "usr/bin" / GUI_COMMAND).symlink_to(GUI)


def stage(root, runtime, destination, gui=None):
    """Copy only the reviewed release inputs and pinned runtime into a new payload."""
    bundled_runtime.verify(runtime, root / "tools/hardware-requirements.txt")
    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
    payload = destination / PAYLOAD.lstrip("/")
    payload.mkdir(mode=0o755, parents=True)
    for name in install.SOURCES:
        source = root / name
        target = payload / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(source, target)
    binaries = payload / "target/release"
    binaries.mkdir(mode=0o755, parents=True)
    for name in install.BINARIES:
        shutil.copy2(root / "target/release" / name, binaries / name)
    shutil.copytree(runtime, payload / "runtime", symlinks=True)
    shutil.copy2(root / "tools/install-offline.sh", payload / "install.sh")
    for path in [destination, *destination.rglob("*")]:
        if not path.is_symlink():
            if path.is_dir():
                path.chmod(0o755)
            else:
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    (payload / "install.sh").chmod(0o755)
    bundled_runtime.verify(payload / "runtime", payload / "tools/hardware-requirements.txt")
    needed = preflight.glibc_need(payload)
    if needed > preflight.RELEASE_GLIBC:
        raise ValueError(
            "native package ABI "
            + ".".join(map(str, needed))
            + " exceeds the declared release baseline "
            + ".".join(map(str, preflight.RELEASE_GLIBC))
            + "; rebuild core binaries on the baseline distribution"
        )
    # Validate links/special files before adding the three fixed absolute aliases.
    contents = inventory(payload)
    (payload / "PACKAGE_CONTENTS.json").write_text(json.dumps(dict(schema=1, entries=contents), sort_keys=True) + "\n")
    (payload / "PACKAGE_CONTENTS.json").chmod(0o644)
    bindir = destination / "usr/bin"
    bindir.mkdir(mode=0o755, parents=True)
    for name, target in COMMANDS.items():
        (bindir / name).symlink_to("/opt/cypherpunk-vpn/bin/" + target)
    if gui is not None:
        stage_gui(root, gui, destination)
    return payload


def debian(root, runtime, output, epoch, gui=None):
    """Build root-owned dpkg metadata without running package scripts or sudo."""
    number = version(root).replace("-", "~", 1) + "-1"
    package = output / ("cypherpunk-vpn_" + number + "_amd64.deb")
    if package.exists():
        raise FileExistsError("package output already exists")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-deb-", dir=output) as temporary:
        tree = Path(temporary) / "root"
        stage(root, runtime, tree, gui)
        control = tree / "DEBIAN"
        control.mkdir(mode=0o755)
        (control / "control").write_text(
            "Package: cypherpunk-vpn\nVersion: " + number + "\nArchitecture: amd64\n"
            "Maintainer: Anonymous\nSection: net\nPriority: optional\n"
            "Depends: libc6 (>= "
            + ".".join(map(str, preflight.RELEASE_GLIBC))
            + "), libgcc-s1, systemd, nftables, iproute2, mount, passwd, dbus, polkitd | policykit-1"
            + (", " + GUI_DEB_DEPENDS if gui is not None else "")
            + ("\nRecommends: " + ASSISTANT_PACKAGE if gui is not None else "")
            + "\nHomepage: https://github.com/R1VER77/CYPHERPUNK_VPN\n"
            "Description: cypherpunk_vpn private network controller"
            + (" and desktop app" if gui is not None else "")
            + "\n"
            " Offline application slots and an independent opt-in boot guard.\n"
            " Installation never starts a tunnel or enrolls a device.\n"
        )
        (control / "control").chmod(0o644)
        for name, text in (("preinst", preinstall(number)), ("postinst", configure()), ("prerm", remove())):
            install.launcher(control / name, text.removeprefix("#!/bin/sh\n").rstrip("\n"))
        environment = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
        subprocess.run(
            [trusted_exe("dpkg-deb"), "--root-owner-group", "--build", str(tree), str(package)],
            check=True,
            env=environment,
            timeout=300,
        )
    return package


ASSISTANT_PACKAGE = "cypherpunk-vpn-assistant"
ASSISTANT_HOME = "/usr/lib/cypherpunk-vpn/assistant"
ASSISTANT_MODEL = "gemma-3-1b-it-Q8_0.gguf"
GEMMA_DOCS = ("docs/third_party/GEMMA_TERMS_OF_USE.md", "docs/third_party/GEMMA_PROHIBITED_USE_POLICY.md")
ASSISTANT_PROFILE_SOURCE = "deploy/assistant/cypherpunk-vpn-assistant.apparmor"
ASSISTANT_PROFILE_SHIPPED = "/usr/share/cypherpunk-vpn-assistant/apparmor/cypherpunk-vpn-assistant"
ASSISTANT_PROFILE = "/etc/apparmor.d/cypherpunk-vpn-assistant"
APPARMOR_FS = "/sys/kernel/security/apparmor"


def assistant_configure():
    """Install and load the launcher's AppArmor profile where this AppArmor can express it.

    Ubuntu 24.04 and later restrict unprivileged user namespaces; the profile lets the
    assistant's launcher (and nothing else) create its network-less namespace. Older
    AppArmor (Ubuntu 22.04) cannot parse `userns` and does not restrict them, so the
    profile is skipped there, and said so.
    """
    return (
        "#!/bin/sh\nset -eu\n"
        'case "${1:-}" in configure)\n'
        "    parser=$(command -v apparmor_parser || true)\n"
        '    if [ -n "$parser" ] && "$parser" -Q -K --skip-cache '
        + ASSISTANT_PROFILE_SHIPPED
        + " >/dev/null 2>&1; then\n"
        "        install -m 0644 " + ASSISTANT_PROFILE_SHIPPED + " " + ASSISTANT_PROFILE + "\n"
        "        if [ -d " + APPARMOR_FS + ' ] && ! "$parser" -r -W ' + ASSISTANT_PROFILE + " >/dev/null 2>&1; then\n"
        "            printf '%s\\n' 'cypherpunk-vpn-assistant: its AppArmor profile could not be loaded; the assistant may fall back to plain rules.' >&2\n"
        "        fi\n"
        '    elif [ -n "$parser" ]; then\n'
        "        printf '%s\\n' 'cypherpunk-vpn-assistant: this AppArmor cannot express the launcher profile (not needed unless the system restricts user namespaces).' >&2\n"
        "    fi\n"
        ";; esac\n"
    )


def assistant_remove():
    """Unload and delete the profile the assistant installed (dpkg runs prerm with `remove`)."""
    return (
        "#!/bin/sh\nset -eu\n"
        'case "${1:-}" in remove)\n'
        "    if [ -f " + ASSISTANT_PROFILE + " ]; then\n"
        "        parser=$(command -v apparmor_parser || true)\n"
        '        if [ -n "$parser" ] && [ -d '
        + APPARMOR_FS
        + ' ]; then "$parser" -R '
        + ASSISTANT_PROFILE
        + " >/dev/null 2>&1 || true; fi\n"
        "        rm -f " + ASSISTANT_PROFILE + "\n"
        "    fi\n"
        ";; esac\n"
    )


def stage_assistant(root, model, server, destination, isolate=None):
    """The local assistant: llama-server and the pinned Gemma model, with Gemma's terms.

    The model must be exactly the pinned file (tools/assistant.py MODEL_SHA256) and the
    server a regular ELF built on the release baseline. Gemma's terms (s3.1) need its
    Notice and a copy of the Terms of Use with every copy distributed.
    """
    import assistant

    model, server = Path(model), Path(server)
    isolate = Path(isolate) if isolate else server.with_name("isolate")
    for path, what in ((model, "model"), (server, "server"), (isolate, "launcher")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("the assistant %s must be a regular file" % what)
    if bundled_runtime.sha256(model) != assistant.MODEL_SHA256:
        raise ValueError("the assistant model is not the pinned Gemma file")
    for path, what in ((server, "server"), (isolate, "launcher")):
        with path.open("rb") as binary:
            if binary.read(4) != b"\x7fELF":
                raise ValueError("the assistant %s is not an ELF executable" % what)
    home = destination / ASSISTANT_HOME.lstrip("/")
    home.mkdir(mode=0o755, parents=True)
    for path, name in ((server, "llama-server"), (isolate, "isolate")):
        shutil.copy2(path, home / name)
        (home / name).chmod(0o755)
    needed = preflight.glibc_need(home)
    if needed > preflight.RELEASE_GLIBC:
        raise ValueError("assistant server ABI " + ".".join(map(str, needed)) + " exceeds the release baseline")
    shutil.copy2(model, home / ASSISTANT_MODEL)
    (home / (ASSISTANT_MODEL + ".sha256")).write_text(assistant.MODEL_SHA256 + "  " + ASSISTANT_MODEL + "\n")
    profile = destination / ASSISTANT_PROFILE_SHIPPED.lstrip("/")
    profile.parent.mkdir(mode=0o755, parents=True)
    shutil.copy2(root / ASSISTANT_PROFILE_SOURCE, profile)
    profile.chmod(0o644)
    docs = destination / "usr/share/doc" / ASSISTANT_PACKAGE
    docs.mkdir(mode=0o755, parents=True)
    shutil.copy2(root / "NOTICE", docs / "NOTICE")
    for name in GEMMA_DOCS:
        shutil.copy2(root / name, docs / Path(name).name)
    (docs / "copyright").write_text(
        "The Gemma 3 1B model in this package is unmodified.\n"
        "Gemma is provided under and subject to the Gemma Terms of Use found at gemma.ai/resources/terms\n"
        "Copies: GEMMA_TERMS_OF_USE.md and GEMMA_PROHIBITED_USE_POLICY.md in this folder.\n"
        "llama-server is from llama.cpp (MIT licence, github.com/ggml-org/llama.cpp).\n"
    )
    for path in [*home.iterdir(), *docs.iterdir()]:
        if path.name not in ("llama-server", "isolate"):
            path.chmod(0o644)
    for path in (destination / "usr").rglob("*"):
        if path.is_dir():
            path.chmod(0o755)


def assistant_debian(root, model, server, output, epoch):
    """The optional assistant package: nothing started, nothing privileged; its scripts only
    install or remove the launcher's AppArmor profile."""
    number = version(root).replace("-", "~", 1) + "-1"
    package = output / (ASSISTANT_PACKAGE + "_" + number + "_amd64.deb")
    if package.exists():
        raise FileExistsError("package output already exists")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-deb-", dir=output) as temporary:
        tree = Path(temporary) / "root"
        stage_assistant(root, model, server, tree)
        control = tree / "DEBIAN"
        control.mkdir(mode=0o755)
        (control / "control").write_text(
            "Package: " + ASSISTANT_PACKAGE + "\nVersion: " + number + "\nArchitecture: amd64\n"
            "Maintainer: Anonymous\nSection: net\nPriority: optional\n"
            "Depends: libc6 (>= "
            + ".".join(map(str, preflight.RELEASE_GLIBC))
            + "), libstdc++6, libgcc-s1, util-linux\n"
            "Enhances: cypherpunk-vpn\nHomepage: https://github.com/R1VER77/CYPHERPUNK_VPN\n"
            "Description: cypherpunk_vpn local troubleshooting assistant (Gemma 3 1B)\n"
            " Explains a failed setup step in plain words on this computer, offline and\n"
            " without network access. Gemma is provided under and subject to the Gemma\n"
            " Terms of Use found at gemma.ai/resources/terms\n"
        )
        (control / "control").chmod(0o644)
        for name, text in (("postinst", assistant_configure()), ("prerm", assistant_remove())):
            install.launcher(control / name, text.removeprefix("#!/bin/sh\n").rstrip("\n"))
        subprocess.run([trusted_exe("dpkg-deb"), "--root-owner-group", "--build", str(tree), str(package)],
                       check=True, env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)), timeout=600)  # fmt: skip
    return package


def rpm_spec(number, gui=False):
    """Render an offline RPM recipe with the same reviewed lifecycle hooks."""
    if not re.fullmatch(RPM_NUMBER, number):
        raise ValueError("RPM builds currently require a stable upstream version")
    return f"""%global __os_install_post %{{nil}}
%global debug_package %{{nil}}
%global _build_id_links none
Name: cypherpunk-vpn
Version: {number}
Release: 1
Summary: cypherpunk_vpn private network controller
License: AGPL-3.0-or-later
URL: https://github.com/R1VER77/CYPHERPUNK_VPN
Source0: payload.tar
BuildArch: x86_64
Requires: glibc >= {".".join(map(str, preflight.RELEASE_GLIBC))}, libgcc, systemd, nftables, iproute, util-linux, shadow-utils, dbus, polkit, policycoreutils{", " + GUI_RPM_REQUIRES if gui else ""}
AutoReqProv: no
%description
Offline application slots and an independent opt-in boot guard. No activation on install.
See the bundled LICENSE for the project's additional exception.
%prep
%build
%install
mkdir -p %{{buildroot}}
tar -xf %{{SOURCE0}} -C %{{buildroot}}
%pre
{preinstall(number, False).removeprefix("#!/bin/sh" + chr(10)).replace("%", "%%")}
%post
{configure(False).removeprefix("#!/bin/sh" + chr(10))}
%preun
{remove(False).removeprefix("#!/bin/sh" + chr(10))}
%files
%defattr(-,root,root,-)
/usr/lib/cypherpunk-vpn
/usr/bin/cypherpunk
/usr/bin/cypherpunkctl
{GUI_FILES if gui else ""}"""


GUI_FILES = (
    "/usr/bin/" + GUI_COMMAND + "\n/usr/share/applications/cypherpunk-vpn.desktop\n"
    "/usr/share/icons/hicolor/128x128/apps/cypherpunk-vpn.png\n"
)


def rpm(root, runtime, output, epoch, gui=None):
    """Build the RPM with unprivileged rpmbuild; no package scripts are executed."""
    number = version(root)
    spec = rpm_spec(number, gui is not None)
    executable = trusted_exe("rpmbuild")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-rpm-", dir=output) as temporary:
        top = Path(temporary)
        tree = top / "payload"
        stage(root, runtime, tree, gui)
        for name in ("SOURCES", "SPECS", "BUILD", "BUILDROOT", "RPMS", "SRPMS"):
            (top / name).mkdir(mode=0o755)
        with tarfile.open(top / "SOURCES/payload.tar", "w") as archive:

            def normalize(member):
                member.uid = member.gid = 0
                member.uname = member.gname = "root"
                member.mtime = epoch
                return member

            archive.add(tree / "usr", arcname="usr", filter=normalize)
        recipe = top / "SPECS/cypherpunk-vpn.spec"
        recipe.write_text(spec)
        subprocess.run(
            [executable, "-bb", "--define", "_topdir " + str(top), "--define", "_buildhost localhost", str(recipe)],
            check=True,
            env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
            timeout=300,
        )
        built = list((top / "RPMS").rglob("*.rpm"))
        if len(built) != 1:
            raise ValueError("unexpected RPM outputs")
        package = output / built[0].name
        if package.exists():
            raise FileExistsError("package output already exists")
        shutil.copy2(built[0], package)
    return package


def main():
    """Build an unsigned candidate; publishing requires the project's signing gates."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--format", choices=("deb", "rpm", "both"), default="deb")
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument(
        "--gui", type=Path, help="the built desktop app (cypherpunk-vpn-gui) to ship with the controller"
    )
    parser.add_argument("--assistant-model", type=Path, help="the pinned Gemma 3 1B file, for the assistant package")
    parser.add_argument("--assistant-server", type=Path, help="llama-server built by tools/build-assistant.sh")
    args = parser.parse_args()
    if bool(args.assistant_model) != bool(args.assistant_server):
        raise ValueError("the assistant package needs both --assistant-model and --assistant-server")
    if os.geteuid() == 0:
        raise PermissionError("build packages as an ordinary user")
    if args.epoch < 0:
        raise ValueError("invalid reproducible-build epoch")
    args.out.mkdir(mode=0o755, parents=True, exist_ok=False)
    packages = []
    for name, builder in (("deb", debian), ("rpm", rpm)):
        if args.format in (name, "both"):
            package = builder(
                args.source.resolve(), args.runtime.resolve(), args.out, args.epoch, args.gui and args.gui.resolve()
            )
            packages.append(
                dict(name=package.name, sha256=bundled_runtime.sha256(package), size=package.stat().st_size)
            )
    if args.assistant_model:
        package = assistant_debian(args.source.resolve(), args.assistant_model.resolve(),
                                   args.assistant_server.resolve(), args.out, args.epoch)  # fmt: skip
        packages.append(dict(name=package.name, sha256=bundled_runtime.sha256(package), size=package.stat().st_size))
    (args.out / "BUILD.json").write_text(
        json.dumps(dict(schema=1, status="unsigned_unqualified_candidate", packages=packages), indent=2) + "\n"
    )
    print(json.dumps(packages, indent=2))


if __name__ == "__main__":
    main()

"""No retained data on a server, enforced: the hardening script and the checks.

Deleting a log does not erase it: until the disk blocks are reused, anyone holding the
volume (the cloud provider, or whoever gets a snapshot) can recover it. So a chain
server must never write a log line to disk in the first place.

`HARDEN` makes a host keep every log in RAM. It runs:
- as cloud-init `bootcmd` when `avpn cloud` creates a server, which is before `sshd`
  accepts its first login, so not even the setup session reaches the disk;
- in `avpn cloud host setup` for servers recorded with `host add` (their history before
  setup is outside this tool's reach: rebuild them if it matters).

`checks()` reads the live host. `avpn doctor` shows the result, and a server's VPN
refuses to start while any check fails (`avpnctl supervise`), unless the host is
recorded as shared, where its logging belongs to whatever else runs on it.
"""

from pathlib import Path
import shutil
import subprocess

# Persistent loggers that would copy log lines (sshd's included) to disk.
LOGGERS = ["rsyslog.service", "syslog.socket", "syslog-ng.service", "auditd.service", "systemd-journal-upload.service"]
# Login records some distributions keep outside /var/log.
LOGIN_DATABASES = ["/var/lib/lastlog/lastlog2.db", "/var/lib/wtmpdb/wtmp.db"]
SHARED_MARKER = Path("/etc/advanced-vpn/shared-host")
JOURNALD_DROPIN = "/etc/systemd/journald.conf.d/50-advanced-vpn.conf"

HARDEN = r"""set -u
# 1. The system journal lives in RAM (/run/log/journal) only.
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\n' > {dropin}
# 2. No other logger may copy lines to disk.
for unit in {loggers}; do
  systemctl stop "$unit" 2>/dev/null || true
  systemctl mask "$unit" 2>/dev/null || true
done
journalctl --relinquish-var 2>/dev/null || true
systemctl restart systemd-journald
rm -rf /var/log/journal
# 3. Everything under /var/log (auth.log, wtmp, btmp, lastlog, package logs) in RAM,
#    now and on every boot.
grep -q '^tmpfs /var/log ' /etc/fstab || echo 'tmpfs /var/log tmpfs nosuid,nodev,noexec,mode=0755,size=64m 0 0' >> /etc/fstab
mountpoint -q /var/log || mount /var/log
systemd-tmpfiles --create --prefix /var/log 2>/dev/null || true
mkdir -p /var/log/apt
# 4. Login databases kept outside /var/log are not allowed to exist.
for db in {databases}; do
  [ -L "$db" ] || rm -f "$db"
done
# 5. RAM must never be paged out to disk.
swapoff -a 2>/dev/null || true
sed -i -E '/^[^#].*[[:space:]]swap[[:space:]]/s/^/#avpn-no-swap# /' /etc/fstab
""".format(dropin=JOURNALD_DROPIN, loggers=" ".join(LOGGERS), databases=" ".join(LOGIN_DATABASES))


def cloud_init():
    """User data that hardens a new server at first boot, before any login."""
    lines = ["#cloud-config", "bootcmd:", "  - - sh", "    - -c", "    - |"]
    lines += ["      " + line for line in HARDEN.splitlines()]
    return "\n".join(lines) + "\n"


def _mounts(path="/proc/self/mounts"):
    """mountpoint -> filesystem type."""
    out = {}
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3:
            out[parts[1].replace("\\040", " ")] = parts[2]
    return out


def _active(unit):
    exe = shutil.which("systemctl")
    if not exe:
        return False
    return subprocess.run([exe, "is-active", "--quiet", unit], check=False, timeout=10).returncode == 0


def _journal_storage(root):
    """The effective journald Storage= setting (last one wins, drop-ins after the main file)."""
    value = "auto"
    etc = root / "etc/systemd"
    files = [etc / "journald.conf"] + sorted((etc / "journald.conf.d").glob("*.conf"))
    for f in files:
        try:
            for line in f.read_text().splitlines():
                line = line.strip()
                if line.startswith("Storage="):
                    value = line.split("=", 1)[1].strip()
        except OSError:
            continue
    return value


def checks(root=Path("/"), mounts="/proc/self/mounts", swaps="/proc/swaps", active=_active):
    """(name, ok, detail) for every way a server could keep a log on disk."""
    out = []
    storage = _journal_storage(root)
    journal_dir = root / "var/log/journal"
    out.append(
        (
            "journal in RAM only",
            storage == "volatile" and not journal_dir.exists(),
            "Storage=%s, %s" % (storage, "/var/log/journal present" if journal_dir.exists() else "no /var/log/journal"),
        )
    )
    fs = _mounts(mounts).get("/var/log")
    out.append(("/var/log in RAM", fs == "tmpfs", "mounted as %s" % (fs or "part of the root disk")))
    running = [u for u in LOGGERS if active(u)]
    out.append(("no disk logger running", not running, ", ".join(running) or "none of " + ", ".join(LOGGERS)))
    found = [d for d in LOGIN_DATABASES if (root / d.lstrip("/")).exists() and not (root / d.lstrip("/")).is_symlink()]
    out.append(("no login database on disk", not found, ", ".join(found) or "none"))
    swap = [ln.split()[0] for ln in Path(swaps).read_text().splitlines()[1:] if ln.strip()]
    out.append(("no swap", not swap, ", ".join(swap) or "none"))
    return out


def failures(**kw):
    """The failing checks only."""
    return [c for c in checks(**kw) if not c[1]]

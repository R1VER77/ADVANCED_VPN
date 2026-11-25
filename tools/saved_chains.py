"""Local signed client bundles and display-only hop location labels."""

import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from zipfile import BadZipFile

from cryptography.exceptions import InvalidSignature

from keyguard import atomic, read_private
from managed_profile import canonical, enroll, inspect_enrollment_bundle
from release_slots import sync_directory

MAX_BUNDLE = 1_048_576
# Map exact provider regions to the named metro. Unmapped regions stay unknown.
REGIONS = {
    ("aws", "eu-north-1"): ("SE", "Stockholm"),
    ("aws", "eu-central-1"): ("DE", "Frankfurt"),
    ("aws", "eu-west-1"): ("IE", "Dublin"),
    ("aws", "eu-west-2"): ("GB", "London"),
    ("aws", "us-east-1"): ("US", None),
    ("oci", "me-dubai-1"): ("AE", "Dubai"),
    ("oci", "eu-frankfurt-1"): ("DE", "Frankfurt"),
    ("oci", "uk-london-1"): ("GB", "London"),
    ("oci", "us-ashburn-1"): ("US", "Ashburn"),
    ("fly", "fra"): ("DE", "Frankfurt"),
    ("fly", "lhr"): ("GB", "London"),
    ("fly", "ams"): ("NL", "Amsterdam"),
    ("fly", "cdg"): ("FR", "Paris"),
    ("fly", "iad"): ("US", "Ashburn"),
    ("fly", "ord"): ("US", "Chicago"),
    ("fly", "yyz"): ("CA", "Toronto"),
    ("fly", "nrt"): ("JP", "Tokyo"),
    ("fly", "sin"): ("SG", "Singapore"),
    ("azure", "swedencentral"): ("SE", None),
    ("gcp", "europe-west4"): ("NL", None),
}


def private_dir(path, create=False):
    """Check the owner and mode without following a directory symlink."""
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Unsafe saved-chain directory")
    return path


def store(state, create=False):
    """Keep saved bundles outside the enrollment directory exchanged on selection."""
    return private_dir(state.with_name(state.name + "-chains"), create)


def read_as_invoker(path, limit):
    """Read a bounded regular file with the invoking user's permissions."""
    identity = {}
    if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit():
        user = pwd.getpwuid(int(os.environ["SUDO_UID"]))
        identity = dict(user=user.pw_uid, group=user.pw_gid, extra_groups=os.getgrouplist(user.pw_name, user.pw_gid))
    script = (
        "import os,stat,sys\n"
        "with os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW),'rb') as f:\n"
        " if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): sys.exit(1)\n"
        " sys.stdout.buffer.write(f.read(int(sys.argv[2])+1))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(path), str(limit)],
        capture_output=True,
        timeout=3,
        env={"PATH": "/usr/bin:/bin"},
        **identity,
    )
    if result.returncode or len(result.stdout) > limit:
        raise ValueError("Cannot read the selected file or it exceeds the size limit")
    return result.stdout


def inventory():
    """Load the normal user's local operator inventory without contacting providers."""
    try:
        uid = int(os.environ.get("SUDO_UID", os.getuid()))
        home = Path(pwd.getpwuid(uid).pw_dir)
        config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config") if uid == os.getuid() else home / ".config"
        path = config / "cypherpunk-vpn/cloud.json"
        if not path.is_file():
            return []
        resources = json.loads(read_as_invoker(path, 1_048_576)).get("resources")
        return list(resources.values()) if isinstance(resources, dict) else []
    except (OSError, ValueError, TypeError, AttributeError, KeyError, subprocess.TimeoutExpired):
        return []


def countries():
    """Read offline country names from the system's tzdata ISO table."""
    names = {
        "AE": "United Arab Emirates",
        "CA": "Canada",
        "DE": "Germany",
        "FR": "France",
        "GB": "United Kingdom",
        "IE": "Ireland",
        "JP": "Japan",
        "NL": "Netherlands",
        "SE": "Sweden",
        "SG": "Singapore",
        "US": "United States",
    }
    try:
        for row in Path("/usr/share/zoneinfo/iso3166.tab").read_text().splitlines():
            code, _, name = row.partition("\t")
            if re.fullmatch("[A-Z]{2}", code) and name:
                names.setdefault(code, name)
    except OSError:
        pass
    return names


def labels(state):
    """Get display labels keyed by enrolled endpoint."""
    try:
        return json.loads(read_private(store(state) / "locations.json"))
    except FileNotFoundError:
        return {}


def set_label(state, endpoint, country, city):
    """Set a display-only location for an exact endpoint."""
    country = country.upper()
    if country not in countries():
        raise ValueError("Enter a recognized two-letter country code")
    if city is not None and (not 1 <= len(city) <= 80 or any(unicodedata.category(c).startswith("C") for c in city)):
        raise ValueError("Enter a city name of at most 80 characters")
    directory = store(state, create=True)
    current = labels(state)
    current[endpoint] = [country, city]
    atomic(directory / "locations.json", canonical(current))


def _from_inventory(endpoint, records):
    host, port = endpoint.rsplit(":", 1)
    address = ipaddress.ip_address(host.strip("[]"))
    found = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            match = ipaddress.ip_address(record.get("public_ip")) == address
        except ValueError:
            continue
        if match and record.get("port") in (None, int(port), port):
            region = record.get("region") or record.get("location")
            if not isinstance(region, str) or not isinstance(record.get("provider"), str):
                continue
            provider = record["provider"]
            location = REGIONS.get((provider, region.lower()))
            if location is None and provider == "gcp":
                location = REGIONS.get((provider, region.rsplit("-", 1)[0]))
            found.add(location)
    return next(iter(found)) if len(found) == 1 else None


def describe_hops(profile, local, records):
    """Project signed endpoints and independent labels into the CLI view."""
    from cypherpunkctl import chain_of

    names = countries()
    standby = bool((profile["core"].get("inner") or {}).get("peer_members"))
    hops = []
    for hop, endpoint in chain_of(profile):
        value = local.get(endpoint)
        source = "user-supplied"
        if value is None:
            value = _from_inventory(endpoint, records)
            source = "inventory-derived"
        code, city = value if value else (None, None)
        hops.append(
            dict(
                hop=hop,
                endpoint=endpoint,
                country=names.get(code),
                country_code=code,
                city=city,
                location_source=source if code else None,
                primary=standby and hop == "exit",
            )
        )
    return hops


def _bundle_path(state, name):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", name):
        raise ValueError("Chain names use lowercase letters, digits, hyphens or underscores")
    return store(state) / (name + ".cpvpn")


def _inspect(path, state):
    from cypherpunkctl import load_profile

    if load_profile(state)["role"] != "client":
        raise ValueError("Saved chains are available for enrolled clients")
    read_private(path, limit=MAX_BUNDLE)
    checked = inspect_enrollment_bundle(path, state / "operator.pub", state, replace=True)
    return checked["profile"], hashlib.sha256(checked["raw"]).hexdigest()


def import_bundle(state, name, source):
    """Verify a bundle for this client and its enrolled operator before saving it."""
    directory = store(state, create=True)
    target = _bundle_path(state, name)
    if target.exists() or target.is_symlink():
        raise ValueError("This saved chain name already exists")
    with tempfile.TemporaryDirectory(prefix=".import-", dir=directory) as temporary:
        candidate = Path(temporary) / "bundle"
        atomic(candidate, read_as_invoker(source, MAX_BUNDLE))
        _inspect(candidate, state)
        os.link(candidate, target)
        sync_directory(directory)


def list_chains(state):
    """List the current enrollment and the still-verifiable saved bundles."""
    from cypherpunkctl import load_profile

    current = load_profile(state)
    digest = json.loads(read_private(state / "ENROLLMENT.json"))["manifest_sha256"]
    local, records = labels(state), inventory()
    result = dict(current=describe_hops(current, local, records), active_saved=False, saved=[])
    try:
        paths = sorted(store(state).glob("*.cpvpn"))
    except FileNotFoundError:
        return result
    for path in paths:
        try:
            profile, saved_digest = _inspect(_bundle_path(state, path.stem), state)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, BadZipFile, InvalidSignature):
            result["saved"].append(dict(name=path.stem, available=False))
            continue
        active = saved_digest == digest
        result["active_saved"] |= active
        result["saved"].append(
            dict(name=path.stem, available=True, active=active, hops=describe_hops(profile, local, records))
        )
    return result


def _exchange(parent, state, candidate):
    """Exchange two directories on the same filesystem without an absent-profile window."""
    rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if rename is None:
        raise RuntimeError("Atomic chain selection requires Linux renameat2")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if rename(fd, os.fsencode(state.name), fd, os.fsencode(candidate.name), 2) != 0:
            raise OSError(ctypes.get_errno(), "Atomic chain selection failed")
    finally:
        os.close(fd)


def _copy_enrollment(state, candidate):
    # Refuse links, foreign entries and special files before copying protected state.
    for directory, subdirs, files in os.walk(state):
        for name in subdirs:
            private_dir(Path(directory) / name)
        for name in files:
            info = (Path(directory) / name).lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Unsafe file in enrollment state")
    shutil.copytree(state, candidate, dirs_exist_ok=True)


def select_chain(state, name, allow_unsaved=False):
    """Prepare and atomically activate a verified bundle while the supervisor is excluded."""
    from cypherpunkctl import service_active, supervisor_locks

    path = _bundle_path(state, name)
    stage = state.with_name("." + state.name + "-chain-stage")
    with supervisor_locks(state):
        if service_active():
            raise RuntimeError("Disconnect the VPN before selecting a chain")
        private_dir(state)
        _inspect(path, state)
        saved = list_chains(state)
        if any(row["name"] == name and row.get("active") for row in saved["saved"]):
            return
        if not saved["active_saved"] and not allow_unsaved:
            raise ValueError("Import the original bundle to save this route, or explicitly allow leaving it unsaved")
        if stage.exists() or stage.is_symlink():
            sync_directory(state.parent)
            shutil.rmtree(private_dir(stage))
        private_dir(stage, create=True)
        exchanged = committed = False
        try:
            _copy_enrollment(state, stage)
            enroll(path, state / "operator.pub", stage, replace=True)
            for directory, _, files in os.walk(stage, topdown=False):
                for file in files:
                    fd = os.open(Path(directory) / file, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                sync_directory(directory)
            _exchange(state.parent, state, stage)
            exchanged = True
            sync_directory(state.parent)
            committed = True
        finally:
            if not exchanged or committed:
                shutil.rmtree(stage)
                sync_directory(state.parent)

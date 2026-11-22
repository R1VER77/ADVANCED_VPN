#!/usr/bin/env python3
"""The desktop app's own-servers side, run as the signed-in user (never root).

    avpn-desktop state                 the profile, recorded servers and chain (no network)
    avpn-desktop check KEY             is this provider's tool installed and signed in?
    avpn-desktop add KEY | remove KEY  add or drop a provider in the profile
    avpn-desktop build --order A[,B[,C]] [--hours N]   (the device request on stdin)
    avpn-desktop export                save the device request (stdin) to Documents
    avpn-desktop signin SERVER         renew the cloud sign-in a recorded server uses (browser)

The root controller holds the device's keys and never sees a cloud credential; this
helper holds the operator side (cloud sign-ins, the operator's Nitrokey vault, the server
inventory) and never sees the device's keys: it takes the device's *public* request on
stdin and gives back the signed bundle, which the app hands to the controller to import.
The app passes nothing else: provider keys and server names are checked against fixed
lists, and every command it runs is a fixed argument list.

`state` reads local files only. Only `check`, `signin` and `build` touch the network, and
only when the person asks, so the app makes no background requests.

Every reply is one JSON object on stdout (`build` writes one per line as it goes).
"""

import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import providers  # noqa: E402

SCHEMA = 1
NAME = re.compile(r"avpn-[a-z0-9-]{1,40}\Z")
MAX_REQUEST = 64 * 1024
MAX_FILE = 1024 * 1024
HOURS = (2, 4, 6, 8, 12, 16, 24)
# The installed package carries the built server binaries in this layout; a checkout
# is used when running from source.
PAYLOAD = Path("/usr/lib/cypherpunk-vpn/payload")
ADJECTIVES = ("quiet", "amber", "hidden", "swift", "silver", "distant", "northern", "gentle", "bright", "hollow",
              "steady", "lucid", "candid", "velvet", "crimson", "cobalt")  # fmt: skip
NOUNS = ("otter", "harbor", "lantern", "falcon", "cedar", "comet", "meadow", "raven", "ember", "glacier",
         "willow", "beacon", "atlas", "heron", "quartz", "orchid")  # fmt: skip


class Refused(Exception):
    """A request outside the helper's contract: a fixed reason, never echoed input."""


def config_dir():
    """The cloud tool's configuration folder."""
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "advanced-vpn"


def profile_path():
    """Where the desktop profile is kept."""
    return config_dir() / "desktop-profile.json"


def keys():
    """Provider keys the app may name: the app's list plus "own" (a host you already run)."""
    return {p["key"] for p in providers.APP_CATALOG} | {"own"}


def random_name():
    """A profile name that says nothing about its owner."""
    return "%s-%s-%02d" % (secrets.choice(ADJECTIVES), secrets.choice(NOUNS), secrets.randbelow(100))


def write_private(path, text):
    """Replace a file atomically, readable by its owner only."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)
    os.replace(tmp, path)


def load_profile():
    """The profile, made (with a random name) on first use."""
    path = profile_path()
    try:
        profile = json.loads(path.read_text())
        if not isinstance(profile, dict) or profile.get("schema") != SCHEMA:
            raise ValueError
    except FileNotFoundError:
        # A first profile starts with the providers of the chain already recorded here.
        inv = inventory()
        chained = [provider_of(inv["resources"][n]) for n in (inv.get("chain") or {}).get("hops") or []
                   if n in inv.get("resources", {})]  # fmt: skip
        profile = dict(schema=SCHEMA, name=random_name(), created=now(), providers=list(dict.fromkeys(chained)),
                       checked={}, hours_per_day=8)  # fmt: skip
        write_private(path, json.dumps(profile, indent=1) + "\n")
    except ValueError:
        raise Refused("profile_unreadable") from None
    profile["providers"] = [k for k in profile.get("providers", []) if k in keys()]
    return profile


def save_profile(profile):
    """Write the profile (owner-only)."""
    write_private(profile_path(), json.dumps(profile, indent=1) + "\n")


def now():
    """The current UTC time, as the profile records it."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inventory():
    """The cloud tool's server inventory (local file), or an empty one."""
    import cloud

    try:
        return cloud.load_inventory()
    except FileNotFoundError:
        return dict(schema=1, resources={})


def provider_of(record):
    """The app's provider key for a recorded server ("own" for a plain SSH host)."""
    key = record.get("catalog") or record.get("provider")
    return key if key in keys() else "own"


def recorded_servers(inv):
    """Servers that can be hops, as the app shows them (addresses are the person's own)."""
    import cloud

    usable = cloud.servers() if inv.get("resources") else {}
    chain = (inv.get("chain") or {}).get("hops") or []
    out = []
    for name in sorted(usable):
        r = inv["resources"][name]
        key = provider_of(r)
        ip = r.get("public_ip", "")
        out.append(dict(
            name=name, provider=key, role=r.get("role"), region=r.get("region"),
            address=ip, family="ipv6" if ":" in ip else "ipv4",
            sphere=providers.sphere(key) or next((p["parent"] for p in providers.APP_CATALOG if p["key"] == key), None),
            in_chain=name in chain, first_hop_ok=":" not in ip,
        ))  # fmt: skip
    return out


def state():
    """Everything the setup screen shows, from local files only."""
    profile = load_profile()
    inv = inventory()
    servers = recorded_servers(inv)
    chain = inv.get("chain") or {}
    vault = chain.get("vault")
    with_servers = {s["provider"] for s in servers}
    return dict(
        schema=SCHEMA,
        profile=dict(
            name=profile["name"],
            created=profile["created"],
            providers=profile["providers"],
            hours_per_day=profile.get("hours_per_day", 8),
            checked={k: v for k, v in profile.get("checked", {}).items() if k in keys()},
            active_providers=len([k for k in profile["providers"] if k in with_servers]),
        ),  # fmt: skip
        servers=servers,
        chain=dict(
            hops=chain.get("hops") or [],
            created=chain.get("created"),
            operator_vault=bool(vault and Path(vault, "credential.json").exists()),
        ),  # fmt: skip
    )


def server_sign_in(record, quick=None):
    """(signed_in, profile) for the cloud sign-in one recorded server needs from here.

    Only AWS servers carry a sign-in that runs out (a console login session, per profile);
    the profile is the one the server was created with, not the CLI's default.
    """
    if record.get("provider") != "aws":
        return True, None
    profile = record.get("profile") or "default"
    exe = providers.cli_path("aws")
    if not exe:
        return False, profile
    argv = [exe, "sts", "get-caller-identity", "--profile", profile, "--output", "json"]
    if record.get("region"):
        argv += ["--region", record["region"]]
    return (quick or providers.quick)(argv), profile


def check(key):
    """Whether this provider's tool is installed and signed in (asks the provider, once)."""
    if key not in keys():
        raise Refused("unknown_provider")
    if key == "fly":
        import fly_api

        try:
            fly_api.token()
            ready, why = True, "deploy token present"
        except Exception:  # noqa: BLE001 (the reason is fixed text below)
            ready, why = False, "no Fly deploy token yet"
    elif key == "aws" and any(r.get("provider") == "aws" for r in inventory().get("resources", {}).values()):
        # Check the profiles the recorded servers use: the default one says nothing about them.
        results = {}
        for r in inventory()["resources"].values():
            if r.get("provider") == "aws":
                ok, profile = server_sign_in(r)
                results[profile] = results.get(profile, True) and ok
        out = sorted(p for p, ok in results.items() if not ok)
        ready = not out
        why = (
            ("signed in (profile %s)" % ", ".join(sorted(results)))
            if ready
            else ("sign-in ran out for profile %s" % ", ".join(out))
        )
    elif key in {p["key"] for p in providers.PROVIDERS} - {"own"}:
        ready, why = providers.readiness(providers.by_key(key))
    else:
        ready, why = True, "added as a server you run over SSH"
    profile = load_profile()
    profile.setdefault("checked", {})[key] = dict(ready=bool(ready), why=str(why)[:200], at=now())
    save_profile(profile)
    return dict(schema=SCHEMA, key=key, ready=bool(ready), why=str(why)[:200])


def sign_in(name, run=subprocess.run, quick=None):
    """Renew the AWS sign-in a recorded server uses: `aws login` opens the browser and takes
    the result on a local callback, so nothing is copied or pasted."""
    record = inventory().get("resources", {}).get(name) if NAME.fullmatch(name or "") else None
    if not record:
        raise Refused("unknown_server")
    if record.get("provider") != "aws":
        raise Refused("sign_in_not_needed")
    exe = providers.cli_path("aws")
    if not exe:
        raise Refused("aws_cli_missing")
    profile = record.get("profile") or "default"
    argv = [exe, "login", "--profile", profile]
    if record.get("region"):
        argv += ["--region", record["region"]]
    last = ""
    try:
        done = run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300, check=False)
        last = next((x.strip() for x in reversed((done.stderr or done.stdout or "").splitlines()) if x.strip()), "")
    except subprocess.TimeoutExpired:
        last = "the browser sign-in was not finished within 5 minutes"
    except OSError:
        raise Refused("aws_cli_missing") from None
    ready, _ = server_sign_in(record, quick)
    why = "signed in (profile %s)" % profile if ready else (last[-200:] or "not signed in")
    return dict(schema=SCHEMA, server=name, provider="aws", profile=profile, ready=ready, why=why)


def add(key):
    """Add a provider to the profile."""
    if key not in keys():
        raise Refused("unknown_provider")
    profile = load_profile()
    if key not in profile["providers"]:
        profile["providers"].append(key)
    save_profile(profile)
    return state()


def remove(key):
    """Drop a provider from the profile."""
    if key not in keys():
        raise Refused("unknown_provider")
    profile = load_profile()
    profile["providers"] = [k for k in profile["providers"] if k != key]
    save_profile(profile)
    return state()


def read_request(stream):
    """The device's public request from stdin: bounded, and shaped like one."""
    raw = stream.buffer.read(MAX_REQUEST + 1)
    if not raw or len(raw) > MAX_REQUEST:
        raise Refused("invalid_device_request")
    try:
        request = json.loads(raw)
    except ValueError:
        raise Refused("invalid_device_request") from None
    if not isinstance(request, dict) or request.get("role") != "client":
        raise Refused("invalid_device_request")
    return raw


def build_argv(order, hours, request_file, vault, source):
    """The one chain command this helper runs (fixed shape; checked names only)."""
    return [sys.executable, "-B", "-E", "-s", str(TOOLS / "cloud.py"), "chain", "--apply", "--yes",
            "--client-request", str(request_file), "--vault", str(vault), "--order", ",".join(order),
            "--hours-per-day", str(hours), "--source", str(source)]  # fmt: skip


def emit(**event):
    """One JSON event line for the app."""
    print(json.dumps(dict(schema=SCHEMA, **event)), flush=True)


def build(order, hours, stream=sys.stdin, run=subprocess.Popen):
    """Sign the recorded servers into one chain for this device and hand back its bundle."""
    import cloud

    inv = inventory()
    names = [n for n in order.split(",") if n]
    usable = cloud.servers() if inv.get("resources") else {}
    if not 1 <= len(names) <= 3 or len(set(names)) != len(names):
        raise Refused("one_to_three_different_servers")
    if any(not NAME.fullmatch(n) or n not in usable for n in names):
        raise Refused("unknown_server")
    if ":" in inv["resources"][names[0]].get("public_ip", ""):
        raise Refused("first_hop_needs_ipv4")
    if hours not in HOURS:
        raise Refused("invalid_hours")
    vault = (inv.get("chain") or {}).get("vault")
    if not vault or not Path(vault, "credential.json").exists():
        raise Refused("no_operator_vault")
    raw = read_request(stream)
    # Every sign-in the route needs, before the security key is asked for anything.
    for name in names:
        ok, profile = server_sign_in(inv["resources"][name])
        if not ok:
            emit(event="error", error="signed_out", provider="aws", server=name, profile=profile,
                 message="Your AWS sign-in for %s (profile %s) has run out. Sign in again, then build."
                 % (name, profile))  # fmt: skip
            return 1
    work = config_dir() / "desktop"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    request_file = work / ("client-%s.req" % stamp)
    write_private(request_file, raw.decode())
    profile = load_profile()
    profile["hours_per_day"] = hours
    save_profile(profile)
    source = PAYLOAD if (PAYLOAD / "target/release").is_dir() else TOOLS.parent
    env = dict(os.environ, AVPN_PROGRESS="events")
    process = run(build_argv(names, hours, request_file, vault, source), stdin=subprocess.DEVNULL,
                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)  # fmt: skip
    last = ""
    # The build's own words, kept beside the request (owner-only): a failure on a server
    # is otherwise gone once the app's window is closed.
    log = work / ("build-%s.log" % stamp)
    write_private(log, "")
    with open(log, "a") as record:
        for line in process.stderr:
            if line.startswith(cloud.PROGRESS_MARK):
                try:
                    emit(event="progress", **json.loads(line[len(cloud.PROGRESS_MARK) :]))
                except (ValueError, TypeError):
                    pass
            elif line.strip():
                record.write(line if line.endswith("\n") else line + "\n")
                record.flush()
                last = line.strip()[-300:]
    if process.wait() != 0:
        emit(event="error", message=last or "the chain could not be built", log=str(log))
        return 1
    built = load_inv_chain()
    bundles = Path(built["bundles"])
    client, operator = bundles / "client.avpn", bundles / "operator.pub"
    if client.stat().st_size > MAX_FILE or operator.stat().st_size > 8192:
        emit(event="error", message="the signed bundle is larger than the app accepts")
        return 1
    emit(
        event="done",
        hops=built["hops"],
        bundle_base64=base64.b64encode(client.read_bytes()).decode(),
        operator_base64=base64.b64encode(operator.read_bytes()).decode(),
    )
    return 0


def documents_dir():
    """The desktop's Documents folder (xdg-user-dirs), or ~/Documents."""
    try:
        out = subprocess.run(
            ["/usr/bin/xdg-user-dir", "DOCUMENTS"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if out and Path(out).is_dir() and Path(out) != Path.home():
            return Path(out)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return Path.home() / "Documents"


def export(stream=sys.stdin):
    """Save the device's public request as a file to send to an operator (join path)."""
    raw = read_request(stream)
    folder = documents_dir()
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = folder / ("cypherpunk-vpn-device-request-%s.req" % stamp)
    write_private(path, raw.decode())
    return dict(schema=SCHEMA, path=str(path))


def load_inv_chain():
    """The chain the cloud tool recorded last."""
    chain = inventory().get("chain") or {}
    if not chain.get("bundles"):
        raise Refused("chain_not_recorded")
    return chain


def main(argv=None):
    """Run one helper command; one JSON reply."""
    if os.geteuid() == 0:
        print(json.dumps(dict(schema=SCHEMA, error="run_as_your_user")))
        return 2
    parser = argparse.ArgumentParser(prog="avpn-desktop")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("state")
    sub.add_parser("export")
    for name in ("check", "add", "remove"):
        sub.add_parser(name).add_argument("key")
    sub.add_parser("signin").add_argument("server")
    b = sub.add_parser("build")
    b.add_argument("--order", required=True)
    b.add_argument("--hours", type=int, default=8)
    a = parser.parse_args(argv)
    try:
        if a.command == "build":
            return build(a.order, a.hours)
        result = dict(state=state, export=export, check=lambda: check(a.key), add=lambda: add(a.key),
                      remove=lambda: remove(a.key), signin=lambda: sign_in(a.server))[a.command]()  # fmt: skip
        print(json.dumps(result))
        return 0
    except Refused as e:
        print(json.dumps(dict(schema=SCHEMA, event="error", error=str(e))))
        return 1
    except Exception as e:  # noqa: BLE001 (one fixed line for the app, no trace)
        print(json.dumps(dict(schema=SCHEMA, event="error", error="failed", message=str(e)[:300])))
        return 1


if __name__ == "__main__":
    sys.exit(main())

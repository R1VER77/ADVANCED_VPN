#!/usr/bin/env python3
"""Privacy-budget lifecycle test: carrier restarts must not burn the allowance,
an exhausted opt-in cap must keep the guard and wait instead of exiting, and
the default (no cap) installs no meter.

Requires: unshare --user --map-root-user --map-auto --net --mount.
Refuses host root or any inherited network interface. No relay is needed: the
carrier is killed repeatedly while it retries its handshake.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from managed_profile import lab_setup  # noqa: E402
import shutil  # noqa: E402
from avpnctl import lab_guard, identity_of, runtime_dir  # noqa: E402

MIB = 1048576


def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=15)


def status(state):
    try:
        return json.loads((runtime_dir(state) / "status.json").read_text())
    except (OSError, ValueError):
        return {}


def wait(predicate, seconds, what):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("timeout: " + what)


def supervisor(state, log):
    args = [
        sys.executable,
        str(ROOT / "tools/avpnctl.py"),
        "--state",
        str(state),
        "--bin-dir",
        str(ROOT / "target/release"),
        "--lab",
        "connect",
    ]
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def carrier_pid(state, previous=None):
    child = status(state).get("children", {}).get("carrier")
    if child and child["alive"] and child["pid"] != previous and identity_of(child["pid"]) == child["identity"]:
        return child["pid"]
    return None


def meter_present():
    return run("/usr/sbin/nft", "list", "table", "inet", "advanced_vpn_meter", check=False).returncode == 0


def scenario(state, name, limit_mib, kills, prefill=False, raise_to=None):
    s = state / name
    shutil.copytree(state / "lab/client", s)  # same enrolled device identity per scenario
    if limit_mib is not None:
        (s / "preferences.json").write_text(json.dumps(dict(daily_limit_mib=limit_mib)))
    if prefill:
        import datetime as dt

        (s / "allowance.json").write_text(
            json.dumps(dict(day=dt.datetime.now(dt.timezone.utc).date().isoformat(), reserved=limit_mib * MIB))
        )
    log = (state / (name + ".log")).open("w")
    proc = supervisor(s, log)
    result = dict(kills=0)
    try:
        if kills:
            pid = wait(lambda: carrier_pid(s), 20, "first carrier")
            result["meter_installed"] = meter_present()
        else:
            # Exhaustion path: wait for the controller to report blocking.
            wait(lambda: proc.poll() is not None or status(s).get("state") == "blocked", 20, "budget decision")
            time.sleep(3)
            result["carrier_running_while_blocked"] = bool(carrier_pid(s))
            result["blocked_supervisor_alive"] = proc.poll() is None
            result["blocked_status"] = status(s).get("state")
            result["blocked_reason"] = status(s).get("reason")
            if raise_to is not None:
                # Raising the limit is an explicit preference; service must resume without a restart.
                run(
                    sys.executable,
                    str(ROOT / "tools/avpnctl.py"),
                    "--state",
                    str(s),
                    "--lab",
                    "preferences",
                    "--daily-limit-mib",
                    str(raise_to),
                )
                result["resumed_after_raise"] = bool(
                    wait(lambda: proc.poll() is None and carrier_pid(s), 45, "resume after raise")
                )
        for _ in range(kills):
            os.kill(pid, signal.SIGKILL)
            result["kills"] += 1
            try:
                pid = wait(lambda prev=pid: proc.poll() is not None or carrier_pid(s, prev), 25, "carrier relaunch")
            except AssertionError:
                break
            if pid is True:
                break
        time.sleep(1)
        result["supervisor_alive"] = proc.poll() is None
        result["status"] = status(s).get("state")
        result["reason"] = status(s).get("reason")
        result["kill_switch_retained"] = (
            run(
                "/usr/sbin/nft",
                "list",
                "table",
                "inet",
                "advanced_vpn",
                check=False,
            ).returncode
            == 0
            or run(
                "ip", "netns", "exec", "avpn-app", "/usr/sbin/nft", "list", "table", "inet", "advanced_vpn", check=False
            ).returncode
            == 0
        )
    finally:
        for child in status(s).get("children", {}).values():
            try:
                if identity_of(child["pid"]) == child["identity"]:
                    os.kill(child["pid"], signal.SIGTERM)
            except ProcessLookupError:
                pass
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        log.close()
        run(
            sys.executable,
            str(ROOT / "tools/avpnctl.py"),
            "--state",
            str(s),
            "--lab",
            "reset",
            "--allow-cleartext",
            check=False,
        )
    # Measured after a supervised stop, which settles the active grant.
    allowance = s / "allowance.json"
    result["reserved_mib"] = json.loads(allowance.read_text())["reserved"] / MIB if allowance.exists() else 0
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    lab_guard()
    if {r["ifname"] for r in json.loads(run("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    state = a.state.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    # Default enrollment: no daily cap. Capped scenarios opt in through preferences.
    (state / "lab").mkdir(mode=0o700)
    lab_setup(state / "lab", "192.0.2.1:41194", "198.51.100.2:4444", destinations=["203.0.113.0/30"])
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "size=64m", "tmpfs", "/run")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "u0", "type", "dummy")
    run("ip", "address", "add", "192.0.2.2/30", "dev", "u0")
    run("ip", "link", "set", "u0", "up")
    results = {}
    # Opt-in 256 MiB cap: twelve near-idle carrier restarts must not exhaust it,
    # and the supervisor must survive under its guard.
    results["capped_restarts"] = capped = scenario(state, "capped", 256, 12)
    # A cap smaller than one carrier grant: exhaustion blocks but must not end
    # the supervisor (systemd Restart=on-failure would never revive a clean exit).
    results["exhausted"] = exhausted = scenario(state, "exhausted", 1, 0, prefill=True, raise_to=128)
    # Default enrollment: no meter, no cap, restarts are free.
    results["default"] = default = scenario(state, "default", None, 3)
    (state / "RESULT.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results), flush=True)
    failures = []
    if not (capped["supervisor_alive"] and capped["kills"] == 12 and capped["reserved_mib"] < 64):
        failures.append("H1 restart reservations are not refunded")
    if not (
        exhausted.get("blocked_supervisor_alive")
        and exhausted.get("blocked_status") == "blocked"
        and exhausted.get("blocked_reason") == "privacy_budget"
        and not exhausted.get("carrier_running_while_blocked")
        and exhausted["kill_switch_retained"]
    ):
        failures.append("H2 exhausted budget ends the supervisor, runs the carrier or drops the guard")
    if not exhausted.get("resumed_after_raise"):
        failures.append("H2 raised limit does not resume service")
    if default["meter_installed"] or not default["supervisor_alive"] or default["reserved_mib"]:
        failures.append("H3 a cap is applied by default")
    if failures:
        raise SystemExit("FAILED: " + "; ".join(failures))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Freeze and run the counterbalanced lab replication without overwriting earlier data."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from wf_protocol import ORDERS, ROUND_SEEDS
from wf_real import host_power
from wf_pcap import library_path

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("advanced-vpn", "advanced-vpn-cloak", "advanced-vpn-wireguard", "advanced-vpn-dns")
RESERVE = 2 * 1024**3


@contextlib.contextmanager
def host_lock():
    """Refuse a second experiment even when it uses another output path."""
    path = Path(tempfile.gettempdir()) / f"cypherpunk-wf-collection-{os.getuid()}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise ValueError("unsafe experiment lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def sha256(path):
    """Hash a file without copying it into RAM."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def schedule():
    """Every arm ordering exactly once, with a distinct recorded site-order seed."""
    return [
        dict(round=i, seed=seed, variant=variant)
        for i, (seed, order) in enumerate(zip(ROUND_SEEDS, ORDERS, strict=True), 1)
        for variant in order
    ]


def arm_environment(parent, variant):
    """Never inherit another experiment's AVPN overrides, including in the control."""
    env = {k: v for k, v in parent.items() if not k.startswith("AVPN_")}
    if variant != "undefended":
        env.update(
            AVPN_WIRE_CLOCK_PPS="4000",
            AVPN_WIRE_CLOCK_DOWNSTREAM="1",
            AVPN_WIRE_CLOCK_MS="30",
            AVPN_CATCH_UP_MS="50",
            AVPN_WIRE_CLOCK_RELAY_MS=variant.removeprefix("relay"),
        )
    env.update(OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1")
    return env


def resource_snapshot():
    """Record coarse host conditions without process arguments, credentials or browsing contents."""
    snapshot = dict(
        time=time.time(), monotonic=time.monotonic(), power=host_power(), load_average=list(os.getloadavg())
    )
    for name, path in (("cpu_pressure", "/proc/pressure/cpu"), ("memory_pressure", "/proc/pressure/memory")):
        try:
            snapshot[name] = Path(path).read_text().strip()
        except OSError:
            snapshot[name] = None
    builds = []
    for directory in Path("/proc").glob("[0-9]*"):
        try:
            name = (directory / "comm").read_text().strip()
            if name in {"rustc", "cargo", "cc1", "cc1plus", "ld.lld", "clang", "clang++", "nvcc", "llama-cli"}:
                builds.append(name)
        except OSError:
            pass
    snapshot["concurrent_build_or_inference"] = sorted(builds)
    return snapshot


def write_json(path, value):
    """Atomically update an experiment-owned progress file."""
    pending = path.with_name(path.name + ".next")
    pending.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    os.replace(pending, path)


def validate_host_conditions(sample):
    """Apply the same recorded power/load gate before, during and after each arm."""
    if sample["concurrent_build_or_inference"]:
        raise RuntimeError("build or inference is active; preserve this stopped experiment")
    if sample["power"]["on_mains"] is False:
        raise RuntimeError("power changed to battery operation during collection")


def projected_bytes(attempts=720):
    """Conservative 45-second attempts, both clock directions and metadata/log overhead."""
    return int(attempts * 45 * 8000 * 12 + 256 * 1024**2)


def package_inventory(executable):
    """Inventory installed distributions using the standard library, without requiring pip."""
    code = (
        "import importlib.metadata,json; "
        "print(json.dumps(sorted((d.metadata.get('Name',''),d.version) "
        "for d in importlib.metadata.distributions()),separators=(',',':')))"
    )
    return subprocess.run(
        [str(executable), "-I", "-c", code], capture_output=True, text=True, check=True, timeout=30
    ).stdout


def prepare(args):
    """Create a new private source/binary snapshot and immutable experiment specification."""
    if not set(range(5)) <= os.sched_getaffinity(0):
        raise RuntimeError("the saved client/server/recorder CPU placement requires CPUs 0 through 4")
    sites = json.loads(args.sites.read_text())
    if (
        len(sites.get("monitored", [])) != 20
        or len(set(sites["monitored"])) != 20
        or sites.get("loads") != 2
        or sites.get("open_world", [])
    ):
        raise ValueError("use the saved 20-site, two-load, closed-world design")
    if shutil.disk_usage(args.out.parent).free < projected_bytes() + RESERVE:
        raise RuntimeError("insufficient storage for collection and the 2 GiB reserve")
    args.out.mkdir(mode=0o700, exist_ok=False)
    frozen = args.out / "frozen"
    frozen.mkdir(mode=0o700)
    shutil.copytree(ROOT / "tools", frozen / "tools", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    source = frozen / "rust-source"
    source.mkdir()
    for name in ("src", "vendor", "crates", "docs/cli"):
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            ROOT / name, destination, ignore=shutil.ignore_patterns("target", ".git", "__pycache__", "*.pyc")
        )
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE", "NOTICE"):
        shutil.copy2(ROOT / name, source / name)
    binaries = frozen / "bin"
    binaries.mkdir()
    for name in BINARIES:
        shutil.copy2(args.bin_dir / name, binaries / name)
    (args.out / "sites.json").write_text(json.dumps(sites, sort_keys=True) + "\n")
    paths = dict(
        python=Path(sys.executable).absolute(),
        browser_python=args.browser_python.absolute(),
        firefox=args.firefox.absolute(),
        geckodriver=args.geckodriver.absolute(),
        pasta=args.pasta.absolute(),
        ethtool=args.ethtool.absolute(),
        nsenter=Path("/usr/bin/nsenter"),
    )
    external = {
        name: dict(path=str(path), resolved=str(path.resolve(strict=True)), sha256=sha256(path))
        for name, path in paths.items()
    }
    pcap = library_path()
    libraries = dict(libpcap=dict(path=str(pcap), resolved=str(pcap), sha256=sha256(pcap)))
    for name in ("python", "browser_python"):
        (args.out / (name + "-packages.json")).write_text(package_inventory(paths[name]))
    diff = subprocess.run(
        ["/usr/bin/git", "diff", "--binary", "HEAD"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    (args.out / "source-tracked-diff.patch").write_bytes(diff)
    files = {str(p.relative_to(args.out)): sha256(p) for p in sorted(frozen.rglob("*")) if p.is_file()}
    for p in (args.out / "sites.json", args.out / "python-packages.json", args.out / "browser_python-packages.json"):
        files[str(p.relative_to(args.out))] = sha256(p)
    manifest = dict(
        schema=1,
        status="prepared",
        source_commit=subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        tracked_diff_sha256=hashlib.sha256(diff).hexdigest(),
        files=files,
        executables=external,
        shared_libraries=libraries,
        schedule=schedule(),
        attempts=720,
        client_cpus="0,1",
        server_cpus="2,3",
        capture_cpus="4",
        capture_bytes_projected=projected_bytes(),
        reserve_bytes=RESERVE,
        timestamp_source="linux_pcap_host_ns",
        observation_interval_seconds=0.5,
        positive_control_gate=0.8,
        direction_control_gate="each view exceeds chance by 0.05 with Holm-corrected p <= 0.05",
        classifier_upper_margin=0.05,
        success_noninferiority_margin=0.05,
        primary="all full fixed windows; failed loads retained; exclusion invalidates collection gate",
        comparisons="Holm family across nine primary variant/direction views",
        permutations_minimum=1000,
        limitations=[
            "One host/network experiment cannot qualify the required cross-environment replication",
            "Protection is sampled; capture audit allowlists underlay metadata without inspecting application payloads",
        ],
    )
    write_json(args.out / "manifest.json", manifest)
    print(json.dumps(dict(status="prepared", out=str(args.out), attempts=720)))


def verify_frozen(root, manifest):
    """Refuse changed source, executables, sites or interpreter package inventories."""
    if manifest.get("schema") != 1 or manifest.get("schedule") != schedule():
        raise ValueError("manifest does not match the prespecified schedule")
    for name, expected in manifest["files"].items():
        if sha256(root / name) != expected:
            raise RuntimeError("frozen experiment file changed: " + name)
    for name, value in {**manifest["executables"], **manifest.get("shared_libraries", {})}.items():
        if (
            str(Path(value["path"]).resolve(strict=True)) != value["resolved"]
            or sha256(value["path"]) != value["sha256"]
        ):
            raise RuntimeError("experiment executable changed: " + name)
    for name in ("python", "browser_python"):
        if package_inventory(manifest["executables"][name]["path"]) != (root / (name + "-packages.json")).read_text():
            raise RuntimeError("interpreter package inventory changed: " + name)
    if shutil.disk_usage(root).free < RESERVE:
        raise RuntimeError("storage is below the experiment reserve")


def collect(root):
    """Run arms serially, stop at any failure, and retain the failed attempt's evidence."""
    root = root.resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text())
    with host_lock(), (root / ".collection.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (root / "RUN.json").exists():
            raise ValueError("this run was already started; create a new experiment rather than overwriting it")
        result = dict(
            schema=1, status="running", started=time.time(), arms=[], manifest_sha256=sha256(root / "manifest.json")
        )
        write_json(root / "RUN.json", result)
        try:
            for arm in manifest["schedule"]:
                verify_frozen(root, manifest)
                before = resource_snapshot()
                validate_host_conditions(before)
                entry = dict(**arm, started=time.time(), before=before, status="running")
                result["arms"].append(entry)
                write_json(root / "RUN.json", result)
                destination = root / f"r{arm['round']}-{arm['variant']}"
                exe = {key: value["path"] for key, value in manifest["executables"].items()}
                argv = [
                    exe["python"],
                    str(root / "frozen/tools/wf_real.py"),
                    "collect",
                    "--config",
                    "undefended" if arm["variant"] == "undefended" else "fast",
                    "--sites",
                    str(root / "sites.json"),
                    "--out",
                    str(destination),
                    "--bin-dir",
                    str(root / "frozen/bin"),
                    "--workers",
                    "1",
                    "--client-cpus",
                    "0,1",
                    "--server-cpus",
                    "2,3",
                    "--capture-cpus",
                    "4",
                    "--seed",
                    str(arm["seed"]),
                    "--pasta",
                    exe["pasta"],
                    "--geckodriver",
                    exe["geckodriver"],
                    "--python",
                    exe["browser_python"],
                    "--ethtool",
                    exe["ethtool"],
                    "--firefox",
                    exe["firefox"],
                ]
                with (
                    (root / f"r{arm['round']}-{arm['variant']}.log").open("x") as log,
                    (root / f"r{arm['round']}-{arm['variant']}.host.jsonl").open("x") as telemetry,
                ):
                    process = subprocess.Popen(
                        argv,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        env=arm_environment(os.environ, arm["variant"]),
                        start_new_session=True,
                    )
                    try:
                        while process.poll() is None:
                            sampled = resource_snapshot()
                            telemetry.write(json.dumps(sampled) + "\n")
                            telemetry.flush()
                            validate_host_conditions(sampled)
                            if shutil.disk_usage(root).free < RESERVE:
                                raise RuntimeError("storage reserve reached during collection")
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                pass
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGTERM)
                            try:
                                process.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait(timeout=5)
                    entry.update(stopped=time.time(), exit_code=process.returncode, after=resource_snapshot())
                    validate_host_conditions(entry["after"])
                    if process.returncode != 0:
                        entry["status"] = "failed"
                        raise RuntimeError("collection arm failed: " + destination.name)
                verify_frozen(root, manifest)
                rows = (destination / "w0/loads.jsonl").read_text().splitlines()
                if len(rows) != 40:
                    raise RuntimeError("collection arm did not record every planned attempt")
                entry.update(status="complete", attempts=len(rows))
                write_json(root / "RUN.json", result)
                print(destination.name, "complete", flush=True)
            result.update(status="complete", stopped=time.time())
        except BaseException as error:
            result.update(status="failed", stopped=time.time(), failure=type(error).__name__ + ": " + str(error))
            raise
        finally:
            write_json(root / "RUN.json", result)


def main():
    """Prepare a new immutable experiment or run its frozen arms."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--sites", type=Path, required=True)
    p.add_argument("--bin-dir", type=Path, required=True)
    p.add_argument("--pasta", type=Path, required=True)
    p.add_argument("--geckodriver", type=Path, required=True)
    p.add_argument("--browser-python", type=Path, required=True)
    p.add_argument("--firefox", type=Path, default=Path("/usr/bin/firefox-esr"))
    p.add_argument("--ethtool", type=Path, default=Path("/usr/sbin/ethtool"))
    commands.add_parser("run").add_argument("out", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() == 0:
        parser.error("run the experiment as an ordinary user")

    def interrupted(*_):
        raise SystemExit("experiment interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    prepare(args) if args.command == "prepare" else collect(args.out)


if __name__ == "__main__":
    main()

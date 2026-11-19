#!/usr/bin/env python3
"""Test additional authenticators against real VPN key/enrollment operations.

Backends use Solo 1 or CanoKey upstream PC authenticators. A private,
networkless Docker container transports actual CTAPHID frames over loopback UDP.
It receives no host USB devices, home directory, credentials or signing keys.
Only transport/discovery and the virtual token's test PIN input are substituted;
the production credential, signature, KEM and sealing code runs unchanged.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOLO_SOURCE = "fc8d2867c5ba8161302b809c80fa1fd6a4df94a2"
CANOKEY_SOURCE = "a349b268e12953dd85169e9649091c4f91ce7c68"
BACKENDS = {
    "solo1-pc": dict(
        source=SOLO_SOURCE,
        scope="actual_solo_pc_firmware_with_udp_ctaphid_transport_and_production_vpn_crypto",
        build="4.1.5-8-gfc8d286, upstream PC Makefile, SOLO_EXPERIMENTAL=1",
        limitation="Experimental PC firmware, not a shipped physical Solo 1 qualification.",
    ),
    "canokey-udp": dict(
        source=CANOKEY_SOURCE,
        scope="actual_canokey_core_firmware_with_udp_ctaphid_transport_and_production_vpn_crypto",
        build="upstream fido-hid-over-udp; ENABLE_TESTS=ON; ASan/UBSan; simulated presence",
        limitation="Upstream virtual firmware, not a shipped CanoKey Pigeon/Canary qualification.",
    ),
}


def digest(path):
    """Hash an input without retaining its complete contents."""
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def isolated_environment():
    """Reject root, external networking and exposed host authenticator interfaces."""
    if os.geteuid() == 0 or list(Path("/dev").glob("hidraw*")) or Path("/dev/bus/usb").exists():
        raise RuntimeError("virtual test requires a non-root process without host USB access")
    interfaces = {row.split(":", 1)[0].strip() for row in Path("/proc/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("virtual test requires a private loopback-only network")


def udp_device(timeout=4):
    """Transport real 64-byte upstream PC CTAPHID frames, not simulated crypto results."""
    from fido2.hid import CtapHidConnection, CtapHidDevice, HidDescriptor

    class Connection(CtapHidConnection):
        def __init__(self):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(("127.0.0.1", 7112))
            self.sock.settimeout(timeout)

        def read_packet(self):
            data, address = self.sock.recvfrom(65)
            if len(data) != 64 or address != ("127.0.0.1", 8111):
                raise ValueError("invalid simulator response frame")
            return data

        def write_packet(self, data):
            if len(data) != 64:
                raise ValueError("invalid outbound simulator frame")
            self.sock.sendto(data, ("127.0.0.1", 8111))

        def close(self):
            self.sock.close()

    connection = Connection()
    try:
        # No vendor/product identifier is forged to make the generic transport
        # look like a physical vendor unit to production repair logic.
        return CtapHidDevice(
            HidDescriptor("firmware-test-udp", 0, 0, 64, 64, "Upstream firmware test only", None), connection
        )
    except BaseException:
        connection.close()
        raise


def operations(work, result, test_pin):
    """Exercise shipping key/sealing/enrollment code with the actual authenticator."""
    import hardware_setup_test
    import keyguard
    import managed_profile
    from cryptography.exceptions import InvalidSignature
    from fido2.hid import CtapHidDevice
    from fido2.ctap import CtapError
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialParameters, PublicKeyCredentialType

    class EdOnlyServer(Fido2Server):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.allowed_algorithms = [PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-8)]

    with (
        mock.patch.object(CtapHidDevice, "list_devices", side_effect=lambda: iter([udp_device()])),
        mock.patch.object(keyguard, "pinentry", return_value=test_pin),
    ):
        result["phases"]["fresh_assertion_roundtrip"] = hardware_setup_test.roundtrip(work)
        vault = work / "operator-vault"
        keyguard.enroll(vault)
        result["default_credential_cose_algorithm"] = keyguard._verifying_key(keyguard.credential_public(vault)).get(3)
        signer = managed_profile.HardwareOperator(vault)
        message = secrets.token_bytes(32)
        classical, pq = signer.sign(message)
        managed_profile.verify_operator(signer.public(), message, classical, pq)
        wrong_message_refused = False
        try:
            managed_profile.verify_operator(signer.public(), message + b"wrong", classical, pq)
        except ValueError:
            wrong_message_refused = True
        if not wrong_message_refused:
            raise AssertionError("wrong-message signature accepted")
        bad_classical = dict(classical)
        bad_bytes = bytearray(keyguard.unb64(classical["signature"]))
        bad_bytes[-1] ^= 1
        bad_classical["signature"] = keyguard.b64(bytes(bad_bytes))
        bad_pq = bytearray(pq)
        bad_pq[-1] ^= 1
        for first, second in ((bad_classical, pq), (classical, bytes(bad_pq))):
            refused = False
            try:
                managed_profile.verify_operator(signer.public(), message, first, second)
            except (ValueError, InvalidSignature):
                refused = True
            if not refused:
                raise AssertionError("one invalid half of the operator signature was accepted")
        result["phases"]["operator_dual_signature"] = dict(
            fido_verified=True,
            mldsa65_verified=True,
            wrong_message_refused=True,
            invalid_fido_half_refused=True,
            invalid_mldsa_half_refused=True,
        )
        second_salt = secrets.token_bytes(32)
        first, _, assertion, second = keyguard.hardware_assertion(vault, message=message, salt2=second_salt)
        keyguard.verify_assertion(keyguard.credential_public(vault), message, assertion)
        again, _, _, second_again = keyguard.hardware_assertion(vault, message=message, salt2=second_salt)
        if not (len(first) == len(second) == 32 and first == again and second == second_again and first != second):
            raise AssertionError("two-salt secret derivation did not satisfy the expected properties")
        result["phases"]["two_salt_hmac_secret"] = dict(stable=True, separated=True, assertion_verified=True)
        for role in ("client", "relay", "exit"):
            state = work / (role + "-keys")
            request = managed_profile.request(role, state, "nitrokey", vault)
            secret, meta = keyguard.hardware_secret(vault)
            names = [p.name.removesuffix("-key.sealed.json") for p in state.glob("*-key.sealed.json")]
            if not names:
                raise AssertionError("no protected VPN keys generated")
            opened = managed_profile.load_keys(state, names, secret, meta)
            if not all(opened.values()):
                raise AssertionError("generated key did not unseal")
            result["phases"][role + "_key_generation"] = dict(role=request["role"], sealed_keys_opened=len(opened))
        lab = work / "enrollment"
        lab.mkdir(mode=0o700)
        managed_profile.lab_setup(
            lab, None, "127.0.0.1:4433", hops=1, protect={"client": "nitrokey"}, vault=vault, operator=signer
        )
        if not (lab / "client/profile.json").is_file():
            raise AssertionError("signed client enrollment not installed")
        result["phases"]["signed_client_enrollment"] = dict(signed_bundle_imported=True, hybrid_delivery_verified=True)
        with mock.patch("fido2.server.Fido2Server", EdOnlyServer):
            edvault = work / "ed25519-vault"
            try:
                keyguard.enroll(edvault)
            except CtapError as error:
                if error.code != CtapError.ERR.UNSUPPORTED_ALGORITHM:
                    raise
                result["phases"]["ed25519_credential"] = dict(supported=False, reason="unsupported_algorithm")
            else:
                algorithm = keyguard._verifying_key(keyguard.credential_public(edvault)).get(3)
                if algorithm != -8:
                    raise AssertionError("Ed25519-only request silently changed its algorithm")
                _, _, assertion = keyguard.hardware_assertion(edvault, message=message)
                keyguard.verify_assertion(keyguard.credential_public(edvault), message, assertion)
                result["phases"]["ed25519_credential"] = dict(
                    supported=True, actual_cose_algorithm=algorithm, assertion_verified=True
                )


def worker(out, vpn_commit, backend="solo1-pc"):
    """Internal container worker; owns disposable state and emits no secret values."""
    isolated_environment()
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin

    work = out / "state"
    work.mkdir(mode=0o700)
    selected = BACKENDS[backend]
    result = dict(
        schema=1,
        status="failed",
        scope=selected["scope"],
        backend=backend,
        vpn_source_commit=vpn_commit,
        firmware_source_commit=selected["source"],
        firmware_build=selected["build"],
        binary_sha256=digest(Path("/simulator")),
        harness_sha256=digest(Path(__file__)),
        started=time.time(),
        phases={},
        physical_device_tested=False,
        tunnel_connection_tested=False,
        strict_hardware_eligible=False,
        strict_block_reason="CTAP PIN/UV protocols 1/2 use P-256; choosing Ed25519 does not change this channel",
        limitations=[
            selected["limitation"],
            "Actual CTAPHID uses UDP transport; USB permissions and physical security are not tested.",
            "No native PIN/presence UI, live tunnel or strict all-interface PQ qualification.",
            "Only test discovery/transport/PIN input are substituted; production crypto is unchanged.",
        ],
    )
    process = None
    simulator_log = None

    def deadline(*_):
        raise TimeoutError("virtual test deadline")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(120)
    try:
        result["stage"] = "simulator_start"
        simulator_log = (out / "simulator.log").open("xb")
        environment = dict(os.environ)
        if backend == "canokey-udp":
            environment.update(
                CANOKEY_VIRT_LFS_ROOT=str(work / "device-lfs"),
                CANOKEY_VIRT_RESET_STORAGE="1",
                ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                UBSAN_OPTIONS="halt_on_error=1",
            )
        process = subprocess.Popen(
            ["/simulator"],
            cwd=work,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=simulator_log,
            stderr=simulator_log,
        )
        time.sleep(0.5)
        if process.poll() is not None:
            raise RuntimeError("simulator exited")
        result["stage"] = "ctaphid_initialization"
        # CanoKey's own virtual-card fabrication simulates five timed presence
        # steps before serving HID. Allow that startup, without weakening the
        # ordinary operation deadline or the production hardware code.
        device = udp_device(timeout=30 if backend == "canokey-udp" else 4)
        try:
            result["stage"] = "get_info"
            ctap = Ctap2(device)
            info = ctap.info
            result["get_info"] = dict(
                versions=info.versions,
                extensions=info.extensions,
                algorithms=info.algorithms,
                pin_uv_protocols=info.pin_uv_protocols,
            )
            test_pin = secrets.token_hex(8)
            result["stage"] = "virtual_pin_initialization"
            ClientPin(ctap).set_pin(test_pin)  # Only the isolated disposable software token.
        finally:
            device.close()
        result["stage"] = "production_vpn_operations"
        operations(work, result, test_pin)
        if process.poll() is not None:
            raise RuntimeError("simulator terminated during operations")
        result["status"] = "passed_key_sealing_operator_and_enrollment_operations"
        result["stage"] = "completed"
    except Exception as error:
        result["error_type"] = type(error).__name__
        code = getattr(error, "code", None)
        if code is not None:
            result["ctap_error_code"] = int(code)
    finally:
        signal.alarm(0)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if simulator_log is not None:
            simulator_log.close()
        shutil.rmtree(work)
        result["disposable_secret_state_removed"] = True
        result["stopped"] = time.time()
        result["production_source_sha256"] = {
            name: digest(ROOT / "tools" / name)
            for name in ("keyguard.py", "managed_profile.py", "hardware_setup_test.py")
        }
        (out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"].startswith("passed") else 1


def run(args):
    """Create an owned, constrained container; no host device or credential mounts."""
    import bundled_runtime
    from sysexec import trusted_exe

    if os.geteuid() == 0:
        raise RuntimeError("run the laboratory as the ordinary user")
    if args.build_record.stat().st_size > 65536:
        raise ValueError("oversized build record")
    build = json.loads(args.build_record.read_text())
    image = build["image_id"]
    simulator = args.simulator.resolve(strict=True)
    runtime = args.runtime.resolve(strict=True)
    out = args.out.absolute()
    if build.get("source_commit") != BACKENDS[args.backend]["source"] or not re.fullmatch(
        r"sha256:[a-f0-9]{64}", image
    ):
        raise ValueError("unrecognized firmware build identity")
    if not simulator.is_file() or digest(simulator) != build["binary_sha256"]:
        raise ValueError("simulator does not match the reviewed build record")
    bundled_runtime.verify(runtime, ROOT / "tools/hardware-requirements.txt")
    for path in (ROOT, simulator, runtime, out):
        if "," in str(path) or any(ord(c) < 32 for c in str(path)):
            raise ValueError("unsafe container mount path")
    docker = trusted_exe("docker")
    commit = subprocess.check_output([trusted_exe("git"), "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("invalid source revision")
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    name = "cypherpunk-device-lab-" + uuid.uuid4().hex
    argv = [
        docker, "create", "--name", name, "--label", "org.cypherpunk-vpn.device-lab=" + name,
        "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "512m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",  # noqa: S108 -- private container tmpfs, not host storage
    ]  # fmt: skip
    for source, target, readonly in (
        (ROOT, "/src", True),
        (runtime, "/runtime", True),
        (simulator, "/simulator", True),
        (out, "/out", False),
    ):
        argv.extend(["--mount", f"type=bind,source={source},target={target}" + (",readonly" if readonly else "")])
    argv.extend([
        image, "/runtime/bin/python3", "-B", "-E", "-s", "/src/tools/device_compatibility_lab.py",
        "--worker", "--out", "/out", "--vpn-source-commit", commit, "--backend", args.backend,
    ])  # fmt: skip
    created = False
    try:
        subprocess.run(argv, check=True, capture_output=True, timeout=30)
        created = True
        config = json.loads(subprocess.check_output([docker, "inspect", name], text=True, timeout=20))[0]
        host = config["HostConfig"]
        if host["NetworkMode"] != "none" or host["Privileged"] or host.get("Devices"):
            raise RuntimeError("unexpected container isolation configuration")
        (out / "SANDBOX.json").write_text(json.dumps(dict(
            image_id=config["Image"], network_mode=host["NetworkMode"], read_only=host["ReadonlyRootfs"],
            cap_drop=host["CapDrop"], user=config["Config"]["User"], mounts=config["Mounts"],
        ), indent=2) + "\n")  # fmt: skip
        with (out / "console.log").open("x") as log:
            completed = subprocess.run([docker, "start", "--attach", name], stdout=log, stderr=log, timeout=150)
        result = json.loads((out / "RESULT.json").read_text())
        print(json.dumps(dict(status=result["status"], evidence=str(out / "RESULT.json"))))
        return completed.returncode
    finally:
        if created:
            subprocess.run([docker, "rm", "--force", name], check=True, capture_output=True, timeout=30)
            if (out / "state").exists():
                shutil.rmtree(out / "state")


def main():
    """Only this explicit laboratory CLI exposes virtual transport, never the broker."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=tuple(BACKENDS), default="solo1-pc")
    parser.add_argument("--simulator", type=Path)
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--vpn-source-commit", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.worker:
        return worker(args.out, args.vpn_source_commit, args.backend)
    if any(value is None for value in (args.simulator, args.build_record, args.runtime)):
        parser.error("--simulator, --build-record and --runtime are required")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Private root broker worker. Only inherited pipes accept requests; no public socket.

The native D-Bus service authenticates the sender and authorizes every request.
Production state paths and commands below are fixed; no CLI fixture/root override.
"""

import contextlib
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import pwd
import selectors
import subprocess
import sys
import tempfile
import time

import avpnctl
from controller_bridge import Broker, Caller, MAX_REQUEST, Refused, blob, canonical
import controller_mutation
import controller_request
import controller_status
import hwkey
import keyguard
import managed_profile
import setup_cli
import setup_flow

ROOT = Path(__file__).resolve().parents[1]
STATE = Path("/etc/advanced-vpn/enrolled")


class Adapter:
    """The existing controller owns all configuration, repairs and security verdicts."""

    def locked(self):
        """Share the cooperating CLI's short-mutation lock."""
        return controller_mutation.locked(STATE)

    def generation(self):
        """Opaque public digest, never a rollback mechanism for private state."""
        value = hashlib.sha256(b"cypherpunk/controller-generation/v1\0")
        for name in (
            "request.json",
            "profile.json",
            "preferences.json",
            "protection.json",
            "operator.pub",
            "ENROLLMENT.json",
        ):
            path = STATE / name
            value.update(name.encode() + b"\0")
            if path.exists() or path.is_symlink():
                value.update(keyguard.read_private(path, limit=1024 * 1024))
            else:
                value.update(b"absent")
        return value.hexdigest()

    def diagnostics(self, caller):
        """Check the actual caller's ACLs, rather than root's ability to open any key."""
        if caller.uid == 0:
            raise Refused("ordinary_user_required")
        person = pwd.getpwuid(caller.uid)
        process = subprocess.Popen(
            [str(ROOT / "venv/bin/python3"), "-B", "-E", "-s", str(ROOT / "tools/hardware_probe.py")],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            user=caller.uid,
            group=person.pw_gid,
            extra_groups=os.getgrouplist(person.pw_name, person.pw_gid),
            env=dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin", HOME=person.pw_dir, LC_ALL="C"),
        )
        # This is an ordinary-user process: its owner could modify it. Enforce
        # bounds in root's reader, irrespective of what the helper itself prints.
        output = bytearray()
        deadline = time.monotonic() + 20
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    if time.monotonic() >= deadline:
                        raise Refused("hardware_probe_timeout")
                    if not selector.select(0.1):
                        continue
                    block = os.read(process.stdout.fileno(), 8192)
                    if not block:
                        break
                    output.extend(block)
                    if len(output) > 65536:
                        raise Refused("hardware_report_too_large")
            if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise Refused("hardware_probe_failed")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process.stdout.close()
        report = json.loads(output)
        if report.get("schema") != 1 or not isinstance(report.get("findings"), list) or len(report["findings"]) > 64:
            raise Refused("invalid_hardware_report")
        return [hwkey.Finding(**f) for f in report["findings"]]

    @contextlib.contextmanager
    def import_files(self, request):
        """Only decoded bounded bytes enter root-owned temporary files on /run tmpfs."""
        runtime = avpnctl.runtime_dir(STATE)
        with tempfile.TemporaryDirectory(prefix="bundle-review-", dir=runtime) as directory:
            directory = Path(directory)
            bundle, operator = directory / "device.avpn", directory / "operator.pub"
            for path, raw in (
                (bundle, blob(request["bundle_base64"], 1024 * 1024)),
                (operator, blob(request["operator_key_base64"], 8192)),
            ):
                with path.open("xb") as stream:
                    stream.write(raw)
                path.chmod(0o600)
            yield bundle, operator

    def prepare(self, caller, request):
        """Inert, current preconditions and the canonical effect list shown for approval."""
        name = request["action"]
        public_inputs = dict(action=request, generation=self.generation())
        if name == "repair":
            findings = self.diagnostics(caller)
            repair, confirmation = setup_cli.repair_plan(request["repair"], findings, request["selector"])
            public_inputs.update(repair=asdict(repair), confirmation=confirmation)
            summary, effects = (
                repair.summary,
                [
                    "Selected device: " + str(request["selector"] or confirmation),
                    repair.changes,
                    "Undo: " + repair.undo,
                ],
            )
        elif name == "request_device":
            if STATE.exists() or STATE.is_symlink():
                raise Refused("device_state_already_exists_use_recovery")
            findings = self.diagnostics(caller)
            if sum(f.code == "key_ready" for f in findings) != 1 or any(f.severity == "blocker" for f in findings):
                raise Refused("select_one_supported_accessible_key")
            public_inputs["hardware"] = [asdict(f) for f in findings]
            summary = "Create this device's VPN credential and public request"
            effects = [
                "Use trusted native PIN/device prompts and touch confirmation.",
                "Create an isolated VPN credential and protect new client keys under it.",
                "Keep existing wallet material, applications, PINs and credentials.",
            ]
        elif name == "import_bundle":
            if avpnctl.service_active():
                raise Refused("disconnect_before_import")
            with self.import_files(request) as (bundle, operator):
                checked = managed_profile.inspect_enrollment_bundle(bundle, operator, STATE, request["replace"])
            if checked["profile"]["role"] != "client":
                raise Refused("desktop_enrollment_is_client_only")
            fingerprint = hashlib.sha256(checked["raw_operator"]).hexdigest()
            public_inputs["operator_sha256"] = fingerprint
            summary = "Import the verified signed client route"
            effects = [
                "Trust operator public-key file SHA-256: " + fingerprint,
                "Verify both operator signatures and bind the route to this device's own keys.",
                "Unseal and protect the route's delivered keys through the trusted hardware prompt.",
                "Replace the installed route." if request["replace"] else "Install this device's first route.",
                "Keep networking inactive until a separate connection approval.",
            ]
        elif name == "unlock":
            if not avpnctl.pin_pending():
                raise Refused("no_pending_hardware_prompt")
            summary, effects = (
                "Answer the controller's hardware prompt",
                [
                    "Open the trusted native PIN dialog for this desktop user.",
                    "Unlocking does not remove the traffic guard.",
                ],
            )
        elif name in ("connect", "retry"):
            profile = managed_profile.require_current(avpnctl.load_profile(STATE))
            if profile["role"] != "client":
                raise Refused("desktop_connection_is_client_only")
            pref = avpnctl.read_json_private(STATE / "preferences.json", {})
            desired = request.get("scope", pref.get("mode", "applications"))
            if avpnctl.service_active() and desired != pref.get("mode", "applications"):
                raise Refused("disconnect_before_changing_scope")
            public_inputs["scope"] = desired
            summary = "Connect the signed route" if name == "connect" else "Retry the signed route"
            effects = [
                "Connection scope: " + desired + ".",
                "Retain the guard throughout connection and failure recovery.",
                "Start the existing verified controller service; hardware authentication stays in a trusted prompt.",
            ]
        elif name == "disconnect":
            summary, effects = (
                "Disconnect and retain protection",
                ["Stop the current supervisor and its owned transports.", "Keep existing traffic guards in place."],
            )
        elif name in ("create_operator_keys", "request_exit", "sign_route"):
            # The setup wizard's create-branch writes (tools/controller_create_join.py):
            # exact hardcoded argv, validated fields, previews that re-verify the world.
            import controller_create_join

            prepared = controller_create_join.prepare(
                request.get("branch"),
                name,
                {k: v for k, v in request.items() if k not in ("action", "branch")},
                controller_create_join.paths(),
            )
            if prepared is None:
                raise Refused("unknown_action")
            public_inputs.update(wizard=prepared)
            summary, effects = prepared["summary"], prepared["effects"]
        else:
            raise Refused("unknown_action")
        return dict(
            summary=summary, effects=effects, checked_inputs=hashlib.sha256(canonical(public_inputs)).hexdigest()
        )

    def dispatch(self, arguments):
        """Only hardcoded operations construct controller arguments."""
        parsed = avpnctl.build_parser().parse_args(
            ["--state", str(STATE), "--bin-dir", str(ROOT / "bin"), "--json", *arguments]
        )
        from keyguard import one_pin

        with one_pin():  # one PIN for this one operation, never for the broker's lifetime
            avpnctl.dispatch(parsed)

    def execute(self, caller, request, cancel, progress):
        """A cancellation never resets devices, discards counters or clears a guard."""
        if cancel.is_set():
            raise InterruptedError
        try:
            with keyguard.authenticated_prompt(caller.uid, cancel):
                name = request["action"]
                if name == "repair":
                    repair, confirmation = setup_cli.repair_plan(
                        request["repair"], self.diagnostics(caller), request["selector"]
                    )
                    args = ["setup", "--repair", repair.id, "--apply", "--confirm", confirmation]
                    if request["selector"]:
                        args.extend(("--device", request["selector"]))
                    parsed = avpnctl.build_parser().parse_args(["--state", str(STATE), "--json", *args])
                    result = setup_cli.setup(parsed, diagnose=lambda: self.diagnostics(caller))
                    if not result["repair"].get("commands_succeeded"):
                        raise Refused("hardware_repair_failed")
                elif name == "request_device":
                    progress(
                        "waiting_for_hardware", "Use the trusted system/device prompt, then touch the selected key."
                    )
                    self.dispatch(
                        ["request", "--role", "client", "--protect", "nitrokey", "--out", str(STATE / "device.req")]
                    )
                elif name == "import_bundle":
                    progress("waiting_for_hardware", "Approve the trusted hardware prompt for this signed route.")
                    with self.import_files(request) as (bundle, operator):
                        args = ["enroll", str(bundle), "--operator-key", str(operator)]
                        if request["replace"]:
                            args.append("--replace")
                        self.dispatch(args)
                elif name == "unlock":
                    progress("waiting_for_user", "Enter the PIN only in the native prompt, then touch your key.")
                    self.dispatch(["unlock"])
                elif name in ("connect", "retry"):
                    if "scope" in request:
                        self.dispatch(["preferences", "--mode", request["scope"]])
                    if cancel.is_set():
                        raise InterruptedError
                    avpnctl.cmd("systemctl", "restart" if name == "retry" else "start", "advanced-vpn.service")
                elif name == "disconnect":
                    avpnctl.cmd("systemctl", "stop", "advanced-vpn.service")
                    self.dispatch(["disconnect"])
                elif name in ("create_operator_keys", "request_exit", "sign_route"):
                    import controller_create_join

                    fields = {k: v for k, v in request.items() if k not in ("action", "branch")}
                    spec = controller_create_join.apply(
                        request.get("branch"), name, fields, controller_create_join.paths()
                    )
                    progress(
                        "waiting_for_hardware",
                        "Approve the trusted hardware prompt for this setup-wizard operation.",
                    )
                    if spec.get("state"):
                        parsed = avpnctl.build_parser().parse_args(
                            ["--state", spec["state"], "--bin-dir", str(ROOT / "bin"), "--json", *spec["argv"]]
                        )
                        from keyguard import one_pin

                        with one_pin():  # one PIN for this one operation
                            avpnctl.dispatch(parsed)
                    else:
                        self.dispatch(spec["argv"])
                    controller_create_join.journal_append(
                        controller_create_join.paths()["journal"], request.get("branch"), name, fields, caller.uid
                    )
                if cancel.is_set():
                    raise InterruptedError
        except Exception:
            if cancel.is_set():
                raise InterruptedError from None
            raise

    def setup(self, caller, branch, busy=False):
        """Client checks are root-authoritative; provider credentials stay ordinary-user scoped."""
        if branch not in ("create", "join"):
            raise Refused("invalid_setup_branch")
        import controller_create_join

        steps = controller_create_join.steps_for(branch)
        if busy:
            rows = [
                dict(
                    id=s.id,
                    title=s.title,
                    state="pending",
                    say="An approved operation is in progress; checks resume after it finishes.",
                    actions=[],
                )
                for s in steps
            ]
            return dict(
                schema=1, branch=branch, complete=0, total=len(rows), current=rows[0]["id"], finished=False, steps=rows
            )
        findings = self.diagnostics(caller)
        import controller_create_join

        wizard = controller_create_join.paths()
        out = setup_flow.run(
            steps,
            dict(state=STATE, vault=avpnctl.DEVICE_VAULT, exit=wizard["exit"], diagnose=lambda: findings),
            avpnctl.runtime_dir(STATE) / ("desktop-setup-" + str(caller.uid)),
        )
        report = setup_flow.report(out)
        report["branch"] = branch
        report["device_request"] = controller_request.public_request(STATE)
        controller_create_join.decorate_report(branch, report, STATE, findings)
        return report


def main():
    """The native broker owns this pipe and supplies its authenticated sender envelope."""
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError("private broker worker requires root and inherited pipes")
    os.umask(0o077)
    avpnctl.harden_process()
    # Reserve the original stdout for protocol replies before silencing all library
    # prints and raw command output, including prints from the action thread.
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", buffering=1)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.close(null)
    adapter, broker = Adapter(), None
    broker = Broker(adapter)
    try:
        while True:
            raw = sys.stdin.buffer.readline(MAX_REQUEST + 4097)
            if not raw:
                return
            if len(raw) > MAX_REQUEST + 4096 or not raw.endswith(b"\n"):
                raise Refused("oversized_private_request")
            try:
                request = json.loads(raw)
                caller = Caller(**request["caller"])
                method, value = request["method"], request.get("value")
                if method == "GetSnapshot":
                    result = controller_status.snapshot(STATE)
                elif method == "SearchProviders":
                    import search_providers

                    result = search_providers.search(search_providers.shipped_index(), value)
                elif method in ("GetStreamingEligibility", "GetMultihopPresets", "GetAutoconnectPolicy"):
                    # The GUI's observation commands (tools/controller_extension.py):
                    # reads only - no plan, no operation, no user input.
                    import controller_extension

                    result = controller_extension.dispatch_extension(method, value)
                elif method == "GetSetup":
                    with broker.lock:
                        busy = any(
                            o.public["state"] in ("running", "waiting_for_user", "waiting_for_hardware")
                            for o in broker.operations.values()
                        )
                    result = adapter.setup(caller, value, busy)
                elif method == "PreviewAction":
                    result = broker.preview(caller, value)
                elif method == "ApplyAction":
                    result = broker.apply(caller, value)
                elif method == "GetPlan":
                    result = broker.plan(caller, value)
                elif method == "GetOperation":
                    result = broker.operation(caller, value)
                elif method == "CancelOperation":
                    result = broker.cancel(caller, value)
                else:
                    raise Refused("unknown_method")
                response = dict(ok=True, result=result)
            except Exception:  # noqa: BLE001 (fixed refusal only; no raw arguments)
                response = dict(ok=False, error="controller_request_refused")
            protocol.write(json.dumps(response, allow_nan=False) + "\n")
    finally:
        with broker.lock:
            for operation in broker.operations.values():
                operation.cancel.set()


if __name__ == "__main__":
    main()

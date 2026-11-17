"""Controller entry points for read-only setup checks and individually confirmed repairs."""

import hashlib
import hmac
import json
import os
from dataclasses import asdict
from pathlib import Path

import hwkey
import preflight
import setup_flow


class RequestError(ValueError):
    """A rejected setup request with a fixed public explanation and no secret payload."""


class ConfirmationRequired(PermissionError):
    """A repair needs renewed explicit approval of its current plan."""


def add_arguments(parser):
    """Setup inspects by default; applying a built-in repair requires a current plan token."""
    parser.add_argument("--vault", type=Path, help="directory holding this device's FIDO2 credential record")
    parser.add_argument("--checkpoint-dir", type=Path, help="private directory for resumable non-secret setup progress")
    parser.add_argument(
        "--repair", choices=("install_udev_rule", "yubikey_enable_fido2"), help="show an available hardware repair plan"
    )
    parser.add_argument("--device", help="the diagnosed hidraw device or vendor serial selecting one repair target")
    parser.add_argument(
        "--apply", action="store_true", help="apply the selected repair after checking its confirmation token"
    )
    parser.add_argument("--confirm", help="the confirmation token printed by the current repair plan")


def checkpoint_dir(args):
    """Per-route private progress, separate from the enrolled profile and runtime status."""
    if args.checkpoint_dir:
        return args.checkpoint_dir
    if os.geteuid() == 0:
        return args.state / "setup"
    key = hashlib.sha256(str(args.state.resolve()).encode()).hexdigest()[:16]
    return Path.home() / ".local/state/advanced-vpn/setup" / key


def repair_plan(repair_id, findings, device=None):
    """Bind one allowlisted repair to a current finding; no arbitrary command arguments."""
    candidates = [f for f in findings if f.repair == repair_id]
    if device:
        candidates = [f for f in candidates if device in (f.device, f.detail.get("serial"))]
    if len(candidates) != 1:
        raise RequestError("repair needs one unambiguous current finding; select the intended device")
    finding = candidates[0]
    selector = finding.detail.get("serial") if repair_id == "yubikey_enable_fido2" else None
    if repair_id == "yubikey_enable_fido2" and selector is None:
        raise RequestError("the vendor did not identify the device")
    repair = hwkey.plan(repair_id, selector)
    if repair_id == "install_udev_rule":
        path = Path(hwkey.UDEV_RULE_PATH)
        if path.is_symlink() or (path.exists() and path.read_text() != hwkey.UDEV_RULE):
            raise RequestError("the device-rule path already contains a different file; review it manually")
    inputs = dict(code=finding.code, device=finding.device, detail=finding.detail)
    token = hashlib.sha256(json.dumps(dict(plan=asdict(repair), inputs=inputs), sort_keys=True).encode()).hexdigest()
    return repair, token


def setup(args, diagnose=None, apply=None, vendor_info=None):
    """Assess the client or apply exactly the explicitly confirmed repair, then reassess."""
    if args.confirm and not args.apply:
        raise RequestError("--confirm requires --apply")
    if args.apply and not args.repair:
        raise RequestError("--apply requires --repair")
    if args.device and not args.repair:
        raise RequestError("--device is used only with --repair")
    diagnose = diagnose or (lambda: hwkey.diagnose(hwkey.hid_devices(), hwkey.usb_devices()))
    if args.repair:
        before = diagnose()
        repair, token = repair_plan(args.repair, before, args.device)
        result = dict(schema=1, plan=asdict(repair), confirmation=token, applied=False, verified=False)
        if args.apply:
            if not args.confirm or not hmac.compare_digest(args.confirm, token):
                raise ConfirmationRequired("Review the current repair plan and supply its confirmation token.")
            codes = (apply or hwkey.apply)(repair, confirmed=True)
            after = diagnose()
            # A udev change may require a replug before ACLs can be tested. Never treat
            # its exit status as proof the key is usable.
            target = [
                f
                for f in before
                if f.repair == args.repair and (not args.device or args.device in (f.device, f.detail.get("serial")))
            ]
            target_devices = {f.device for f in target if f.device}
            ready = [f for f in after if f.code == "key_ready" and (not target_devices or f.device in target_devices)]
            if args.repair == "yubikey_enable_fido2":
                vendor = (vendor_info or hwkey.yubikey_info)()
                ready = [f for f in ready if f.detail.get("vendor") == hwkey.YUBICO]
                if vendor.get("serial") != repair.selector or vendor.get("fido2") != "Enabled":
                    ready = []
            result.update(
                applied=True,
                commands_succeeded=bool(codes) and all(c == 0 for c in codes),
                verified=bool(ready) and bool(codes) and all(c == 0 for c in codes),
                findings=hwkey.report(after),
            )
        return dict(
            ok=not result["applied"] or result["verified"],
            action="setup",
            message="Repair verified."
            if result["verified"]
            else "Review the repair plan."
            if not result["applied"]
            else "Repair attempted; key readiness is not verified. Reconnect the key and check again.",
            repair=result,
        )
    vault = args.vault
    if vault is None:
        import avpnctl

        protection = avpnctl.read_json_private(args.state / "protection.json", {})
        vault = Path(protection["vault"]) if protection.get("vault") else avpnctl.DEVICE_VAULT
    out = setup_flow.run(
        setup_flow.client_steps(), dict(state=args.state, vault=vault, diagnose=diagnose), checkpoint_dir(args)
    )
    report = setup_flow.report(out)
    return dict(
        ok=True,
        action="setup",
        message=f"Setup: {report['complete']} of {report['total']} checks complete.",
        setup=report,
    )


def preflight_result(args):
    """The standalone preflight schema with controller action/success fields."""
    report = preflight.inspect_host(args)
    return dict(
        ok=report["ready"],
        action="preflight",
        message="Ready to install." if report["ready"] else "Resolve the preflight blockers before installation.",
        preflight=report,
    )


def print_result(args, result):
    """Emit one JSON object or a compact human checklist; never print secrets or PINs."""
    if args.json:
        print(json.dumps(result, sort_keys=True))
        return
    print(result["message"])
    if "setup" in result:
        for row in result["setup"]["steps"]:
            mark = "✓" if row["state"] == "complete" else "·"
            print(f"  {mark} {row['title']}: {row['state']} — {row['say']}")
            for finding in row["findings"]:
                if finding.get("repair"):
                    print("      Repair plan: avpn setup --repair " + finding["repair"])
    elif "preflight" in result:
        for row in result["preflight"]["findings"]:
            print(f"  {row['severity']}: {row['message']}")
            if row.get("fix"):
                print("      Suggested fix: " + row["fix"])
        if result["preflight"]["install"]:
            print("  Suggested package command: " + result["preflight"]["install"])
    elif "repair" in result:
        repair = result["repair"]
        print("  " + repair["plan"]["changes"])
        print("  Undo: " + repair["plan"]["undo"])
        if not repair["applied"]:
            print("  Confirmation token: " + repair["confirmation"])
            print("  Re-run with --apply --confirm TOKEN after reviewing this plan.")
        else:
            for finding in repair.get("findings", []):
                print(f"  {finding['severity']}: {finding['message']}")

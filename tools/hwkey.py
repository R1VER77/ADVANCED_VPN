"""Security-key diagnostics for setup (`avpn setup`): exact checks, typed findings, repairs
only by plan and confirmation.

What it checks, in order, from what the system itself reports:
1. Which HID devices are FIDO keys: udev's `fido_id` (systemd >= 244) sets ID_FIDO_TOKEN=1;
   otherwise the report descriptor declares the FIDO usage page (0xF1D0).
2. Whether this user may open each one. FIDO classification and desktop uaccess are
   independent: a denial with uaccess already present needs session/ACL diagnosis.
3. A plugged-in Yubico device with no usable FIDO2 interface: only a vendor report can
   establish disabled USB FIDO2; absence alone never authorizes changing a device.
4. For each openable key, without a PIN or a touch: CTAP2 support, the hmac-secret
   extension (AVPN derives its keys from it), whether a PIN is set, and the PIN retries left.

Repairs are plans: what changes, the commands, whether root is needed and how to undo it.
Nothing runs without explicit confirmation, and the caller checks again afterwards; success
is the next diagnosis, never the command's exit status. A FIDO reset (which deletes every
credential on the key) is never offered as a repair: it is a separate recovery decision.
"""

import os
import re
import sys
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

FIDO_USAGE_PAGE = b"\x06\xd0\xf1"  # HID report descriptor: Usage Page (FIDO Alliance)
NITROKEY, YUBICO, TREZOR, LEDGER = "20A0", "1050", "1209", "2C97"
# Recognized device families, not a capability or certification allowlist.
KNOWN_KEYS = {
    (NITROKEY, "42B1"): "Nitrokey 3",
    (NITROKEY, "42B2"): "Nitrokey 3",
    (YUBICO, None): "YubiKey",  # any Yubico product id
    (TREZOR, "53C1"): "Trezor",
    (LEDGER, None): "Ledger",  # product ids change with the selected application
}
LOW_PIN_RETRIES = 3

# Ranking (docs/DEVICE_COMPATIBILITY_VALIDATION.md, "Ranking"). Every key is supported; the
# ranking says which to prefer. "open": the firmware doing the FIDO2 work is published;
# "closed": it is not (Ledger's app is public, its OS and secure element are not).
FIRMWARE = {
    "Nitrokey 3": "open",
    "Trezor": "open",
    "Solo 1": "open",
    "Solo 2": "open",
    "YubiKey": "closed",
    "Ledger": "closed",
}
# Ranked by full USB id only (these vendor ids are shared): STMicroelectronics' with Solo 1's
# product id (solo1 usbd_desc.c); pid.codes' with Solo 2's (solo2 runners/lpc55 device_config.rs).
RANKED_ONLY = {("0483", "A2CA"): "Solo 1", ("1209", "BEEE"): "Solo 2"}
# CTAP PIN/UV protocols 1 and 2 are the only ones any key or client implements: the PIN and the
# hmac-secret that unseals the vault cross USB encrypted under a P-256 ECDH key. Flagged on
# every key; a recorded USB link plus a future quantum computer would reveal both.
USB_CHANNEL = "p256_ecdh_ctap_pin_uv_1_2"


def rank(vendor, product, on_device):
    """(tier, rank) of a key: 1 is best. Open firmware is cypherpunk-preferred, and a PIN
    entered on the key itself beats one typed on this computer, where malware can read it."""
    family = key_name(vendor, product) or RANKED_ONLY.get((vendor, product))
    firmware = FIRMWARE.get(family)
    if firmware is None:
        return "unranked", 5
    tier = "cypherpunk_preferred" if firmware == "open" else "closed_source"
    return tier, (1 if firmware == "open" else 3) + (0 if on_device else 1)


UDEV_RULE_PATH = "/etc/udev/rules.d/70-avpn-security-keys.rules"
# Reclassify FIDO HID interfaces if the distribution's classification rule is absent.
# Wallet access is restricted to the FIDO interface: never grant their wallet APDU
# interface, group-wide access or world-writable device permissions.
UDEV_RULE = (
    "# AVPN: local-session access to recognized security-key interfaces\n"
    'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", IMPORT{program}="fido_id"\n'
    'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="42b1|42b2", TAG+="uaccess"\n'
    'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"\n'
    'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="53c1", '
    'ENV{ID_FIDO_TOKEN}=="1", TAG+="uaccess"\n'
    'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="2c97", ENV{ID_FIDO_TOKEN}=="1", TAG+="uaccess"\n'
)


@dataclass
class HidDevice:
    """One hidraw device as the system reports it."""

    node: str  # e.g. hidraw2
    vendor: str  # USB vendor id, upper-case hex
    product: str
    name: str
    fido: bool  # a FIDO interface (udev's tag or the report descriptor)
    fido_tagged: bool | None  # udev's ID_FIDO_TOKEN (None: udev gave no answer)
    access: bool  # this user can read and write /dev/<node>
    uaccess_tagged: bool = False  # classification and desktop-session access are separate tags


@dataclass
class Finding:
    """One diagnosis: a code, how serious, what to tell the person, and a repair id if one exists."""

    code: str
    severity: str  # ok, info, warning, blocker (the install plan's names)
    message: str  # plain words for the user
    device: str | None = None
    detail: dict = field(default_factory=dict)
    repair: str | None = None  # a repair id (see plan), or None


@dataclass
class Repair:
    """A repair's plan: what changes, the commands, root or not, and how to undo it."""

    id: str
    summary: str
    changes: str
    commands: list
    needs_root: bool
    undo: str
    destructive: bool = False
    selector: str | None = None


def key_name(vendor, product):
    """A supported key's name, or None."""
    return KNOWN_KEYS.get((vendor, product)) or KNOWN_KEYS.get((vendor, None))


def tool_environment():
    """Vendor/system tools inherit no Python-path, loader or askpass overrides."""
    return dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8")


def udev_properties(node, run=subprocess.run):
    """udev's properties for /dev/<node> (an empty dict when udevadm is unavailable)."""
    try:
        from sysexec import trusted_exe

        executable = trusted_exe("udevadm") if run is subprocess.run else "udevadm"
        r = run(
            [executable, "info", "--query=property", "--name=/dev/" + node],
            capture_output=True,
            text=True,
            timeout=5,
            env=tool_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if r.returncode != 0:
        return {}
    return dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)


def hid_devices(sysfs=Path("/sys"), dev=Path("/dev"), udev=udev_properties, access=None):
    """Every hidraw device, with whether it is a FIDO key and whether we may open it."""
    access = access or (lambda p: os.access(p, os.R_OK | os.W_OK))
    out = []
    for d in sorted((sysfs / "class/hidraw").glob("hidraw*")):
        node = d.name
        uevent = {}
        try:
            for line in (d / "device/uevent").read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    uevent[k] = v
        except OSError:
            continue
        parts = uevent.get("HID_ID", "0:0:0").split(":")
        vendor, product = (parts[1][-4:].upper(), parts[2][-4:].upper()) if len(parts) == 3 else ("", "")
        props = udev(node)
        tagged = props.get("ID_FIDO_TOKEN") == "1" if props else None
        try:
            in_descriptor = FIDO_USAGE_PAGE in (d / "device/report_descriptor").read_bytes()
        except OSError:
            in_descriptor = False
        # TAGS can retain tags from previous events. CURRENT_TAGS, when supplied,
        # describes the latest rule evaluation, including an explicitly empty set.
        session_access = "uaccess" in props.get("CURRENT_TAGS", props.get("TAGS", "")).split(":")
        out.append(
            HidDevice(node, vendor, product, uevent.get("HID_NAME", ""), bool(tagged) or in_descriptor, tagged,
                      access(str(dev / node)), session_access)
        )  # fmt: skip
    return out


def usb_devices(sysfs=Path("/sys")):
    """(vendor, product, name) of every USB device, to find a key with its FIDO interface off."""
    out = []
    for d in sorted((sysfs / "bus/usb/devices").glob("*")):
        try:
            vendor = (d / "idVendor").read_text().strip().upper()
            product = (d / "idProduct").read_text().strip().upper()
        except OSError:
            continue
        try:
            name = (d / "product").read_text().strip()
        except OSError:
            name = ""
        out.append((vendor, product, name))
    return out


def probe_device(node, dev=Path("/dev")):
    """What the key says about itself, without a PIN or a touch: CTAP2 getInfo and, when a PIN
    is set, the retries left. Returns a dict (raises OSError if the device cannot be opened)."""
    from fido2.ctap2 import ClientPin, Ctap2
    from fido2.hid import CAPABILITY, open_device

    device = open_device(str(dev / node))
    try:
        if not device.capabilities & CAPABILITY.CBOR:  # no CTAP2: U2F only
            return dict(ctap2=False)
        ctap = Ctap2(device)
        info = ctap.info
        pin_set = bool(info.options.get("clientPin"))
        retries = ClientPin(ctap).get_pin_retries()[0] if pin_set else None
        return dict(
            ctap2=True,
            versions=list(info.versions),
            hmac_secret="hmac-secret" in (info.extensions or []),
            pin_set=pin_set,
            pin_retries=retries,
            uv=info.options.get("uv") is True,
            algorithms=[a.get("alg") for a in (info.algorithms or [])],
            firmware=info.firmware_version,
            aaguid=str(info.aaguid),
        )
    finally:
        device.close()


def ctap_probe(node, dev=Path("/dev"), run=subprocess.run):
    """Isolate device I/O in a bounded worker: a broken key cannot hang the setup controller."""
    import json

    if not re.fullmatch(r"hidraw[0-9]+", node) or dev != Path("/dev"):
        raise ValueError("a local hidraw device name is required")
    try:
        process = run(
            [sys.executable, "-E", "-s", str(Path(__file__).resolve()), "--probe", node],
            capture_output=True,
            text=True,
            timeout=10,
            env=tool_environment(),
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError("security-key probe timed out") from e
    if process.returncode != 0:
        raise OSError("security-key probe failed")
    try:
        value = json.loads(process.stdout)
    except (ValueError, UnicodeError) as e:
        raise OSError("invalid security-key probe response") from e
    if not isinstance(value, dict):
        raise OSError("invalid security-key probe response")
    return value


def yubikey_info(run=subprocess.run):
    """Read one key's vendor report; ambiguous/unavailable output never authorizes a repair."""
    from sysexec import trusted_exe

    try:
        r = run([trusted_exe("ykman"), "info"], capture_output=True, text=True, timeout=10, env=tool_environment())
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if r.returncode != 0:
        return {}
    application = re.search(r"^FIDO2\s+(Enabled|Disabled|Not available)(?:\s|$)", r.stdout, re.M)
    serial = re.search(r"^Serial number:\s*([0-9]{1,12})\s*$", r.stdout, re.M)
    version = re.search(r"^Firmware version:\s*(\d+\.\d+\.\d+)", r.stdout, re.M)
    if not (application and serial and version):
        return {}
    return dict(
        fido2=application[1], serial=serial[1], firmware=version[1], locked="protected by a lock code" in r.stdout
    )


def diagnose(devices, usb, probe=ctap_probe, management=yubikey_info):
    """Findings for the security keys on this machine, most important first."""
    findings = []
    fido = [d for d in devices if d.fido]
    for d in fido:
        name = key_name(d.vendor, d.product) or "".join(c for c in d.name if c.isprintable())[:100] or "security key"
        if not d.access:
            if d.uaccess_tagged:
                findings.append(Finding(
                    "desktop_access_denied", "blocker",
                    f"The {name} is present and tagged for desktop access, but cannot be opened. "
                    "Check the active local session and device ACL; installing another rule is not a verified fix.",
                    d.node, dict(vendor=d.vendor, product=d.product),
                    None,
                ))  # fmt: skip
            else:
                findings.append(Finding(
                    "permission_denied", "blocker",
                    f"The {name} is there, but this system does not let you open it. Installing AVPN's "
                    "device rule gives the signed-in user access to supported keys.",
                    d.node, dict(vendor=d.vendor, product=d.product),
                    "install_udev_rule" if key_name(d.vendor, d.product) else None,
                ))  # fmt: skip
            continue
        try:
            p = probe(d.node)
        except Exception as e:
            findings.append(
                Finding(
                    "probe_failed", "blocker", f"The {name} could not be checked.", d.node, dict(error=type(e).__name__)
                )
            )
            continue
        base = dict(vendor=d.vendor, product=d.product, firmware=p.get("firmware"))
        if not p.get("ctap2"):
            findings.append(Finding(
                "no_ctap2", "blocker",
                ("The Ledger currently offers only U2F. Unlock it and open the Security Key app, then check again. "
                 "Do not reset the wallet or enter its recovery phrase."
                 if d.vendor == LEDGER else
                 f"The {name} only speaks the old U2F protocol. AVPN needs a FIDO2 key."), d.node, base,
            ))  # fmt: skip
            continue
        if not p.get("hmac_secret"):
            findings.append(Finding(
                "no_hmac_secret", "blocker",
                f"The {name} does not offer hmac-secret, which AVPN uses to protect your keys. "
                "This key cannot be used.", d.node, base,
            ))  # fmt: skip
            continue
        uv = p.get("uv") is True
        if not p.get("pin_set") and not uv:
            findings.append(Finding(
                "pin_not_set", "blocker",
                f"The {name} has no PIN yet. Set one with the key's own tool; AVPN never asks for your PIN "
                "in its window.", d.node, base,
            ))  # fmt: skip
            continue
        retries = p.get("pin_retries")
        if retries == 0 and not uv:
            findings.append(Finding(
                "pin_blocked", "blocker",
                f"The {name}'s PIN is blocked. Only a reset helps, and a reset deletes every credential on "
                "the key, so it is your decision, not a repair AVPN makes.", d.node, base,
            ))  # fmt: skip
            continue
        if retries is not None and retries <= LOW_PIN_RETRIES:
            findings.append(Finding(
                "pin_retries_low", "warning",
                f"Only {retries} PIN attempts are left on the {name}. Enter it carefully.", d.node,
                dict(base, pin_retries=retries),
            ))  # fmt: skip
        tier, place = rank(d.vendor, d.product, uv)
        findings.append(Finding(
            "key_ready", "ok", f"The {name} reports FIDO2, hmac-secret and "
            + ("on-device verification." if uv else "a configured PIN.")
            + {"cypherpunk_preferred": " Cypherpunk-preferred: its firmware is open source.",
               "closed_source": " Supported, but its firmware is closed source.",
               "unranked": ""}[tier]
            + (" Its PIN is entered on the key, so this computer never sees it." if uv else
               " Its PIN is typed on this computer, where malware could read it.")
            + " Like every FIDO2 key, it protects the PIN and key secret on the USB link with P-256,"
            " which is not post-quantum.", d.node,
            dict(base, pin_retries=retries, verification="on_device" if uv else "pin",
                 algorithms=p.get("algorithms", []), validation="capability_only",
                 tier=tier, rank=place, usb_channel=USB_CHANNEL),
        ))  # fmt: skip
    # Missing HID / CBOR is not evidence that an application is disabled. Ask the vendor
    # tool, and authorize an enable only for a single identified device with that state.
    yubis = [(v, p, n) for v, p, n in usb if v == YUBICO]
    if yubis and not any(f.code == "key_ready" and f.detail.get("vendor") == YUBICO for f in findings):
        info = management() if len(yubis) == 1 else {}
        if info.get("fido2") == "Disabled" and info.get("serial") and not info.get("locked"):
            findings = [f for f in findings if not (f.code == "no_ctap2" and f.detail.get("vendor") == YUBICO)]
            findings.append(Finding(
                "fido2_disabled", "blocker",
                "Yubico's tool confirms FIDO2 is disabled on USB. You can enable just that function; "
                "OTP slots and other applications are not changed.",
                None, dict(vendor=YUBICO, serial=info["serial"], firmware=info.get("firmware")),
                "yubikey_enable_fido2",
            ))  # fmt: skip
        elif info.get("locked"):
            findings.append(
                Finding(
                    "configuration_locked",
                    "blocker",
                    "The key's configuration is locked. "
                    "Use the vendor's trusted tool and your configuration lock code.",
                )
            )
        elif info.get("fido2") == "Not available":
            findings.append(
                Finding("fido2_unavailable", "blocker", "The vendor reports FIDO2 is unavailable on this key.")
            )
        elif not any(f.device for f in findings):
            findings.append(
                Finding(
                    "fido2_unknown",
                    "blocker",
                    "A Yubico device is present, but its FIDO2 state "
                    "could not be confirmed. Use ykman info with only the intended key connected.",
                )
            )
    fido_ids = {(d.vendor, d.product) for d in fido}
    for vendor, product, _ in usb:
        if vendor != YUBICO and key_name(vendor, product) and (vendor, product) not in fido_ids:
            findings.append(
                Finding(
                    "key_interface_unknown",
                    "blocker",
                    (
                        "A Ledger is connected, but its FIDO interface is unavailable. Unlock it and open "
                        "the Security Key app, then check again. Never enter its recovery phrase."
                        if vendor == LEDGER
                        else "A known security key is plugged in, but its FIDO interface could not be identified. "
                        "Check permissions and the device's own screen or vendor tool."
                    ),
                )
            )
    ready = [f for f in findings if f.code == "key_ready"]
    if len(ready) > 1:
        findings.append(Finding(
            "several_keys", "info", "More than one key is ready: choose the one to use, and keep the other "
            "safe or unplugged during setup.", None, dict(keys=[f.device for f in ready]),
        ))  # fmt: skip
    if not findings:
        findings.append(Finding(
            "no_key", "blocker", "No security key found. Plug in your Nitrokey (or YubiKey) and check again.",
        ))  # fmt: skip
    order = dict(blocker=0, warning=1, info=2, ok=3)
    return sorted(findings, key=lambda f: order[f.severity])


def plan(repair_id, selector=None):
    """The repair's plan: what changes, how, and how to undo it. Only these exist."""
    if repair_id == "install_udev_rule":
        return Repair(
            "install_udev_rule",
            "Give the signed-in user access to supported security keys",
            f"Writes {UDEV_RULE_PATH} for Nitrokey 3, YubiKey, Trezor and Ledger and reloads udev. "
            "Wallet access is limited to FIDO-classified HID interfaces. The system's fido_id helper is required "
            "for wallet classification; no wallet data or credentials are changed.",
            [
                ["install", "-m", "0644", "/dev/stdin", UDEV_RULE_PATH],
                ["udevadm", "control", "--reload"],
                ["udevadm", "trigger", "--subsystem-match=hidraw"],
            ],  # fmt: skip
            True,
            f"Remove {UDEV_RULE_PATH} only if this repair created it, then reload udev; retain a pre-existing identical rule.",
        )
    if repair_id == "yubikey_enable_fido2":
        if selector is not None and not re.fullmatch(r"[0-9]{1,12}", selector):
            raise ValueError("invalid device selector")
        return Repair(
            "yubikey_enable_fido2",
            "Switch on the YubiKey's FIDO2 function for USB",
            "Enables only FIDO2 over USB with Yubico's tool; OTP slots, PIV, OpenPGP and NFC settings are "
            "not touched. Your confirmed plan replaces the vendor's second confirmation. "
            "Locked configurations are refused; use the vendor's trusted tool separately.",
            [
                ["ykman"]
                + (["--device", selector] if selector else [])
                + ["config", "usb", "--enable", "FIDO2", "--force"]
            ],
            False,
            "`ykman config usb --disable FIDO2`.",
            selector=selector,
        )
    raise ValueError("no such repair: " + repair_id)


def apply(repair, confirmed, run=subprocess.run, stdin=None):
    """Run a repair's commands only when `confirmed`; root steps through sudo. Returns the
    commands' exit codes. The caller must diagnose again: that, not these codes, is success."""
    if confirmed is not True:
        raise PermissionError("a repair runs only after the user confirms it")
    if repair != plan(repair.id, repair.selector):
        raise ValueError("repair differs from the built-in plan")
    if repair.id == "yubikey_enable_fido2" and repair.selector is None:
        raise ValueError("repair needs the exact device selector")
    codes = []
    for cmd in repair.commands:
        if run is subprocess.run:
            from sysexec import trusted_exe

            cmd = [trusted_exe(cmd[0])] + cmd[1:]
        argv = (["/usr/bin/sudo"] + cmd) if repair.needs_root and os.geteuid() != 0 else cmd
        data = UDEV_RULE if "/dev/stdin" in cmd else stdin
        # Keep the controller's stdout as one JSON object. Vendor progress and any
        # sudo prompt belong on stderr/the user's terminal, never in the result.
        r = run(argv, input=data, text=True, env=tool_environment(), stdout=sys.stderr)
        codes.append(r.returncode)
        if r.returncode != 0:
            break
    return codes


def report(findings):
    """JSON-ready findings."""
    return [asdict(f) for f in findings]


def main():
    """`python3 tools/hwkey.py`: diagnose this machine's keys (no PIN, no touch, no changes)."""
    import json

    if len(sys.argv) == 3 and sys.argv[1] == "--probe":
        if not re.fullmatch(r"hidraw[0-9]+", sys.argv[2]):
            raise SystemExit(2)
        try:
            print(json.dumps(probe_device(sys.argv[2])))
        except Exception:
            # Probe metadata is not a reason to expose a library traceback to the GUI.
            raise SystemExit(1) from None
        return
    if len(sys.argv) != 1:
        raise SystemExit(2)
    print(json.dumps(report(diagnose(hid_devices(), usb_devices())), indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Opt-in physical-key setup checks, with disposable local vaults and no networking.

Default mode reads capabilities only. --roundtrip additionally creates a non-resident
test credential, verifies two assertions and an envelope round trip, then removes its
local vault. It never resets a key or touches an existing vault or wallet seed.
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

import hwkey
import setup_flow

FAMILIES = {"nitrokey": hwkey.NITROKEY, "yubikey": hwkey.YUBICO, "trezor": hwkey.TREZOR, "ledger": hwkey.LEDGER}


def assess(findings, family=None):
    """Only one unambiguously usable, expected family may proceed to an interaction."""
    result = setup_flow.check_key({"diagnose": lambda: findings})
    ready = [f for f in findings if f.code == "key_ready"]
    matched = family is None or (len(ready) == 1 and ready[0].detail.get("vendor") == FAMILIES[family])
    return dict(
        state=result.state if matched else "blocked",
        ready=result.state == "complete" and matched,
        expected_family=family,
        findings=[dict(code=f.code, severity=f.severity, message=f.message, repair=f.repair) for f in findings],
        family_matches=matched,
        device_capabilities=(
            {
                name: ready[0].detail.get(name)
                for name in ("vendor", "product", "firmware", "verification", "algorithms")
            }
            if len(ready) == 1
            else None
        ),
    )


def roundtrip(parent, key_api=None):
    """Use fresh test data; report booleans only, never credential handles or secrets."""
    from cryptography.exceptions import InvalidTag

    if key_api is None:
        import keyguard as key_api

    with tempfile.TemporaryDirectory(prefix="test-vault-", dir=parent) as directory:
        vault = Path(directory) / "vault"
        print("1/3: create a separate test credential; approve on the intended key.", flush=True)
        key_api.enroll(vault)
        valid = setup_flow.check_vault({"vault": vault})
        if valid.state != "complete":
            raise RuntimeError("test credential validation failed")
        print("2/3: authenticate once to seal random test data.", flush=True)
        secret, meta = key_api.hardware_secret(vault)
        payload, binding = secrets.token_bytes(32), secrets.token_bytes(32)
        envelope = key_api.seal_bytes(secret, meta, "client", binding, payload)
        # A new physical assertion must recover the same secret and authenticate a
        # message, rather than merely decrypting twice with one in-memory secret.
        message = secrets.token_bytes(32)
        print("3/3: authenticate again to verify a fresh assertion and unseal the test data.", flush=True)
        recovered, current, assertion = key_api.hardware_assertion(vault, message=message)
        key_api.verify_assertion(key_api.credential_public(vault), message, assertion)
        opened = key_api.open_bytes(recovered, current, "client", binding, envelope)
        if not secrets.compare_digest(opened, payload):
            raise RuntimeError("hardware envelope round trip failed")
        tampered = dict(envelope)
        raw = bytearray(key_api.unb64(tampered["ciphertext"]))
        raw[-1] ^= 1
        tampered["ciphertext"] = key_api.b64(bytes(raw))
        try:
            key_api.open_bytes(recovered, current, "client", binding, tampered)
        except (ValueError, InvalidTag):
            pass
        else:
            raise RuntimeError("corrupted envelope was accepted")
        return dict(
            credential_record=True,
            authenticated_assertion=True,
            fresh_assertion_unseal=True,
            corrupted_envelope_refused=True,
            local_test_vault_removed=True,
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=tuple(FAMILIES), help="require this physically connected device family")
    parser.add_argument("--out", required=True, type=Path, help="new private directory for non-secret results")
    parser.add_argument("--roundtrip", action="store_true", help="create and exercise a separate test credential")
    parser.add_argument("--confirm-create-test-credential", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        parser.error("run as the intended ordinary desktop user, never root")
    if args.roundtrip != args.confirm_create_test_credential:
        parser.error("--roundtrip and --confirm-create-test-credential must be supplied together")
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    sources = ("hardware_setup_test.py", "hwkey.py", "setup_flow.py", "setup_cli.py", "keyguard.py")
    hashes = {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in sources}
    result = dict(
        schema=1, scope="physical_setup", roundtrip_requested=args.roundtrip, passed=False, source_sha256=hashes
    )
    try:
        findings = hwkey.diagnose(hwkey.hid_devices(), hwkey.usb_devices())
        result["diagnostic"] = assess(findings, args.family)
        if not result["diagnostic"]["ready"]:
            if not result["diagnostic"]["family_matches"]:
                print(f"The connected key is not the requested {args.family}. No test credential was created.")
            else:
                print(
                    "Hardware is not unambiguously ready. See result.json; unplug other keys or resolve its findings."
                )
            return 1
        if args.roundtrip:
            print(
                "Create a separate test credential, then verify two assertions. Use trusted PIN/device prompts only.",
                flush=True,
            )
            result["roundtrip"] = roundtrip(args.out)
        result["passed"] = True
        print(
            "Physical hardware check passed"
            + (" with a fresh-assertion vault round trip." if args.roundtrip else " (capability detection only).")
        )
        return 0
    except Exception as error:
        # Error strings may contain library/credential data. Keep only the class.
        result["error_type"] = type(error).__name__
        print(
            "Hardware check failed. No reset or PIN retry is attempted; review the device and run a new test.",
            file=sys.stderr,
        )
        return 1
    finally:
        fd = os.open(args.out / "result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(result, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())

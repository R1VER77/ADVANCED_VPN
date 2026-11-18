#!/usr/bin/env python3
"""Ordinary-user read-only device diagnostics for the authenticated desktop session."""

from dataclasses import asdict
import json
import os

import hwkey


def main():
    """No repair, enrollment, authentication, PIN or credential operation."""
    if os.geteuid() == 0:
        raise RuntimeError("hardware access diagnostics must run as the desktop user")
    findings = hwkey.diagnose(hwkey.hid_devices(), hwkey.usb_devices())
    print(json.dumps(dict(schema=1, findings=[asdict(f) for f in findings]), allow_nan=False))


if __name__ == "__main__":
    main()

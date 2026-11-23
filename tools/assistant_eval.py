#!/usr/bin/env python3
"""Evaluate the local assistant on every failure class, with the real model.

    assistant_eval.py --model GGUF --server LLAMA_SERVER [--runs N] --out FILE.json

For each class's real failure text, the engine's finding is explained N times. Recorded
per answer: whether it passed the checks, why not, whether its suggestion matched the
engine's first fix, and how long it took. The engine decides the fixes either way; this
measures how far the model's words can be relied on.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

import assistant  # noqa: E402
import troubleshoot  # noqa: E402

CASES = {
    "apt_lock_held": ["E: Could not get lock /var/lib/apt/lists/lock. It is held by process 489333 (apt-get)"],
    "aws_signed_out": ["An error occurred (ExpiredToken) when calling the GetCallerIdentity operation"],
    "server_dns_blocked": ["Temporary failure resolving 'deb.debian.org'"],
    "server_locked": ["cpvpn-flyexit did not accept its data key"],
    "capped": ["cpvpn-relay: capped until 2026-12-01"],
    "pin_wrong": ["fido2.ctap.CtapError: CTAP error: 0x31 - PIN_INVALID"],
    "pin_blocked": ["CTAP error: 0x32 - PIN_BLOCKED"],
    "key_not_touched": ["fido_dev_get_assert: FIDO_ERR_USER_ACTION_TIMEOUT"],
    "ssh_unreachable": ["ssh: connect to host 203.0.113.9 port 22: Connection timed out"],
    "fly_token_missing": ["fly api: 401 Unauthorized"],
}


def main(argv=None):
    """Run the evaluation and write its record."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--server", required=True, type=Path)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args(argv)
    rows = []
    for code, lines in CASES.items():
        finding = troubleshoot.diagnose("Build the route", lines, server="cpvpn-relay")
        if finding["code"] != code:
            raise SystemExit("case %s diagnosed as %s" % (code, finding["code"]))
        for run in range(a.runs):
            start = time.monotonic()
            try:
                text = assistant.ask_local_model(assistant.prompt(finding), assistant.answer_schema(finding),
                                                 a.model, a.server)  # fmt: skip
                checked = assistant.check(finding, text)
                why = None if checked else "answer_refused"
            except assistant.AssistantUnavailable as e:
                text, checked, why = None, None, str(e)
            rows.append(dict(code=code, run=run, seconds=round(time.monotonic() - start, 1), used=bool(checked),
                             why=why, explanation=checked and checked["explanation"],
                             suggestion=checked and (checked["suggestion"] or {}).get("action"),
                             engine_first=finding["fixes"][0]["action"]))  # fmt: skip
            print(code, run, rows[-1]["used"], rows[-1]["suggestion"], rows[-1]["seconds"], file=sys.stderr)
    used = [r for r in rows if r["used"]]
    record = dict(
        schema=1,
        date=datetime.date.today().isoformat(),
        model=dict(file=a.model.name, sha256=hashlib.sha256(a.model.read_bytes()).hexdigest()),
        isolation="unshare -rn (loopback only), llama-server --offline over a Unix socket",
        runs=len(rows),
        used=len(used),
        suggestion_matches_engine_first=sum(r["suggestion"] == r["engine_first"] for r in used),
        suggestion_dropped_or_absent=sum(r["suggestion"] is None for r in used),
        median_seconds=sorted(r["seconds"] for r in rows)[len(rows) // 2],
        rows=rows,
    )
    a.out.write_text(json.dumps(record, indent=1) + "\n")
    print(json.dumps({k: v for k, v in record.items() if k != "rows"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

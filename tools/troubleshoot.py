#!/usr/bin/env python3
"""Why did a route build fail, and what can fix it: a deterministic diagnosis.

    troubleshoot.py diagnose --step TEXT [--server NAME] < build.log    one JSON finding

The finding is decided here, by fixed rules over the build's own output: never by a
language model. The local assistant (tools/assistant.py) may only explain a finding in
plain words; the fixes offered, and their order, are this module's. Each fix is a typed
action the app maps to a command it already has (D007's rules):

    retry_build        build the route again
    sign_in_aws        renew the AWS sign-in this server's profile uses
    host_update NAME   cypherpunk cloud host update NAME (one PIN and touch)
    unlock_server NAME cypherpunk cloud unlock NAME (after a server reboot)
    check_health       cypherpunk cloud health: stopped, locked, capped or gone servers
    open_docs          the troubleshooting page

Evidence lines are scrubbed before they leave this module: addresses, account numbers,
tokens and keys are replaced, so neither the model nor the screen gets them.
"""

import argparse
from dataclasses import dataclass
import json
import re
import sys

SCHEMA = 1
ACTIONS = ("retry_build", "sign_in_aws", "host_update", "unlock_server", "check_health", "open_docs")
NEEDS_SERVER = ("sign_in_aws", "host_update", "unlock_server")
MAX_EVIDENCE = 6
MAX_LINE = 200


@dataclass(frozen=True)
class Rule:
    """One failure class: what matches it, what it means, and the fixes, best first."""

    code: str
    title: str
    meaning: str
    patterns: tuple
    fixes: tuple


RULES = (
    Rule(
        "aws_signed_out",
        "The AWS sign-in for this server has run out",
        "The cloud account's sign-in session expired, so the build could not reach the server.",
        (
            r"\bsigned_out\b",
            r"ExpiredToken",
            r"[Tt]oken has expired",
            r"session has expired",
            r"Unable to locate credentials",
        ),
        ("sign_in_aws", "retry_build"),
    ),
    Rule(
        "apt_lock_held",
        "Another update on the server held the package manager",
        "The server was busy installing updates, and the build could not get the package manager's lock in time.",
        (r"Could not get lock", r"Waiting for cache lock", r"lock-frontend", r"dpkg was interrupted"),
        ("retry_build", "host_update"),
    ),
    Rule(
        "server_dns_blocked",
        "The server could not look up names",
        "The server could not resolve the package archive's name, so it could not download "
        "updates. An older server version blocks lookups for everything but itself.",
        (r"Temporary failure resolving", r"Could not resolve", r"Name or service not known"),
        ("retry_build", "host_update"),
    ),
    Rule(
        "server_locked",
        "The server's keys are locked after a reboot",
        "The server restarted and is waiting for your security key to unlock its keys.",
        (r"did not accept its data key", r"locked: it cannot open its keys"),
        ("unlock_server", "check_health"),
    ),
    Rule(
        "capped",
        "The server reached its monthly free allowance",
        "The server stopped carrying traffic because it used this month's free allowance; it starts again on the 1st.",
        (r"\bcapped\b", r"no monthly cap for"),
        ("check_health", "open_docs"),
    ),
    Rule(
        "pin_wrong",
        "The security key's PIN was not accepted",
        "The PIN typed for the security key was wrong, so nothing was signed.",
        (r"PIN_INVALID", r"PIN_AUTH_INVALID", r"wrong PIN"),
        ("retry_build",),
    ),
    Rule(
        "pin_blocked",
        "The security key is blocked after too many wrong PINs",
        "The key refuses PINs until it is unplugged and plugged in again; too many more wrong PINs lock it for good.",
        (r"PIN_BLOCKED", r"PIN_AUTH_BLOCKED", r"\bpin_blocked\b"),
        ("open_docs",),
    ),
    Rule(
        "key_not_touched",
        "The security key was not touched in time",
        "The key waited for a touch and gave up, so nothing was signed.",
        (r"USER_ACTION_TIMEOUT", r"PIN prompt not answered", r"PIN dialog cancelled", r"not touched"),
        ("retry_build",),
    ),
    Rule(
        "ssh_unreachable",
        "The server did not answer",
        "The build could not open a connection to the server: it may be stopped by its "
        "provider, still starting, or unreachable.",
        (
            r"Connection timed out",
            r"No route to host",
            r"Connection refused",
            r"kex_exchange_identification",
            r"Connection closed by",
            r"timed out waiting for",
            r"IncorrectInstanceState",
            r"is stopped",
        ),
        ("check_health", "retry_build"),
    ),
    Rule(
        "fly_token_missing",
        "The Fly.io deploy token is missing or refused",
        "The Fly.io exit could not be managed because its deploy token is missing, expired or refused.",
        (r"FLY_API_TOKEN", r"[Ff]ly.{0,20}token", r"401 Unauthorized"),
        ("open_docs",),
    ),
)
UNKNOWN = Rule(
    "unknown",
    "The build stopped for a reason not recognised here",
    "The build stopped, and its output does not match a known cause.",
    (),
    ("retry_build", "open_docs"),
)

# Scrubbing, most specific first: nothing secret or identifying reaches a model or a screen.
SCRUB = (
    (re.compile(r"FlyV1 [^\s\"']+|fm[12]_[A-Za-z0-9_\-]+"), "<token>"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<aws-key>"),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}"), "<secret>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<hex>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b"), "<address>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"), "<address>"),
    (re.compile(r"\b\d{12}\b"), "<account>"),
    (re.compile(r"\bi-[0-9a-f]{8,17}\b"), "<instance>"),
    (re.compile(r"(?i)(password|secret|token|pin)(\s*[=:]\s*)\S+"), r"\1\2<redacted>"),
)


def scrub(line):
    """One evidence line, safe to show and to give a model."""
    text = "".join(c for c in line if c.isprintable() or c == " ")
    for pattern, replacement in SCRUB:
        text = pattern.sub(replacement, text)
    return text.strip()[:MAX_LINE]


def diagnose(step, lines, server=None, event=None):
    """The finding for a failed build: the first rule whose pattern matches, else unknown.

    `event` is the helper's error event (a dict), whose `error` code is the most direct
    evidence when it carries one (signed_out). Lines are the build's kept stderr.
    """
    lines = [str(x) for x in lines if str(x).strip()]
    haystack = list(lines)
    if event:
        haystack = [str(event.get("error", "")), str(event.get("message", ""))] + haystack
    for rule in RULES:
        hits = [x for x in haystack if any(re.search(p, x) for p in rule.patterns)]
        if hits:
            break
    else:
        rule, hits = UNKNOWN, lines[-3:]
    evidence = []
    for x in hits:
        s = scrub(x)
        if s and s not in evidence:
            evidence.append(s)
    fixes = []
    for action in rule.fixes:
        if action in NEEDS_SERVER and not server:
            continue
        fixes.append(dict(action=action, server=server) if action in NEEDS_SERVER else dict(action=action))
    return dict(schema=SCHEMA, code=rule.code, title=rule.title, meaning=rule.meaning, step=scrub(step or ""),
                server=server, evidence=evidence[-MAX_EVIDENCE:], fixes=fixes)  # fmt: skip


def valid_fix(finding, fix):
    """A fix is admissible only if the finding offers it (same action, same server)."""
    return isinstance(fix, dict) and fix in finding["fixes"]


def main(argv=None):
    """Diagnose a failed build from its log on stdin; one JSON reply."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("diagnose")
    d.add_argument("--step", default="")
    d.add_argument("--server")
    a = parser.parse_args(argv)
    print(json.dumps(diagnose(a.step, sys.stdin.read().splitlines()[-400:], a.server)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

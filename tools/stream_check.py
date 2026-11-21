#!/usr/bin/env python3
"""`avpn stream-check`: measure a streaming service's eligibility of an exit.

The honest answer to "does this VPN unblock Netflix?" is a dated,
reproducible measurement per exit, per service — never a blanket claim
(STREAMING_GEO_PARITY_20261120.md section 4.1). This tool is that
measurement:

  avpn run -- stream-check netflix            # inside the namespace, so
                                              # the requests egress through
                                              # the exit under test
  avpn run -- stream-check bbc-iplayer --json
  stream-check netflix --base-url http://127.0.0.1:8123   # tests use a
                                              # local mock of the marker
                                              # responses, never a fake pass

Each run fetches the service's region-eligibility pages from the
exit's vantage point, classifies the response by the documented markers
("You seem to be using an unblocker or proxy", the iPlayer outside-UK
gate, the Disney+/Max/YouTube TV geo notices), and records:

  - the result: eligible | blocked | unknown (unknown is a result, not
    a pass; marker sets are versioned and dated below);
  - the transport profile of the tested path (cloak / tcp443 / i2p-front
    / tor-front / direct) — the 2026 detection stacks fingerprint the
    tunnel transport (JA3/JA4, WireGuard handshake entropy) as well as
    the IP class, so an eligibility claim without the transport it was
    measured on is incomplete;
  - the egress address as the service saw it;
  - the timestamp.

Results are written to docs/evidence/streaming/<service>-<exit>.json and
(optionally) merged into the exit descriptor's `streaming` list for the
owner's signing step; the probe never mutates a signed descriptor in
place. The eligibility table (tools/streaming_table.py) is generated
from these records.

Marker sources are the services' own user-facing notices (Netflix's
help page 114701; the iPlayer geo gate; Disney+/Max/YouTube TV "not
available in your location" pages), refreshed when a service changes
copy. A service whose page matches no marker classifies as unknown and
the seen text is kept for marker review.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCHEMA = 1
DEFAULT_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# Where run records live (docs/evidence/streaming/), and where the
# descriptor's streaming field is merged by the owner's signing step.
EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "streaming"


class ProbeError(Exception):
    """A fetch failed before classification (no network, DNS, timeout)."""


# ---------------------------------------------------------------- adapters
#
# Each adapter: which pages to fetch and which response markers classify
# the exit. Markers are lowercase-matched against the raw response body;
# `region_regex` extracts the region string the service reports when it
# serves content. blocked markers take precedence over eligible markers
# (a page can carry both; the geo notice wins).

ADAPTERS = {
    "netflix": {
        "name": "Netflix",
        "pages": [
            "https://www.netflix.com/",
            "https://www.netflix.com/title/70143836",
        ],
        # Netflix's own notice (help.netflix.com/en/node/114701).
        "blocked_markers": [
            "you seem to be using an unblocker or proxy",
            "streaming error",
            "cannot play this title right now",
            "we can't process your request",
        ],
        # A title page that renders (not the proxy notice) means the
        # catalog served this exit.
        "eligible_markers": [
            "netflix",
        ],
        "region_regex": r'"currentCountry"\s*:\s*"([A-Z]{2})"',
    },
    "bbc-iplayer": {
        "name": "BBC iPlayer",
        "pages": [
            "https://www.bbc.co.uk/iplayer",
            "https://www.bbc.co.uk/iplayer/group/most-popular",
        ],
        # The iPlayer geo gate for connections outside the UK.
        "blocked_markers": [
            "it looks like you're outside the uk",  # noqa: RUF001 (service copy)
            "not available in your area",
            "currently only available in the united kingdom",
            "we think you are outside the uk",
        ],
        "eligible_markers": [
            "iplayer",  # the index rendered for this vantage point
        ],
        # iPlayer serves UK content; region is UK when eligible.
        "region_regex": None,
        "region_if_eligible": "GB",
    },
    "disney-plus": {
        "name": "Disney+",
        "pages": [
            "https://www.disneyplus.com/",
            "https://www.disneyplus.com/sign-up",
        ],
        "blocked_markers": [
            "not available in your location",
            "not available in your region",
            "is not yet available in your country",
            "unavailable in your market",
        ],
        "eligible_markers": [
            "disney+",
        ],
        "region_regex": None,
    },
    "max": {
        "name": "Max (HBO)",
        "pages": [
            "https://www.max.com/",
            "https://www.max.com/sign-in",
        ],
        "blocked_markers": [
            "not available in your location",
            "not available in your region",
            "max is not available",
        ],
        "eligible_markers": [
            "max",
        ],
        "region_regex": None,
    },
    "youtube-tv": {
        "name": "YouTube TV",
        "pages": [
            "https://tv.youtube.com/",
            "https://tv.youtube.com/welcome/",
        ],
        "blocked_markers": [
            "not available in your area",
            "not available in your location",
            "unavailable in your country",
        ],
        "eligible_markers": [
            "youtube tv",
        ],
        "region_regex": None,
    },
    "dazn": {
        "name": "DAZN",
        "pages": [
            "https://www.dazn.com/",
            "https://www.dazn.com/home",
        ],
        "blocked_markers": [
            "not available in your location",
            "not available in your region",
        ],
        "eligible_markers": [
            "dazn",
        ],
        "region_regex": None,
    },
}

# The transport profiles a chain can run under; the probe records which
# one it measured, because the 2026 detection stacks (JA3/JA4, DPI on
# WireGuard handshakes) classify the transport, not just the IP.
TRANSPORTS = ("cloak", "tcp443", "i2p-front", "tor-front", "wireguard", "direct")


def classify(service: str, pages: list[tuple[str, int, str]]) -> dict:
    """Turn fetched pages into (result, region, markers_seen).

    blocked beats eligible beats unknown; each page's status code is
    part of the evidence (403/451 on a content page is a class signal
    even when the copy matches nothing)."""
    adapter = ADAPTERS[service]
    markers_seen = []
    statuses = [status for _, status, _ in pages]
    result = "unknown"
    region = None
    for _url, status, body in pages:
        low = body.lower()
        for marker in adapter["blocked_markers"]:
            if marker in low and marker not in markers_seen:
                markers_seen.append(marker)
                result = "blocked"
        for marker in adapter["eligible_markers"]:
            if marker in low and marker not in markers_seen:
                markers_seen.append(marker)
        # 403/451 anywhere on a content page: the class-level refusal.
        if status in (403, 451) and result == "unknown":
            result = "blocked"
            markers_seen.append(f"http-{status}")
    if result == "unknown" and markers_seen:
        result = "eligible"
    if adapter.get("region_regex"):
        for _, _, body in pages:
            m = re.search(adapter["region_regex"], body)
            if m:
                region = m.group(1)
                break
    if result == "eligible" and region is None and adapter.get("region_if_eligible"):
        region = adapter["region_if_eligible"]
    return {
        "result": result,
        "region": region,
        "markers_seen": markers_seen,
        "statuses": statuses,
    }


def fetch(url: str, timeout: int, base_url: str | None = None) -> tuple[int, str]:
    """One page fetch. base_url overrides the adapter's origin (tests)."""
    if base_url:
        target = base_url.rstrip("/") + "/" + url.split("://", 1)[1].split("/", 1)[1]
    else:
        target = url
    # Only https to a service; plain http only to this machine (the tests' local server).
    parts = urllib.parse.urlsplit(target)
    if not (
        parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"))
    ):
        raise ValueError("refusing to fetch %s: https only" % parts.scheme)
    req = urllib.request.Request(  # noqa: S310 (scheme checked above)
        target, headers={"User-Agent": USER_AGENT, "Accept-Language": "en-GB,en;q=0.9"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310 (scheme checked above)
            body = response.read(512 * 1024).decode("utf-8", "replace")
            return response.status, body
    except urllib.error.HTTPError as e:
        # A refused request is evidence, not a fetch failure.
        body = e.read(512 * 1024).decode("utf-8", "replace")
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ProbeError(f"{target}: {e}") from e


def run_probe(service: str, *, timeout: int = DEFAULT_TIMEOUT, base_url: str | None = None) -> dict:
    """Fetch every page of the adapter and classify. Returns the dated
    record the evidence file and the descriptor merge consume."""
    if service not in ADAPTERS:
        raise SystemExit(f"unknown service: {service} (known: {', '.join(sorted(ADAPTERS))})")
    pages = []
    errors = []
    for url in ADAPTERS[service]["pages"]:
        try:
            status, body = fetch(url, timeout, base_url)
            pages.append((url, status, body))
        except ProbeError as e:
            errors.append(str(e))
    if not pages and errors:
        raise ProbeError("; ".join(errors))
    verdict = classify(service, pages)
    return {
        "schema": SCHEMA,
        "service": service,
        "checked": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "result": verdict["result"],
        "region": verdict["region"],
        "markers_seen": verdict["markers_seen"],
        "statuses": verdict["statuses"],
        "pages": len(pages),
        "fetch_errors": errors,
    }


def record_path(evidence_dir: Path, service: str, exit_id: str) -> Path:
    """Where a probe's record is written."""
    safe = re.sub(r"[^a-z0-9._-]", "_", exit_id.lower())
    return evidence_dir / f"{service}-{safe}.json"


def save_record(record: dict, exit_id: str, transport: str, evidence_dir: Path | None = None) -> Path:
    """Write the dated run record (one per service-exit, history kept)."""
    evidence_dir = evidence_dir or EVIDENCE_DIR
    path = record_path(evidence_dir, record["service"], exit_id)
    history = []
    if path.exists():
        try:
            history = json.loads(path.read_text()).get("history", [])
        except (json.JSONDecodeError, OSError):
            history = []
    entry = dict(record)
    entry["exit"] = exit_id
    entry["transport_profile"] = transport
    history.append(entry)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema": SCHEMA,
        "service": record["service"],
        "exit": exit_id,
        "history": history,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=1) + "\n")
    os.replace(tmp, path)
    return path


def descriptor_merge(descriptor_path: Path, record: dict, transport: str) -> list:
    """Merge the result into a descriptor's `streaming` list (unsigned
    working copy; the owner's signing step re-signs the descriptor —
    the probe never touches a signed file in place).

    One entry per service, replaced (not appended) so the field stays
    the current dated fact; the full history lives in the evidence
    file."""
    doc = json.loads(Path(descriptor_path).read_text())
    streaming = list(doc.get("streaming", []))
    entry = {
        "service": record["service"],
        "region": record["region"],
        "result": record["result"],
        "checked": record["checked"],
        "transport_profile": transport,
    }
    streaming = [e for e in streaming if e.get("service") != entry["service"]]
    streaming.append(entry)
    doc["streaming"] = streaming
    tmp = Path(descriptor_path).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=1) + "\n")
    os.replace(tmp, descriptor_path)
    return streaming


def human_report(record: dict, transport: str) -> str:
    """A probe record as text for the terminal."""
    lines = [
        f"{ADAPTERS[record['service']]['name']}: {record['result'].upper()}"
        + (f" ({record['region']})" if record["region"] else ""),
        f"  checked : {record['checked']} (UTC)",
        f"  transport: {transport}",
        f"  statuses: {record['statuses']} over {record['pages']} page(s)",
    ]
    if record["markers_seen"]:
        lines.append(f"  markers : {', '.join(record['markers_seen'])}")
    if record["fetch_errors"]:
        lines.append(f"  errors  : {record['fetch_errors']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    """Command line: probe one service through the current exit."""
    parser = argparse.ArgumentParser(
        prog="stream-check",
        description="Measure a streaming service's eligibility of this exit "
        "(run it inside the namespace: avpn run -- stream-check ...)",
    )
    parser.add_argument("service", choices=sorted(ADAPTERS))
    parser.add_argument("--exit", default="this-exit", help="the exit's id for the record (descriptor name or IP)")
    parser.add_argument(
        "--transport", default="direct", choices=TRANSPORTS, help="the transport profile of the tested path"
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--base-url", default=None, help=argparse.SUPPRESS)  # tests: local mock origin
    parser.add_argument("--descriptor", default=None, help="merge the dated result into this (unsigned) descriptor")
    parser.add_argument("--json", action="store_true", help="print the record as JSON")
    parser.add_argument("--evidence-dir", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        record = run_probe(args.service, timeout=args.timeout, base_url=args.base_url)
    except ProbeError as e:
        print(f"probe failed: {e}", file=sys.stderr)
        return 2
    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else EVIDENCE_DIR
    path = save_record(record, args.exit, args.transport, evidence_dir)
    if args.descriptor:
        descriptor_merge(Path(args.descriptor), record, args.transport)
    if args.json:
        print(json.dumps(record, indent=1))
    else:
        print(human_report(record, args.transport))
    print(f"record: {path}")
    # Exit codes are honest: unknown is not a pass.
    return 0 if record["result"] == "eligible" else 1 if record["result"] == "blocked" else 3


if __name__ == "__main__":
    raise SystemExit(main())

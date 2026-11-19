#!/usr/bin/env python3
"""Bounded, read-only SearchProviders over the pinned local provider index.

Implements the controller-contract extension from
docs/HARDWARE_EMULATION_AND_CLOUD_INSTALLER_PLAN_20261118.md (§ Interfaces
and execution boundary): "Add bounded, read-only SearchProviders(query,
cursor, filter) ... Maximum 50 results, 256 UTF-8 query bytes; opaque cursor
bound to the index digest. Return public metadata only and keep existing
response bounds."

Design points shared with tools/controller_bridge.py:

- Fixed refusal strings; raw text never crosses the boundary.
- Strict allowlist and exact request fields before any work runs.
- The shipped index is read from a fixed root-owned path delivered through
  the authenticated application release; callers never name a file, URL,
  provider binary or plugin. Registry search never executes provider
  binaries and never installs anything.
- No query telemetry: queries are not logged, not echoed in responses and
  not persisted anywhere. There are no network calls and no per-keystroke
  I/O beyond one immutable in-memory index.
- A result's listing tier is registry fact; recipe availability is review
  fact. Registry inclusion does not establish that a provider offers VM
  compute, permits VPN exits or supports this VPN, so capability and
  evidence fields are "unknown"/"none" unless separately reviewed evidence
  says otherwise. Unreviewed entries stay viewable but can never be
  promoted to runnable status by this contract.
"""

import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zlib
from functools import lru_cache

from controller_bridge import Refused, canonical

MAX_QUERY_BYTES = 256
MAX_RESULTS = 50
MAX_RESPONSE = 128 * 1024
MAX_CURSOR_CHARS = 512
MAX_ARCHIVE_BYTES = 256 * 1024
MAX_INDEX_BYTES = 2 * 1024 * 1024
INDEX_SHA256 = "47012468ee08e20632716ac1343c4543a0731183dc47af75a269d2873c10f991"
FILTERS = ("all", "reviewed_recipes", "unreviewed", "unavailable_non_compute")
INDEX_FIELDS = (
    "schema",
    "source",
    "source_tree_sha",
    "fetched_utc",
    "providers_total",
    "reviewed_recipe_candidates",
    "search_contract",
    "providers",
    "index_sha256",
)
ENTRY_FIELDS = ("id", "namespace", "name", "path", "reviewed_recipe_candidate")
CURSOR_PREFIX = b"cypherpunk/provider-cursor/v1"


def load_index(path, artifact_sha256):
    """Load and strictly validate the immutable shipped index bundle.

    `path` is a fixed production path chosen by the worker, never a caller
    value. `artifact_sha256` is the required reviewed uncompressed digest;
    mismatching bytes refuse the whole bundle (no partial fallback).
    """
    if not isinstance(artifact_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        raise Refused("provider_index_digest_required")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            entry = os.fstat(stream.fileno())
            if not stat.S_ISREG(entry.st_mode) or entry.st_size > MAX_ARCHIVE_BYTES:
                raise Refused("invalid_provider_index")
            raw = stream.read(MAX_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise Refused("invalid_provider_index")
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as archive:
            payload = archive.read(MAX_INDEX_BYTES + 1)
        if len(payload) > MAX_INDEX_BYTES:
            raise Refused("invalid_provider_index")
    except (OSError, EOFError, zlib.error):
        raise Refused("provider_index_unavailable") from None
    # The reviewed release digest covers the uncompressed canonical payload;
    # the gzip container is transport, verified by the release process itself.
    if hashlib.sha256(payload).hexdigest() != artifact_sha256:
        raise Refused("provider_index_digest_mismatch")
    try:
        document = json.loads(payload)
    except ValueError:
        raise Refused("invalid_provider_index") from None
    if not isinstance(document, dict) or tuple(sorted(document)) != tuple(sorted(INDEX_FIELDS)):
        raise Refused("invalid_provider_index")
    if type(document["schema"]) is not int or document["schema"] != 1 or not isinstance(document["providers"], list):
        raise Refused("invalid_provider_index")
    if type(document["providers_total"]) is not int or document["providers_total"] != len(document["providers"]):
        raise Refused("provider_index_count_mismatch")
    seen = set()
    for entry in document["providers"]:
        if not isinstance(entry, dict) or tuple(sorted(entry)) != tuple(sorted(ENTRY_FIELDS)):
            raise Refused("invalid_provider_index")
        provider_id = entry["id"]
        if any(
            not isinstance(entry[k], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", entry[k])
            for k in ("namespace", "name")
        ):
            raise Refused("invalid_provider_index")
        if not isinstance(provider_id, str) or provider_id != f"{entry['namespace']}/{entry['name']}".lower():
            raise Refused("invalid_provider_index")
        if provider_id in seen or type(entry["reviewed_recipe_candidate"]) is not bool:
            raise Refused("invalid_provider_index")
        seen.add(provider_id)
    # The embedded digest covers the document without the digest field itself,
    # reproduced byte-exactly by re-serializing in the shipped insertion order
    # (the indexer never sorts keys; neither does this verification).
    body = {name: document[name] for name in document if name != "index_sha256"}
    payload = json.dumps(body, separators=(",", ":")).encode()
    if hashlib.sha256(payload).hexdigest() != document["index_sha256"]:
        raise Refused("provider_index_digest_mismatch")
    if document.get("search_contract") != {
        "max_results": MAX_RESULTS,
        "max_query_bytes": MAX_QUERY_BYTES,
        "cursor_bound_to_index_digest": True,
        "no_network_calls": True,
        "no_query_telemetry": True,
    }:
        raise Refused("provider_index_contract_mismatch")
    return document


@lru_cache(maxsize=1)
def shipped_index():
    """Read only the digest-pinned bundle in this authenticated application slot."""
    return load_index(Path(__file__).with_name("provider_data") / "opentofu_registry_index.json.gz", INDEX_SHA256)


def encode_cursor(offset, query, provider_filter, index_digest):
    """Opaque pagination token bound to this index, query and filter."""
    body = canonical(
        dict(
            v=1,
            o=offset,
            q=hashlib.sha256(
                CURSOR_PREFIX + b"\0q\0" + query.encode() + b"\0f\0" + provider_filter.encode()
            ).hexdigest(),
            i=index_digest,
        )
    )
    return base64.urlsafe_b64encode(CURSOR_PREFIX + b"\0" + body).decode("ascii").rstrip("=")


def decode_cursor(token, query, provider_filter, index_digest, total):
    """Validate strictly; a foreign query, filter, index or offset refuses."""
    if not isinstance(token, str) or not token or len(token) > MAX_CURSOR_CHARS:
        raise Refused("invalid_provider_cursor")
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        prefix, _, body = raw.partition(b"\0")
        value = json.loads(body)
    except (ValueError, TypeError):
        raise Refused("invalid_provider_cursor") from None
    if prefix != CURSOR_PREFIX or not isinstance(value, dict) or set(value) != {"v", "o", "q", "i"}:
        raise Refused("invalid_provider_cursor")
    if value["v"] != 1 or type(value["o"]) is not int or not 0 <= value["o"] <= total:
        raise Refused("invalid_provider_cursor")
    expected = hashlib.sha256(
        CURSOR_PREFIX + b"\0q\0" + query.encode() + b"\0f\0" + provider_filter.encode()
    ).hexdigest()
    if value["q"] != expected or value["i"] != index_digest:
        raise Refused("stale_provider_cursor")
    return value["o"]


def _entry_tier(entry):
    if entry["reviewed_recipe_candidate"]:
        return "recipe_candidate"
    return "listed_only"


def _result(entry):
    """Public metadata only. Evidence tiers stay unknown/none without review."""
    provider_id = entry["id"]
    reviewed = entry["reviewed_recipe_candidate"]
    return dict(
        id=provider_id,
        namespace=entry["namespace"],
        name=entry["name"],
        listed=True,
        tier=_entry_tier(entry),
        reviewed_recipe_candidate=reviewed,
        recipe_available=False,
        can_launch_provisioning=False,
        recipe_blocker="no_reviewed_recipe",
        documented_capabilities="unknown",
        vm_test_evidence="unknown",
        authorized_live_evidence="unknown",
    )


def search(index, value):
    """The SearchProviders(query, cursor, filter) contract method.

    `index` is the validated immutable document from load_index. Recipe
    candidates are discovery leads only. The returned dict is the complete public
    response; it never echoes the raw query text.
    """
    if not isinstance(value, dict) or set(value) != {"query", "cursor", "filter"}:
        raise Refused("invalid_search_request")
    query, cursor, provider_filter = value["query"], value["cursor"], value["filter"]
    if provider_filter not in FILTERS:
        raise Refused("invalid_search_filter")
    if not isinstance(query, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in query):
        raise Refused("invalid_search_query")
    if len(query.encode()) > MAX_QUERY_BYTES or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in query
    ):
        raise Refused("invalid_search_query")
    digest = index["index_sha256"]
    total = index["providers_total"]
    needle = query.casefold()
    matches = [entry for entry in index["providers"] if _matches(entry, needle, provider_filter)]
    offset = 0 if cursor is None else decode_cursor(cursor, query, provider_filter, digest, total)
    if offset > len(matches):
        raise Refused("stale_provider_cursor")
    page = matches[offset : offset + MAX_RESULTS]
    next_cursor = None
    if offset + MAX_RESULTS < len(matches):
        next_cursor = encode_cursor(offset + MAX_RESULTS, query, provider_filter, digest)
    response = dict(
        schema=1,
        index_sha256=digest,
        index_source_tree_sha=index["source_tree_sha"],
        index_generated_utc=index["fetched_utc"],
        filter=provider_filter,
        total_matches=len(matches),
        offset=offset,
        returned=len(page),
        next_cursor=next_cursor,
        results=[_result(entry) for entry in page],
    )
    if len(canonical(response)) > MAX_RESPONSE:
        raise Refused("search_response_too_large")
    return response


def _matches(entry, needle, provider_filter):
    """Deterministic local match. Index order already ranks reviewed first."""
    if provider_filter == "reviewed_recipes":
        # No reviewed executable OpenTofu recipes have shipped. A research
        # candidate cannot grant execution authority or appear as reviewed.
        return False
    elif provider_filter == "unreviewed":
        pass
    elif provider_filter == "unavailable_non_compute":
        # Only separately reviewed capability evidence may mark a listed
        # provider unavailable/non-compute; the registry alone never does.
        return False
    if not needle:
        return True
    haystack = (entry["id"] + "\0" + entry["namespace"] + "\0" + entry["name"]).casefold()
    return needle in haystack

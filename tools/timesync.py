"""A synchronized clock for timestamps other people see (htpdate-style, as Tails does it).

Oblivious requests no longer use it: they take the relay's clock (tools/mesh.py
relay_clock), which costs no extra traffic and asks no third party. This stays for a
caller without a relay; note that, unlike Tails, it does not run over Tor, so its regular
visits to a fixed set of sites are visible to whoever watches this host's connection.

An oblivious request (tools/ohttp.py) carries a timestamp, and the gateway sees it beside
its own clock: a member whose clock is off by a steady offset would be recognizable by
that offset from request to request. So the timestamp comes from this clock, not the
system's: like Tails' htpdate, take the HTTP `Date` header of one randomly chosen server
from each of three pools of busy HTTPS sites run by unrelated organizations, and use the
median, so one lying or broken pool cannot move it. A pool none of whose tried servers
answers with a valid certificate aborts the sync: nothing is sent with an unsynchronized
clock. Only response headers are fetched (HEAD), and the system clock is never changed.

The result is used rounded down to a 30-second bucket (ohttp.BUCKET), so members with
synchronized clocks send the same value; the `Date` header's one-second resolution and
the network delay are well inside a bucket.
"""

import email.utils
import random
import ssl
import statistics
import threading
import time
import urllib.error
import urllib.request

# Unrelated operators, one pool each (Tails' design: a server in one pool is unlikely to
# collude with one in another): free-software and privacy groups; public institutions,
# universities and newspapers; commercial infrastructure. Busy sites, so a time query is
# unremarkable traffic. Chosen from a live survey on 20 November 2026: each answered HEAD
# with a fresh Date within a second of the median. Left out: sites whose answers came
# from a cache (eff.org, wikipedia.org, mozilla.org, kernel.org, ietf.org, w3.org,
# python.org, ethz.ch) and two that answered fresh but consistently ~9.5 s off
# (amazon.com fast, github.com slow).
POOLS = (
    ("www.torproject.org", "riseup.net", "www.debian.org", "www.gnu.org", "www.ccc.de", "www.openbsd.org"),
    ("www.bbc.co.uk", "www.theguardian.com", "www.mit.edu", "www.ox.ac.uk", "home.cern", "archive.org"),
    ("www.cloudflare.com", "www.google.com", "www.apple.com", "www.fastly.com", "www.netflix.com"),
)
TRIES_PER_POOL = 3
TIMEOUT = 10
VALID_SECONDS = 3600  # resynchronize hourly
MAX_SPREAD = 30  # the pools disagree by more than a bucket: something is wrong
MAX_AGE = 2  # seconds a response may have spent in a cache


class ClockUnsynchronized(RuntimeError):
    """No trustworthy time: a pool failed, or the pools disagree."""


def date_offset(host, timeout=TIMEOUT):
    """Seconds to add to the local clock to match `host`'s Date header (HEAD over HTTPS,
    certificate verified), measured at the midpoint of the request."""
    request = urllib.request.Request(  # noqa: S310 (a fixed https:// URL)
        "https://%s/" % host, method="HEAD", headers={"User-Agent": "Mozilla/5.0", "Cache-Control": "no-cache"}
    )
    before = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as r:  # noqa: S310
            headers = r.headers
    except urllib.error.HTTPError as e:  # an error page still carries the server's Date
        headers = e.headers
    after = time.time()
    date = headers.get("Date")
    if not date:
        raise ValueError("no Date header")
    # A cached response's Date may be when the origin made it (Wikipedia's CDN served one
    # 73 minutes old) or when the cache served it (others rewrite it), so Age cannot be
    # applied either way: a response that was cached is not used, and the pool's next
    # server answers instead. The request asks for a fresh one.
    if int(headers.get("Age") or 0) > MAX_AGE:
        raise ValueError("a cached response: its Date is not now")
    return email.utils.parsedate_to_datetime(date).timestamp() - (before + after) / 2


def synchronize(pools=POOLS, offset_of=date_offset, rng=None):
    """The median offset of one server per pool; raises ClockUnsynchronized."""
    rng = rng or random.SystemRandom()
    offsets = []
    for pool in pools:
        for host in rng.sample(list(pool), min(TRIES_PER_POOL, len(pool))):
            try:
                offsets.append(offset_of(host))
                break
            except Exception:  # noqa: S112 (unreachable, bad certificate, no Date: the next one)
                continue
        else:
            raise ClockUnsynchronized("no server in a time pool answered; refusing to guess")
    middle = statistics.median(offsets)
    # One outlier is what the median is for; but at least two pools must agree with it.
    if sum(abs(o - middle) <= MAX_SPREAD for o in offsets) < 2:
        raise ClockUnsynchronized("the time pools disagree; refusing to guess")
    return middle


_lock = threading.Lock()
_state = {"offset": None, "at": 0.0}


def now(sync=synchronize):
    """The synchronized time in seconds; synchronizes at most hourly."""
    with _lock:
        if _state["offset"] is None or time.monotonic() - _state["at"] > VALID_SECONDS:
            _state["offset"] = sync()
            _state["at"] = time.monotonic()
        return time.time() + _state["offset"]


def forget():
    """Drop the cached offset (tests, or after the system clock jumps)."""
    with _lock:
        _state["offset"] = None

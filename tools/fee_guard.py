"""No fees from a free account: every server's monthly outbound cap (standard library only).

Contributing a free-tier account to the network must never produce a bill (owner, 20 Nov
2026). What a provider bills a VPN host for is, in the end, outbound traffic: a server
sends every byte it carries out again. So every server enforces a monthly cap on what it
sends, and stops serving at it until the first of the next month (UTC):

- the cap comes from the provider's free allowance, and that allowance belongs to the
  account, not the server (AWS: 100 GB "aggregated across all AWS Services and Regions";
  Azure: 100 GB per customer; Oracle: 10 TB per tenancy; Fly.io: a personal organization's
  whole bill under $5), so servers sharing an account share it;
- fixed costs come off a money allowance first (Fly.io bills a bill of $5 or more in full:
  the cap keeps the whole bill, machine and volume included, under it with a margin);
- a margin (10%) covers SSH, updates and counting granularity;
- an account whose allowance is not on record gets no cap by default: a server without a
  cap refuses to serve unless its owner sets one or marks it unlimited (their own box).

The meter counts what the host sends on every interface except loopback and the data
plane's own TUN devices (a host with containers is overcounted, never under), per UTC
calendar month. It keeps one number, rounded up to 16 MiB, across reboots: no per-user,
per-session or per-destination count, and no times.

Imported by cloud.py under the system Python: nothing outside the standard library.
"""

import datetime
import json
import math
import os
from pathlib import Path

CHECKED = "2026-11-20"
GB = 1000**3  # providers bill decimal gigabytes
STEP = 16 << 20  # what the persisted count is rounded to
MARGIN = 0.9  # of the free allowance the data plane may use

# Free monthly outbound allowance per ACCOUNT (decimal GB), and where it was read.
ACCOUNT_FREE_GB = {
    "oci": (10_000, "10 TB per month of outbound data (Always Free), per tenancy",
            "https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm"),
    "aws": (100, "100 GB/month out to the internet, aggregated across all services and Regions",
            "https://aws.amazon.com/ec2/pricing/on-demand/"),
    "azure": (100, "the first 100 GB/month of egress free to all customers",
              "https://azure.microsoft.com/en-us/pricing/details/bandwidth/"),
    "gcp": (1, "1 GB/month out (e2-micro free tier)", "https://docs.cloud.google.com/free/docs/free-cloud-features"),
}  # fmt: skip

# Fly.io: no free allowance, but a personal organization's bill under $5 a month is waived,
# and a bill of $5 or more is paid in full (docs.fly.io/about/free-waiver).
FLY_WAIVER_USD = 5.0
FLY_SAFETY_USD = 1.0  # kept unused: price changes, rounding, a stray snapshot
FLY_USD_PER_GB = {"na_eu": 0.02, "apac_oceania_sa": 0.04, "africa_india": 0.12}
FLY_MACHINE_USD = {256: 2.19, 512: 3.69, 1024: 6.70}  # iad/ewr, the cheapest regions
FLY_REGION_FACTOR = 1.2  # other regions cost more (1 GB: $7.73 in fra vs $6.70 in iad)
FLY_VOLUME_USD_PER_GB = 0.15
FLY_SOURCE = "https://docs.fly.io/about/pricing"
FLY_GROUPS = {
    "na_eu": {"iad", "ewr", "ord", "dfw", "lax", "sjc", "sea", "yyz", "yul", "mia", "atl", "bos", "den", "phx",
              "qro", "ams", "fra", "lhr", "cdg", "arn", "mad", "otp", "waw", "lis"},
    "apac_oceania_sa": {"nrt", "hkg", "sin", "syd", "gru", "scl", "eze", "bog", "gdl"},
    "africa_india": {"jnb", "bom", "maa", "del"},
}  # fmt: skip


class FeeGuardError(Exception):
    """A cap that cannot be set safely."""


def fly_region_group(region):
    """The Fly.io price group of `region` (an unknown one costs the most)."""
    for group, regions in FLY_GROUPS.items():
        if region in regions:
            return group
    return "africa_india"  # an unknown region is priced at the dearest rate


def fly_free_gb(region, memory_mb=256, volume_gb=1, machines=1):
    """(GB, why): outbound traffic a Fly.io personal organization can send in a month and
    stay under the waiver, after its machines and volumes are paid for."""
    if memory_mb not in FLY_MACHINE_USD:
        raise FeeGuardError("no Fly.io price on record for a %d MB machine" % memory_mb)
    factor = 1.0 if region in ("iad", "ewr") else FLY_REGION_FACTOR
    fixed = machines * (FLY_MACHINE_USD[memory_mb] * factor + volume_gb * FLY_VOLUME_USD_PER_GB)
    left = FLY_WAIVER_USD - FLY_SAFETY_USD - fixed
    rate = FLY_USD_PER_GB[fly_region_group(region)]
    if left <= 0:
        raise FeeGuardError(
            "Fly.io fixed costs (about $%.2f/month for %d machine(s)) leave nothing under the $5 waiver"
            % (fixed, machines)
        )
    return left / rate, "Fly.io $5 waiver: $%.2f fixed, $%.2f kept spare, $%.2f/GB in %s" % (
        fixed, FLY_SAFETY_USD, rate, region)  # fmt: skip


def account_free_gb(provider, **fly):
    """(GB or None, why) the account behind `provider` may send free per month."""
    if provider == "fly":
        return fly_free_gb(**fly)
    if provider in ACCOUNT_FREE_GB:
        gb, why, _source = ACCOUNT_FREE_GB[provider]
        return gb, why
    return None, "no free allowance on record for %s" % provider


def plan_caps(servers):
    """Each server's cap in bytes: {name: (bytes or None, why)}.

    `servers` maps name -> dict(provider, account, and for Fly region/memory_mb/volume_gb).
    The account's allowance is shared equally by its servers (all of them forward the
    same stream); an explicit `cap_gb` or `unlimited` on a server wins.
    """
    accounts = {}
    for name, s in servers.items():
        accounts.setdefault((s["provider"], s.get("account") or ""), []).append(name)
    caps = {}
    for (provider, _account), names in accounts.items():
        explicit = [n for n in names if servers[n].get("cap_gb") is not None or servers[n].get("unlimited")]
        shared = [n for n in names if n not in explicit]
        for n in explicit:
            s = servers[n]
            caps[n] = (None, "unlimited (set by its owner)") if s.get("unlimited") else (
                int(s["cap_gb"] * GB), "%g GB (set by its owner)" % s["cap_gb"])  # fmt: skip
        if not shared:
            continue
        first = servers[shared[0]]
        fly = {}
        if provider == "fly":
            fly = dict(region=first.get("region", ""), memory_mb=first.get("memory_mb", 256),
                       volume_gb=first.get("volume_gb", 1), machines=len(names))  # fmt: skip
        gb, why = account_free_gb(provider, **fly)
        for n in shared:
            if gb is None:
                caps[n] = (None, why + ": set a cap (avpn cloud cap %s --gb N) or mark it --unlimited" % n)
                continue
            share = gb * MARGIN / len(names)
            caps[n] = (int(share * GB), "%.0f GB: %d%% of %s%s" % (
                share, MARGIN * 100, why, ", shared by %d servers on this account" % len(names) if len(names) > 1
                else ""))  # fmt: skip
    return caps


def month_of(t):
    """The UTC month of `t`, as YYYY-MM."""
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m")


def next_month_start(t):
    """The start of the UTC month after `t`."""
    d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    y, m = (d.year + 1, 1) if d.month == 12 else (d.year, d.month + 1)
    return datetime.datetime(y, m, 1, tzinfo=datetime.timezone.utc)


def month_fraction(t):
    """How far through its UTC month `t` is (0..1)."""
    d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    start = datetime.datetime(d.year, d.month, 1, tzinfo=datetime.timezone.utc)
    return (t - start.timestamp()) / (next_month_start(t).timestamp() - start.timestamp())


def read_cap(path):
    """The cap a server enforces: ('bytes', N), ('unlimited', None), or ('missing', None)."""
    try:
        raw = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return "missing", None
    if raw.get("unlimited") is True:
        return "unlimited", None
    cap = raw.get("cap_bytes")
    if not isinstance(cap, int) or cap <= 0:
        raise FeeGuardError("monthly cap file is malformed")
    return "bytes", cap


def write_cap(path, cap_bytes, why):
    """Write a server's cap (None: unlimited) atomically, root-only."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = dict(schema=1, why=why, checked=CHECKED)
    body.update(unlimited=True) if cap_bytes is None else body.update(cap_bytes=int(cap_bytes))
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(body))
    tmp.chmod(0o600)
    os.replace(tmp, path)


class Meter:
    """The host's outbound bytes this UTC month, kept across reboots and restarts."""

    def __init__(self, path, sysfs="/sys/class/net", boot_id="/proc/sys/kernel/random/boot_id", now=None,
                 source=None):  # fmt: skip
        # `source`: a callable giving {name: cumulative bytes} instead of the interfaces
        # (a shared host counts only the VPN's own traffic, from an nftables counter).
        self.path, self.sysfs, self.boot_path, self.source = Path(path), Path(sysfs), Path(boot_id), source
        import time

        self.now = now or time.time
        self.month, self.used, self.boot, self.counters = month_of(self.now()), 0, None, {}
        try:
            saved = json.loads(self.path.read_text())
            self.month, self.used = saved["month"], int(saved["bytes"])
            self.boot, self.counters = saved.get("boot"), dict(saved.get("counters") or {})
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            pass
        self.saved_step = None

    def interfaces(self):
        """tx byte counters of every interface but loopback and TUN devices."""
        out = {}
        for d in sorted(self.sysfs.iterdir()) if self.sysfs.exists() else []:
            if d.name == "lo" or (d / "tun_flags").exists():
                continue
            try:
                out[d.name] = int((d / "statistics" / "tx_bytes").read_text())
            except (OSError, ValueError):
                continue
        return out

    def sample(self):
        """Fold in what was sent since the last sample; persist when the rounded total moves."""
        boot = self.boot_path.read_text().strip() if self.boot_path.exists() else ""
        now_counters = self.source() if self.source else self.interfaces()
        if boot != self.boot:
            delta = sum(now_counters.values())  # everything since this boot
        else:
            delta = sum(v - self.counters[k] if k in self.counters and v >= self.counters[k] else v
                        for k, v in now_counters.items())  # fmt: skip
        self.boot, self.counters = boot, now_counters
        month = month_of(self.now())
        if month > self.month:
            self.month, self.used = month, 0  # a gap across the turn of the month counts in the new one
        # A clock set back never reopens an earlier month's allowance: it keeps counting
        # in the latest month seen.
        self.used += delta
        step = math.ceil(self.used / STEP)
        if step != self.saved_step:
            self.persist(step)
        return self.used

    def persist(self, step):
        """Save the month's total, rounded up to `step` x STEP."""
        # Conservative both ways: the total rounded up, the counters rounded down (so a
        # restart on the same boot counts a little twice rather than not at all).
        body = dict(schema=1, month=self.month, bytes=step * STEP, boot=self.boot,
                    counters={k: v // STEP * STEP for k, v in self.counters.items()})  # fmt: skip
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body))
        tmp.chmod(0o600)
        os.replace(tmp, self.path)
        self.saved_step = step


def verdict(used, cap, t):
    """The status row's `monthly` field: used, cap, whether capped, when it resumes, and
    when (at this month's pace) the cap would be reached."""
    row = dict(month=month_of(t), used_bytes=used, cap_bytes=cap, capped=cap is not None and used >= cap)
    if cap is None:
        return row
    row["resumes"] = next_month_start(t).isoformat(timespec="seconds")
    frac = month_fraction(t)
    if used > 0 and frac > 0.02:
        pace = used / frac  # projected for the whole month
        if pace > cap:
            d = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
            start = datetime.datetime(d.year, d.month, 1, tzinfo=datetime.timezone.utc)
            span = (next_month_start(t) - start).total_seconds()
            row["runs_out"] = (start + datetime.timedelta(seconds=span * cap / pace)).isoformat(timespec="seconds")
    return row


def describe(row):
    """One line for status and health."""
    used = row["used_bytes"] / GB
    if row.get("cap_bytes") is None:
        return "%.1f GB sent this month (no cap: unlimited)" % used
    cap = row["cap_bytes"] / GB
    text = "%.1f of %.0f GB this month (%d%%)" % (used, cap, min(999, 100 * row["used_bytes"] // row["cap_bytes"]))
    if row["capped"]:
        return text + ": CAPPED, stopped until %s so the account is never billed" % row["resumes"][:10]
    if row.get("runs_out"):
        return text + "; at this pace it stops on %s" % row["runs_out"][:10]
    return text


def paths(state):
    """Where a server keeps its cap and its meter: beside, not inside, the enrolled state,
    so re-enrolling (which replaces that directory) never resets the month."""
    base = Path(state).parent / "metering" / Path(state).name
    return base / "cap.json", base / "usage.json"

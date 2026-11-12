"""The constant-rate stream's classes and what they cost (standard library only).

Imported by managed_profile (signing) and by cloud.py, which runs under the system
Python without the hash-locked dependencies, so it must not import anything else.
"""

# The constant-rate stream's classes (src/daita.rs RateClass): wire packets per second
# in each direction of each link while connected. Speed and cost differ; the shape does not.
RATE_CLASSES = {"metered": 50, "standard": 500, "fast": 4000, "line": 16000}


# Bytes per wire packet (IPv4 + UDP + the cloak's QUIC datagram carrying one cell),
# measured in docs/evidence/RATE_CLASSES.json.
WIRE_PACKET_BYTES = 1448


def rate_cost_gib(rate, hours_per_day, links=1):
    """Monthly (30-day) outbound GiB the stream costs one hop with `links` paced links
    (a relay has two: back to the client over the carrier, on to the next hop)."""
    return links * RATE_CLASSES[rate] * WIRE_PACKET_BYTES * 3600 * hours_per_day * 30 / (1 << 30)


def choose_rate(requested, allowance_gib, hours_per_day, accept_cost=False, links=1):
    """(class, reason) for `avpn init --rate`. `auto` picks the fastest class whose
    stream fits the chain's smallest monthly outbound allowance at `hours_per_day`
    connected (a relay pays for `links` streams); an explicit class that does not fit is refused unless `accept_cost`."""
    if not 0 < hours_per_day <= 24:
        raise ValueError("hours per day must be 1..24")
    if allowance_gib is not None and allowance_gib <= 0:
        raise ValueError("the allowance must be positive")
    fits = [r for r in RATE_CLASSES if allowance_gib is None or rate_cost_gib(r, hours_per_day, links) <= allowance_gib]
    if requested == "auto":
        if allowance_gib is None:
            return "metered", "no hop allowance given (--allowance-gib): the slowest class"
        if not fits:
            if not accept_cost:
                raise ValueError(
                    "even the metered class needs about %d GiB/month at %g h/day, over the %d GiB allowance; "
                    "connect fewer hours (--hours-per-day) or pass --accept-cost"
                    % (rate_cost_gib("metered", hours_per_day, links), hours_per_day, allowance_gib)
                )
            return "metered", "over the allowance, accepted with --accept-cost"
        best = fits[-1]
        return best, "fastest class within %d GiB/month at %g h/day (about %d GiB/month)" % (
            allowance_gib,
            hours_per_day,
            rate_cost_gib(best, hours_per_day, links),
        )
    if requested not in RATE_CLASSES:
        raise ValueError("unknown rate class: " + str(requested))
    if requested not in fits and not accept_cost:
        raise ValueError(
            "the %s class needs about %d GiB/month at %g h/day, over the %d GiB allowance; "
            "choose a slower class or pass --accept-cost"
            % (requested, rate_cost_gib(requested, hours_per_day, links), hours_per_day, allowance_gib)
        )
    return requested, "chosen explicitly"

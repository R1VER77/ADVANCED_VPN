#!/usr/bin/env python3
"""Byte budgets, latency and queue math for the AVPN mix lane + PQ-Sphinx graft.
All numbers printed here are the single source of truth for MIX_LANE_DESIGN.md."""

M = 1 << 20

# ---------------------------------------------------------------
# 1. Sphinx header sizes
# ---------------------------------------------------------------
# Per-hop header components (bytes)
X25519_ELEM = 32  # classical Sphinx group element
MLKEM512_CT = 768  # FIPS 203 ML-KEM-512 ciphertext
MLKEM768_CT = 1088  # FIPS 203 ML-KEM-768 ciphertext
MLKEM1024_CT = 1568  # FIPS 203 ML-KEM-1024 ciphertext
MAC = 32  # per-hop MAC (BLAKE3/HMAC truncated to 32B)
ROUTING_BLOCK = 48  # per-hop routing command block (padded, symmetric ct)
FIXED = 4  # version | n_hops | flags | pad
AEAD_TAG = 16  # payload AEAD tag (ChaCha20-Poly1305)

options = {
    # name: per-hop size expression as function of v
    "A classical X25519": lambda v: v * (X25519_ELEM + MAC + ROUTING_BLOCK),
    "B hybrid X25519+MLKEM-512": lambda v: v * (X25519_ELEM + MLKEM512_CT + MAC + ROUTING_BLOCK),
    "C ML-KEM-512 only": lambda v: v * (MLKEM512_CT + MAC + ROUTING_BLOCK),
    "D ML-KEM-768 only": lambda v: v * (MLKEM768_CT + MAC + ROUTING_BLOCK),
    "E entry ML-KEM-768 + inner X25519": lambda v: (
        (MLKEM768_CT + MAC + ROUTING_BLOCK) + (v - 1) * (X25519_ELEM + MAC + ROUTING_BLOCK)
    ),
}

print("=== 1. Header sizes (bytes) ===")
hdr = {}
print(f"{'option':<36}{'v=3':>8}{'v=4':>8}{'v=5':>8}")
for name, f in options.items():
    hdr[name] = {v: FIXED + f(v) for v in (3, 4, 5)}
    print(f"{name:<36}{hdr[name][3]:>8}{hdr[name][4]:>8}{hdr[name][5]:>8}")

# ---------------------------------------------------------------
# 2. Payload per cell + efficiency
# ---------------------------------------------------------------
print("\n=== 2. Payload bytes per cell (payload = S - header - AEAD tag) ===")
cells = (2048, 4096, 8192)
V = 3  # recommended path length for the mesh
print(f"path length v={V}; efficiency = payload/cell")
print(f"{'option':<36}" + "".join(f"{f'S={S}':>12}" for S in cells))
for name in options:
    h = hdr[name][V]
    row = f"{name:<36}"
    for S in cells:
        p = S - h - AEAD_TAG
        row += f"{p:>7}({100 * p / S:>3.0f}%)"
    print(row)

# ---------------------------------------------------------------
# 3. End-to-end latency: sum of v i.i.d. Exp(mean) = Erlang(v, 1/mean)
# ---------------------------------------------------------------
print("\n=== 3. End-to-end delay quantiles (seconds), v=3 hops ===")


def erlang_cdf(x, k, mean):
    """P(end-to-end delay <= x) for k Exp hops of the given per-hop mean (Erlang)."""
    # P(X<=x) for Erlang-k with mean 'mean'  (rate = k/mean)
    import math

    rate = k / mean
    s = 0.0
    term = 1.0
    for i in range(k):
        s += term
        term *= (rate * x) / (i + 1)
    return 1.0 - math.exp(-rate * x) * s


def quantile(q, k, mean):
    """The delay below which a fraction q of k-hop paths complete (inverse Erlang CDF)."""
    lo, hi = 0.0, 1.0
    while erlang_cdf(hi, k, mean) < q:
        hi *= 2
    for _ in range(80):
        mid = (lo + hi) / 2
        if erlang_cdf(mid, k, mean) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


print(f"{'per-hop mean':>14}{'p50':>8}{'p95':>8}{'p99':>8}")
for mean in (0.25, 0.5, 1.0, 2.0):
    print(f"{mean:>13}s{quantile(0.50, V, mean):>8.1f}{quantile(0.95, V, mean):>8.1f}{quantile(0.99, V, mean):>8.1f}")

# ---------------------------------------------------------------
# 4. Queue sizing (Little's law) + memory bounds
# ---------------------------------------------------------------
print("\n=== 4. Mix queue sizing (Little's law, 4 KB cells) ===")
CELL = 4096
print(f"{'cells/s':>9}{'mean delay':>12}{'steady E[Q]':>13}{'Q_max (4x)':>12}{'RAM@Q_max':>12}")
for rate in (100, 500, 1280):
    for mean in (0.5, 1.0, 2.0):
        eq = rate * mean
        qmax = 4 * eq
        print(f"{rate:>9}{mean:>11}s{eq:>13.0f}{qmax:>12.0f}{qmax * CELL / M:>11.0f}MB")

# ---------------------------------------------------------------
# 5. Cover-traffic volume per rate class (illustrative rates)
# ---------------------------------------------------------------
print("\n=== 5. Cover volume, 24/7 at class rate (illustrative bitrates) ===")
print(f"{'rate':>12}{'GB/month':>10}{'cells/s (4KB)':>15}")
for kbit in (64, 256, 1024, 4096):
    gbm = kbit * 1e3 / 8 * 86400 * 30 / 1e9
    cps = kbit * 1e3 / 8 / CELL
    print(f"{kbit:>10}kb{gbm:>10.1f}{cps:>15.1f}")

# ---------------------------------------------------------------
# 6. Mix CPU cost of ML-KEM decapsulation
# ---------------------------------------------------------------
print("\n=== 6. Mix CPU budget: ML-KEM-768 decap ~= 30 us/cell (modern x86) ===")
for rate in (500, 1280, 5000):
    print(f"{rate:>6} cells/s -> {rate * 30e-6 * 100:>5.1f}% of one core")

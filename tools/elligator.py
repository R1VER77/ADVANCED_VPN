"""Elligator 2 for X25519 public keys: a key that looks like 32 uniform random bytes.

Plain Curve25519 public keys are recognisable: about half of all 32-byte strings are not
valid points, and an observer can test which half a string is in. Elligator 2 maps field
elements onto the curve; its inverse gives, for about half of all points, a
"representative" that is indistinguishable from random. padbook.py uses it so that a sealed
contribution has no recognisable structure at all (the design obfs4 uses for its handshake).

Two details make the representatives uniform:
- "Dirty" keys (as in Monocypher): the ephemeral public key is d*B + t*L, where L has
  order 8 and t is random. Representatives of prime-order points alone are distinguishable
  (map back, multiply by the group order, see the identity). The recipient's clamped scalar
  is a multiple of 8, so t*L drops out of the shared secret.
- Either square root, and a random top bit: a representative is below 2^255 - 19, so its
  top bit would otherwise always be zero.

Field and Edwards arithmetic follow RFC 8032's reference code; the forward map is RFC 9380's
map_to_curve_elligator2 with Z = 2 (checked against its curve25519 test vectors). Pure
Python: slow (milliseconds per key) and not constant-time, which is acceptable for a
once-per-book ephemeral that never touches a long-term secret.
"""

import secrets

P = 2**255 - 19
A = 486662  # Curve25519: v^2 = u^3 + A u^2 + u
Z = 2  # Elligator 2 non-square (RFC 9380 for curve25519)
L_ORDER = 2**252 + 27742317777372353535851937790883648493  # prime subgroup order
D = -121665 * pow(121666, P - 2, P) % P  # Edwards25519: -x^2 + y^2 = 1 + d x^2 y^2
SQRT_M1 = pow(2, (P - 1) // 4, P)


def inv(x):
    """x^-1 mod p (inv(0) = 0, as RFC 9380's inv0)."""
    return pow(x, P - 2, P)


def is_square(x):
    """True for 0 and the quadratic residues mod p."""
    return x % P == 0 or pow(x, (P - 1) // 2, P) == 1


def sqrt(x):
    """A square root of x mod p (p = 5 mod 8), or None if x is not a square."""
    x %= P
    r = pow(x, (P + 3) // 8, P)
    if r * r % P != x:
        r = r * SQRT_M1 % P
    return r if r * r % P == x else None


def map_to_curve(r):
    """RFC 9380 map_to_curve_elligator2 for Curve25519 (K = 1): field element -> u."""
    x1 = -A * inv(1 + Z * r * r) % P
    if x1 == 0:
        x1 = -A % P
    gx1 = (x1**3 + A * x1 * x1 + x1) % P
    return x1 if is_square(gx1) else (-x1 - A) % P


def representative(u):
    """32 random-looking bytes that map back to u, or None if u has no representative.

    r^2 = -(u + A) / (2u) makes map_to_curve take its first branch to u, since u is on the
    curve. It exists when -2u(u + A) is a square: about half of all points."""
    u %= P
    if u == 0 or (u + A) % P == 0 or not is_square(-2 * u * (u + A)):
        return None
    r = sqrt(-(u + A) * inv(2 * u))
    if r is None:
        return None
    if secrets.randbits(1):
        r = P - r
    return (r | (secrets.randbits(1) << 255)).to_bytes(32, "little")


def from_representative(rep):
    """u for a representative (its top bit is ignored)."""
    r = int.from_bytes(rep, "little") & ((1 << 255) - 1)
    return map_to_curve(r % P)


# --- Edwards25519 (RFC 8032 reference formulas), for the dirty key -------------------------
def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, pt):
    q = (0, 1, 1, 0)  # identity
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _is_identity(pt):
    return pt[0] % P == 0 and (pt[1] - pt[2]) % P == 0


def _recover_x(y):
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    return sqrt(x2)


def _from_y(y):
    x = _recover_x(y)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


_BY = 4 * inv(5) % P
_BX = _recover_x(_BY)
_BX = _BX if _BX % 2 == 0 else P - _BX
BASE = (_BX, _BY, 1, _BX * _BY % P)


def to_montgomery_u(pt):
    """u = (1 + y) / (1 - y) of an Edwards point."""
    y = pt[1] * inv(pt[2]) % P
    return (1 + y) * inv(1 - y) % P


def _order8_point():
    """A point of exact order 8: l * Q kills Q's prime-order part; keep one of order 8."""
    r = 2
    while True:
        u = map_to_curve(r)
        y = (u - 1) * inv(u + 1) % P
        q = _from_y(y)
        if q is not None:
            t = _mul(L_ORDER, q)
            if not _is_identity(_mul(4, t)):
                return t
        r += 1


LOW_ORDER = _order8_point()


def clamp(sk):
    """X25519 scalar clamping (RFC 7748)."""
    k = bytearray(sk)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def dirty_public(sk, t):
    """u of clamp(sk)*B + t*L, with L of order 8 and t in [0, 8)."""
    return to_montgomery_u(_add(_mul(clamp(sk), BASE), _mul(t, LOW_ORDER)))


def ephemeral():
    """(sk, u, representative) for a fresh dirty X25519 key that has a representative."""
    while True:
        sk = secrets.token_bytes(32)
        u = dirty_public(sk, secrets.randbelow(8))
        rep = representative(u)
        if rep is not None:
            return sk, u, rep

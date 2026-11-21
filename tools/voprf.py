#!/usr/bin/env python3
"""The ristretto255 prime-order group and the RFC 9497 VOPRF, in pure Python.

The Rust data plane refuses public-pool token spends until a reviewed,
constant-time VOPRF crate is vendored (src/mesh/tokens.rs, fail-closed).
This module is the control-plane half of that step: a complete, standard-
library-only implementation of the ciphersuite the Rust side names
(ristretto255-SHA512), verified against the RFC's own test vectors, so the
public mesh pool's credits can move off blind RSA (which a quantum adversary
forges) onto the Privacy-Pass primitive family the design calls for.

Everything here follows the specifications exactly:

* field arithmetic, Edwards curve25519 points and the ristretto255
  encode/decode/equals/element-derivation functions: RFC 9496 sections
  4.1-4.3 (constants verbatim in section 4.1);
* expand_message_xmd with SHA-512: RFC 9380 section 5.3.1;
* hash_to_ristretto255 (64 uniform bytes -> MAP -> P1 + P2): RFC 9380
  Appendix B and RFC 9496 section 4.3.4;
* the OPRF/VOPRF protocol (DeriveKeyPair, Blind, BlindEvaluate, Finalize,
  GenerateProof, VerifyProof, ComputeComposites and batch variants):
  RFC 9497 sections 3-4 and 2.2.

Constant-time it is not: scalar multiplication is a plain ladder and field
arithmetic uses Python ints. That is acceptable for the control plane
(issuance and verification run on the operator's machine, on blinded values),
and the header of src/mesh/tokens.rs remains the authority on what the data
plane accepts. RFC 9497's test vectors in tools/test_voprf.py are the proof
this implementation is the specified function, not an approximation.
"""

from __future__ import annotations

import hashlib
import secrets

# ------------------------------------------------------------------ field

P = 2**255 - 19  # the field prime
L = 2**252 + 27742317777372353535851937790883648493  # the group order

# RFC 9496 section 4.1 implementation constants (verbatim).
D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952

# The Edwards25519 base point (RFC 8032 section 5.1): B = (x, 4/5, 1, x*4/5),
# with x the positive root of the curve equation at y = 4/5.
_B_Y = 4 * pow(5, P - 2, P) % P
_B_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
GENERATOR = (_B_X, _B_Y, 1, _B_X * _B_Y % P)
IDENTITY = (0, 1, 1, 0)


def _is_negative(x: int) -> bool:
    """Field elements are negative iff their integer encoding is odd."""
    return bool(x & 1)


def sqrt_ratio_m1(u: int, v: int) -> tuple[bool, int]:
    """RFC 9496 section 4.2: (was_square, r) with r the nonnegative sqrt
    of u/v (times SQRT_M1 when the ratio is non-square)."""
    u %= P
    v %= P
    r = u * v**3 % P * pow(u * v**7 % P, (P - 5) // 8, P) % P
    check = v * r * r % P
    correct_sign_sqrt = check == u
    flipped_sign_sqrt = check == (-u) % P
    flipped_sign_sqrt_i = check == (-u * SQRT_M1) % P
    if flipped_sign_sqrt or flipped_sign_sqrt_i:
        r = SQRT_M1 * r % P
    if _is_negative(r):
        r = P - r
    return (correct_sign_sqrt or flipped_sign_sqrt), r


# ------------------------------------------------------------- points


def add(p1, p2):
    """Edwards addition in extended coordinates (RFC 7748 section 4)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * D % P * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def scalar_mult(k: int, point):
    """A plain double-and-add ladder; not constant time (module docstring)."""
    k %= L
    acc = IDENTITY
    while k:
        if k & 1:
            acc = add(acc, point)
        point = add(point, point)
        k >>= 1
    return acc


def scalar_mult_gen(k: int):
    """k times the group generator."""
    return scalar_mult(k, GENERATOR)


def equals(p1, p2) -> bool:
    """RFC 9496 section 4.3.3."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    return (x1 * y2 % P == y1 * x2 % P) or (y1 * y2 % P == x1 * x2 % P)


# ----------------------------------------------------- encode / decode


def encode(point) -> bytes:
    """RFC 9496 section 4.3.2."""
    x0, y0, z0, t0 = point
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 * u2 % P)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    rotate = _is_negative(t0 * z_inv % P)
    x = y0 * SQRT_M1 % P if rotate else x0
    y = x0 * SQRT_M1 % P if rotate else y0
    den_inv = den1 * INVSQRT_A_MINUS_D % P if rotate else den2
    if _is_negative(x * z_inv % P):
        y = P - y
    s = den_inv * (z0 - y) % P
    if _is_negative(s):
        s = P - s
    return s.to_bytes(32, "little")


def decode(buf: bytes):
    """RFC 9496 section 4.3.1; raises ValueError on any invalid encoding."""
    if len(buf) != 32:
        raise ValueError("an element encoding is 32 bytes")
    s = int.from_bytes(buf, "little")
    if s >= P:
        raise ValueError("non-canonical field encoding")
    if _is_negative(s):
        raise ValueError("negative field element")
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-D * u1 * u1 - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr % P)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = 2 * s * den_x % P
    if _is_negative(x):
        x = P - x
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or _is_negative(t) or y == 0:
        raise ValueError("not a valid ristretto255 encoding")
    return (x, y, 1, t)


def element_derivation(b: bytes):
    """RFC 9496 section 4.3.4: MAP on each 32-byte half, then add."""
    if len(b) != 64:
        raise ValueError("element derivation takes 64 bytes")
    return add(_map(b[:32]), _map(b[32:]))


def _map(b32: bytes):
    t = int.from_bytes(b32[:31] + bytes([b32[31] & 0x7F]), "little") % P
    r = SQRT_M1 * t * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) % P * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    s_prime = s * t % P
    if _is_negative(s_prime):
        s_prime = P - s_prime
    s_prime = -s_prime % P
    s = s if was_square else s_prime
    c = (-1) % P if was_square else r
    n = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s * v % P
    w1 = n * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


# ------------------------------------------------ hashing (RFC 9380)


def expand_message_xmd(msg: bytes, dst: bytes, length: int) -> bytes:
    """RFC 9380 section 5.3.1 with SHA-512 (block 128 bytes, 64-byte digest)."""
    if length > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd input out of bounds")
    ell = (length + 63) // 64
    if ell > 255:
        raise ValueError("expand_message_xmd asked for too much output")
    dst_prime = dst + bytes([len(dst)])
    msg_prime = bytes(128) + msg + length.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = hashlib.sha512(msg_prime).digest()
    out = hashlib.sha512(b0 + b"\x01" + dst_prime).digest()
    prev = out
    for i in range(2, ell + 1):
        prev = hashlib.sha512(bytes(a ^ b for a, b in zip(b0, prev, strict=True)) + bytes([i]) + dst_prime).digest()
        out += prev
    return out[:length]


def hash_to_group(msg: bytes, dst: bytes):
    """hash_to_ristretto255 (RFC 9380 Appendix B)."""
    return element_derivation(expand_message_xmd(msg, dst, 64))


def hash_to_scalar(msg: bytes, dst: bytes) -> int:
    """64 uniform bytes -> little-endian 512-bit integer -> mod L."""
    return int.from_bytes(expand_message_xmd(msg, dst, 64), "little") % L


# ------------------------------------------------- the OPRF/VOPRF suites

IDENTIFIER = b"ristretto255-SHA512"
MODE_OPRF = 0x00
MODE_VOPRF = 0x01


def _context_string(mode: int) -> bytes:
    return b"OPRFV1-" + bytes([mode]) + b"-" + IDENTIFIER


def _i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _hash_transcript(parts, trailer: bytes) -> bytes:
    """len-prefixed concatenation of `parts`, then the raw trailer string
    ("Challenge" / "Composite" / "Finalize" are NOT length-prefixed)."""
    out = b""
    for part in parts:
        out += _i2osp(len(part), 2) + part
    return out + trailer


def derive_key_pair(seed: bytes, info: bytes, mode: int) -> tuple[int, bytes]:
    """RFC 9497 section 3.2.1: (skS, pkS-encoded) from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("the seed is 32 bytes")
    ctx = _context_string(mode)
    derive_input = seed + _i2osp(len(info), 2) + info
    dst = b"DeriveKeyPair" + ctx
    counter = 0
    sk = 0
    while sk == 0:
        if counter > 255:
            raise ValueError("DeriveKeyPair exhausted its counter")
        sk = hash_to_scalar(derive_input + bytes([counter]), dst)
        counter += 1
    return sk, encode(scalar_mult_gen(sk))


def random_scalar() -> int:
    """A uniform scalar (64 random bytes -> LE -> mod L, RFC 9496 section 4.4)."""
    return int.from_bytes(secrets.token_bytes(64), "little") % L


# ------------------------------------------------------------ protocol


class Server:
    """The evaluation half: holds skS, produces (evaluation, proof)."""

    def __init__(self, sk: int, mode: int = MODE_VOPRF):
        self.ctx = _context_string(mode)
        self.mode = mode
        self.sk = sk % L
        self.pk = scalar_mult_gen(self.sk)

    @classmethod
    def from_seed(cls, seed: bytes, info: bytes, mode: int = MODE_VOPRF):
        """A server whose key is derived from `seed` (RFC 9497 DeriveKeyPair)."""
        sk, _ = derive_key_pair(seed, info, mode)
        return cls(sk, mode)

    def _hash_to_scalar(self, msg: bytes) -> int:
        return hash_to_scalar(msg, b"HashToScalar-" + self.ctx)

    def _hash_to_group(self, msg: bytes):
        return hash_to_group(msg, b"HashToGroup-" + self.ctx)

    def evaluate_direct(self, msg: bytes) -> bytes:
        """RFC 9497 Evaluate: the PRF output without the protocol (for the issuer)."""
        return hashlib.sha512(
            _i2osp(len(msg), 2)
            + msg
            + _i2osp(len(self.evaluate_element(msg)), 2)
            + self.evaluate_element(msg)
            + b"Finalize"
        ).digest()

    def evaluate_element(self, msg: bytes) -> bytes:
        """The issued element alone (encoded sk*H(msg)), for redemption
        by re-derivation in private-token style protocols."""
        element = self._hash_to_group(msg)
        if equals(element, IDENTITY):
            raise ValueError("input maps to the identity")
        return encode(scalar_mult(self.sk, element))

    def blind_evaluate(self, blinded_encoded: bytes, proof_scalar: int | None = None):
        """RFC 9497 BlindEvaluate. OPRF mode returns the evaluation alone;
        VOPRF mode also returns the (optionally batched) DLEQ proof."""
        blinded = decode(blinded_encoded)
        evaluated = scalar_mult(self.sk, blinded)
        if self.mode == MODE_OPRF:
            return encode(evaluated), None
        if proof_scalar is None:
            proof_scalar = random_scalar()
        proof = self._generate_proof(self.sk, GENERATOR, self.pk, [blinded], [evaluated], proof_scalar)
        return encode(evaluated), proof

    def blind_evaluate_batch(self, blinded_encoded: list[bytes], proof_scalar: int | None = None):
        """The batched form: one proof for the whole list."""
        blinded = [decode(b) for b in blinded_encoded]
        evaluated = [scalar_mult(self.sk, b) for b in blinded]
        if proof_scalar is None:
            proof_scalar = random_scalar()
        proof = self._generate_proof(self.sk, GENERATOR, self.pk, blinded, evaluated, proof_scalar)
        return [encode(e) for e in evaluated], proof

    # ---- DLEQ proofs (RFC 9497 section 2.2)

    def _compute_composites_fast(self, k, b_point, c_list, d_list):
        bm = encode(b_point)
        seed = hashlib.sha512(
            _i2osp(len(bm), 2) + bm + _i2osp(len(b"Seed-" + self.ctx), 2) + b"Seed-" + self.ctx
        ).digest()
        m = IDENTITY
        for i, (c, d_) in enumerate(zip(c_list, d_list, strict=True)):
            ci, di = encode(c), encode(d_)
            composite = (
                _i2osp(len(seed), 2)
                + seed
                + _i2osp(i, 2)
                + _i2osp(len(ci), 2)
                + ci
                + _i2osp(len(di), 2)
                + di
                + b"Composite"
            )
            m = add(scalar_mult(self._hash_to_scalar(composite), c), m)
        return m, scalar_mult(k, m)

    def _generate_proof(self, k, a, b_point, c_list, d_list, r):
        m, z = self._compute_composites_fast(k, b_point, c_list, d_list)
        t2 = scalar_mult(r, a)
        t3 = scalar_mult(r, m)
        transcript = _hash_transcript([encode(b_point), encode(m), encode(z), encode(t2), encode(t3)], b"Challenge")
        c = self._hash_to_scalar(transcript)
        s = (r - c * k) % L
        return c, s


class Client:
    """The requester half: blinds inputs, verifies proofs, finalizes."""

    def __init__(self, pk_encoded: bytes | None, mode: int = MODE_VOPRF):
        self.ctx = _context_string(mode)
        self.mode = mode
        # The OPRF mode has no server public key (no proof to verify).
        self.pk = decode(pk_encoded) if pk_encoded else None

    def _hash_to_scalar(self, msg: bytes) -> int:
        return hash_to_scalar(msg, b"HashToScalar-" + self.ctx)

    def _hash_to_group(self, msg: bytes):
        return hash_to_group(msg, b"HashToGroup-" + self.ctx)

    def blind(self, msg: bytes, blind_scalar: int | None = None):
        """RFC 9497 Blind: (blind, blindedElement-encoded)."""
        if blind_scalar is None:
            blind_scalar = random_scalar()
        element = self._hash_to_group(msg)
        if equals(element, IDENTITY):
            raise ValueError("input maps to the identity")
        blinded = scalar_mult(blind_scalar, element)
        return blind_scalar, encode(blinded)

    def verify_proof(self, a, b_point, c_list, d_list, proof) -> bool:
        """RFC 9497 section 2.2.2 VerifyProof with public composites."""
        c, s = proof
        m, z = self._compute_composites(b_point, c_list, d_list)
        t2 = add(scalar_mult(s, a), scalar_mult(c, b_point))
        t3 = add(scalar_mult(s, m), scalar_mult(c, z))
        transcript = _hash_transcript([encode(b_point), encode(m), encode(z), encode(t2), encode(t3)], b"Challenge")
        return self._hash_to_scalar(transcript) == c

    def _compute_composites(self, b_point, c_list, d_list):
        bm = encode(b_point)
        seed = hashlib.sha512(
            _i2osp(len(bm), 2) + bm + _i2osp(len(b"Seed-" + self.ctx), 2) + b"Seed-" + self.ctx
        ).digest()
        m = IDENTITY
        z = IDENTITY
        for i, (c, d_) in enumerate(zip(c_list, d_list, strict=True)):
            ci, di = encode(c), encode(d_)
            composite = (
                _i2osp(len(seed), 2)
                + seed
                + _i2osp(i, 2)
                + _i2osp(len(ci), 2)
                + ci
                + _i2osp(len(di), 2)
                + di
                + b"Composite"
            )
            m = add(scalar_mult(self._hash_to_scalar(composite), c), m)
            z = add(scalar_mult(self._hash_to_scalar(composite), d_), z)
        return m, z

    def finalize(self, msg: bytes, blind: int, evaluated_encoded: bytes, blinded_encoded: bytes, proof=None) -> bytes:
        """RFC 9497 Finalize: proof check (VOPRF), unblind, hash to output."""
        evaluated = decode(evaluated_encoded)
        blinded = decode(blinded_encoded)
        if self.mode == MODE_VOPRF:
            if proof is None:
                raise ValueError("VOPRF mode requires the proof")
            if not self.verify_proof(GENERATOR, self.pk, [blinded], [evaluated], proof):
                raise ValueError("proof verification failed")
        unblinded = scalar_mult(pow(blind, -1, L), evaluated)
        element = encode(unblinded)
        return hashlib.sha512(_i2osp(len(msg), 2) + msg + _i2osp(len(element), 2) + element + b"Finalize").digest()

    def finalize_batch(
        self, msgs: list[bytes], blinds: list[int], evaluated_encoded: list[bytes], blinded_encoded: list[bytes], proof
    ) -> list[bytes]:
        """Batch finalization with one proof over every pair."""
        blinded = [decode(b) for b in blinded_encoded]
        evaluated = [decode(b) for b in evaluated_encoded]
        if not self.verify_proof(GENERATOR, self.pk, blinded, evaluated, proof):
            raise ValueError("batch proof verification failed")
        out = []
        for msg, blind, ev in zip(msgs, blinds, evaluated, strict=True):
            element = encode(scalar_mult(pow(blind, -1, L), ev))
            out.append(
                hashlib.sha512(_i2osp(len(msg), 2) + msg + _i2osp(len(element), 2) + element + b"Finalize").digest()
            )
        return out


def run(server: Server, client: Client, msg: bytes, blind_scalar: int | None = None):
    """A full one-message-each-way protocol run, returning the PRF output."""
    blind, blinded = client.blind(msg, blind_scalar)
    evaluated, proof = server.blind_evaluate(blinded)
    return client.finalize(msg, blind, evaluated, blinded, proof)

#!/usr/bin/env python3
"""Generate cross-language verification vectors for avpn-pq-sphinx.

Every value is computed by an independent Python implementation:
  - hashlib / hmac          : SHA-256, HMAC, SHA-3, SHAKE
  - blake3 package          : BLAKE3 (unkeyed + keyed)
  - cryptography 44.x       : X25519, ChaCha20-Poly1305
  - pure big-int Poly1305   : direct RFC 8439 spec transcription
  - kyber-py (FIPS 203)     : ML-KEM-768 — itself validated against the
                              official NIST KATs, so agreement transitively
                              validates the Rust wire format.

Output: vectors.txt, one record per line:  name|field|hex
The Rust integration test (tests/vectors.rs) parses and asserts equality.
"""

import hashlib
import hmac as hmac_mod
import os

import blake3 as blake3_mod
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from kyber_py.ml_kem import ML_KEM_768

OUT = []


def rec(name, field, data: bytes):
    OUT.append(f"{name}|{field}|{data.hex()}")


def det_bytes(seed: int, n: int) -> bytes:
    """Deterministic bytes (splitmix64) — mirrors the Rust DetRng byte stream
    is NOT needed here; any fixed bytes work for cross-checks."""
    return bytes((seed * 31 + i * 17 + 3) & 0xFF for i in range(n))


# --- SHA-256 / HMAC / HKDF -------------------------------------------------
for i, data in enumerate([b"", b"abc", det_bytes(1, 55), det_bytes(2, 64), det_bytes(3, 1000)]):
    rec(f"sha256_{i}", "data", data)
    rec(f"sha256_{i}", "digest", hashlib.sha256(data).digest())

for i, (key, msg) in enumerate([
    (b"\x0b" * 20, b"Hi There"),
    (b"Jefe", b"what do ya want for nothing?"),
    (det_bytes(4, 131), det_bytes(5, 500)),
]):
    rec(f"hmac_{i}", "key", key)
    rec(f"hmac_{i}", "msg", msg)
    rec(f"hmac_{i}", "digest", hmac_mod.new(key, msg, hashlib.sha256).digest())


def hkdf_sha256(salt, ikm, info, length):
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


for i, (salt, ikm, info, ln) in enumerate([
    (bytes(range(13)), b"\x0b" * 22, bytes(range(0xF0, 0xFA)), 42),
    (b"salt", b"ikm", b"info", 100),
    (b"", det_bytes(6, 80), b"", 64),
]):
    rec(f"hkdf_{i}", "salt", salt)
    rec(f"hkdf_{i}", "ikm", ikm)
    rec(f"hkdf_{i}", "info", info)
    rec(f"hkdf_{i}", "len", bytes([ln]))
    rec(f"hkdf_{i}", "okm", hkdf_sha256(salt, ikm, info, ln))

# --- SHA-3 / SHAKE -----------------------------------------------------------
for i, data in enumerate([b"", b"abc", det_bytes(7, 200), det_bytes(8, 1000)]):
    rec(f"sha3_256_{i}", "data", data)
    rec(f"sha3_256_{i}", "digest", hashlib.sha3_256(data).digest())
    rec(f"sha3_512_{i}", "data", data)
    rec(f"sha3_512_{i}", "digest", hashlib.sha3_512(data).digest())
    rec(f"shake128_{i}", "data", data)
    rec(f"shake128_{i}", "digest", hashlib.shake_128(data).digest(64))
    rec(f"shake256_{i}", "data", data)
    rec(f"shake256_{i}", "digest", hashlib.shake_256(data).digest(200))

# --- BLAKE3 ------------------------------------------------------------------
for ln in [0, 1, 2, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 4097, 5000]:
    data = det_bytes(9, ln)
    rec(f"blake3_{ln}", "hash", blake3_mod.blake3(data).digest())
    key = det_bytes(10, 32)
    rec(f"blake3k_{ln}", "hash", blake3_mod.blake3(data, key=key).digest())
    rec(f"blake3k_{ln}", "key", key)
    rec(f"blake3k_{ln}", "data", data)

# --- X25519 ------------------------------------------------------------------
for i in range(6):
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    a_raw = a.private_bytes_raw()
    b_raw = b.private_bytes_raw()
    a_pub = a.public_key().public_bytes_raw()
    b_pub = b.public_key().public_bytes_raw()
    ss = a.exchange(b.public_key())
    rec(f"x25519_{i}", "ask", a_raw)
    rec(f"x25519_{i}", "bpub", b_pub)
    rec(f"x25519_{i}", "ss", ss)
    rec(f"x25519_{i}", "apub", a_pub)
    rec(f"x25519_{i}", "bsk", b_raw)

# --- Poly1305 (pure big-int, direct spec transcription) ----------------------
def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little")
    s = int.from_bytes(key[16:], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    p = (1 << 130) - 5
    acc = 0
    for j in range(0, len(msg), 16):
        blk = msg[j : j + 16]
        n = int.from_bytes(blk + b"\x01", "little")
        acc = (acc + n) * r % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


for i, (key, msg) in enumerate([
    (bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"), b"Cryptographic Forum Research Group"),
    (det_bytes(11, 32), b""),
    (det_bytes(12, 32), det_bytes(13, 100)),
    (det_bytes(14, 32), det_bytes(15, 16)),
]):
    rec(f"poly1305_{i}", "key", key)
    rec(f"poly1305_{i}", "msg", msg)
    rec(f"poly1305_{i}", "tag", poly1305(key, msg))

# --- ChaCha20-Poly1305 --------------------------------------------------------
for i, (key, nonce, aad, pt) in enumerate([
    (det_bytes(16, 32), det_bytes(17, 12), b"", b""),
    (det_bytes(18, 32), det_bytes(19, 12), b"aad", b"secret payload"),
    (det_bytes(20, 32), det_bytes(21, 12), det_bytes(22, 50), det_bytes(23, 2000)),
]):
    aead = ChaCha20Poly1305(key)
    sealed = aead.encrypt(nonce, pt, aad)
    rec(f"aead_{i}", "key", key)
    rec(f"aead_{i}", "nonce", nonce)
    rec(f"aead_{i}", "aad", aad)
    rec(f"aead_{i}", "pt", pt)
    rec(f"aead_{i}", "sealed", sealed)

# --- ML-KEM-768 (kyber-py, FIPS 203 final) ------------------------------------
kem = ML_KEM_768
for i in range(4):
    d = det_bytes(30 + 2 * i, 32)
    z = det_bytes(31 + 2 * i, 32)
    ek, dk = kem.key_derive(d + z)
    rec(f"mlkem_{i}", "d", d)
    rec(f"mlkem_{i}", "z", z)
    rec(f"mlkem_{i}", "ek", ek)
    rec(f"mlkem_{i}", "dk", dk)
    m = det_bytes(40 + i, 32)
    K, c = kem._encaps_internal(ek, m)
    rec(f"mlkem_{i}", "m", m)
    rec(f"mlkem_{i}", "K", K)
    rec(f"mlkem_{i}", "c", c)
    K2 = kem.decaps(dk, c)
    assert K2 == K
    # tampered ciphertext -> implicit rejection
    bad = bytearray(c)
    bad[17] ^= 0x40
    rec(f"mlkem_{i}", "Kbad", kem.decaps(dk, bytes(bad)))

with open(os.path.join(os.path.dirname(__file__), "vectors.txt"), "w") as f:
    f.write("\n".join(OUT) + "\n")

print(f"wrote {len(OUT)} records to vectors.txt")

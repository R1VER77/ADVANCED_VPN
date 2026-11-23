#!/usr/bin/env python3
"""DC-net pads (docs/DCNET_CONTROL_DESIGN.md §2): one-time pad books for pairs who met in
person, forward-secure chains for pairs who cannot meet.

Each member's contribution is kernel output (os.urandom: getrandom(2)) XOR Nitrokey output, drawn
before any noise is recorded, XOR, for a book, the extracted output of an assessed raw
noise source (`assess`, then `make --raw`): raw CPU timing jitter from
jitterentropy's recorder, health-tested (SP 800-90B 4.4) and Toeplitz-extracted under conditional
entropy/seed assumptions, counting half of the empirical min-entropy estimate. The
Nitrokey alone is not enough for an information-theoretic claim: its `rng` command
returns a ChaCha8 stream seeded once per boot (firmware source, Trussed). A pair's book
is the XOR of both contributions; uniformity and secrecy require an appropriate
independence or conditional-source assumption as well as a good contribution. A chain's
32-byte seed is made the same way and then moves one way each round (src/dcnet.rs
Ratchet); it is always computational.

Each contribution travels sealed to the partner's hybrid ML-KEM-768 + X25519 key
(tools/keyguard.py kem_seal), bound to its delivery label and raw-source record:
`in_person` (removable media, never on a network) or `remote` (as strong as the hybrid
KEM). The software reports conditional-information-theoretic for declared in-person
raw-source provenance; this does not certify the physical assumptions. Otherwise it
reports computational.

Nothing is in the clear, at rest or in transit (after TrueCrypt's volume header: a random
salt, then everything encrypted). book.bin is a random salt, a nonce and the encrypted
header, contributions and chain state, under keys derived from the Nitrokey's FIDO2
hmac-secret (keyguard.hardware_secret: PIN + touch, once per session) and that salt.
pads.bin holds every round's 64-byte pad as its own record under a per-round key from a
one-way chain (chain[k+1] = HKDF(chain[k], "next")), filled with random records up to a
30-day bucket. Records and book.bin are a cascade: ChaCha20-Poly1305 over AES-256-GCM,
separate keys. An envelope is an Elligator 2 representative of a dirty X25519 ephemeral,
an ML-KEM-768 ciphertext and AES-256-GCM over the padded header and contribution: random
bytes to anyone without the recipient's key. Taking a round
advances the chain first and then zeroes the used records before successful return.
The current state no longer opens used rounds through this API; snapshots, flash
remnants and hostile hosts remain outside that guarantee. Rounds follow the clock
(round = unix time // 30): a round already past is refused, so restoring an old state
is refused through this API with a trustworthy clock. Whole snapshots, hostile
clocks and flash remnants are not defeated. A used-up book stops; nothing falls back to derived pads.

Run with --help for the commands. Never a software random source alone: without a
Nitrokey, `make` refuses; without `--raw`, the contribution is labelled computational.
"""

import argparse
import contextlib
import atexit
import ctypes
import hashlib
import json
import math
import os
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time
import weakref
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyguard  # noqa: E402


# --- Keep key material in RAM as briefly as possible, and scrub it on the way out ----------
# Python cannot encrypt its whole address space the way VeraCrypt's driver does, nor wipe the
# immutable copies CPython makes (hex(), json, bytes slices). So this is a reduction, not a
# guarantee: hold secrets in a mutable buffer we CAN zero, wipe them the moment we are done,
# and scrub every live one on exit or a signal (Tails wipes RAM on shutdown). The real
# zeroization guarantee is in the Rust data plane (src/dcnet.rs, PadBook/Ratchet).
_LIVE = weakref.WeakSet()


class Secret:
    """Key bytes in a mutable buffer that `wipe()` zeroes in place."""

    def __init__(self, data):
        self._buf = bytearray(data)
        _LIVE.add(self)

    @property
    def bytes(self):
        """A copy of the key bytes (a short-lived copy CPython will not let us wipe)."""
        if self._buf is None:
            raise ValueError("secret already wiped")
        return bytes(self._buf)

    def wipe(self):
        """Overwrite the buffer with zeros (memset, so the compiler cannot elide it)."""
        if self._buf is None:
            return
        n = len(self._buf)
        if n:
            ctypes.memset((ctypes.c_char * n).from_buffer(self._buf), 0, n)
        self._buf = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.wipe()


def _memzero(buf):
    """Zero a bytearray in place (memset, not elidable)."""
    n = len(buf)
    if n:
        ctypes.memset((ctypes.c_char * n).from_buffer(buf), 0, n)


def _wipe_all(*_):
    for s in list(_LIVE):
        s.wipe()


def _install_wipe_on_exit():
    """Scrub live secrets at normal exit and on a terminating signal (chaining the handler)."""
    atexit.register(_wipe_all)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        prev = signal.getsignal(sig)

        def handler(signum, frame, _prev=prev):
            _wipe_all()
            if callable(_prev):
                _prev(signum, frame)
            else:
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)

        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass  # not the main thread, or an unsupported signal


PAD = 64  # bytes per round per pair (src/dcnet.rs BODY_LEN)
ROUND_SECS = 30  # src/dcnet.rs ROUND_SECS
ROUNDS_PER_DAY = 86400 // ROUND_SECS
DELIVERIES = ("in_person", "remote")
NITROKEY_CHUNK = 4096  # bytes per `nitropy nk3 rng` call
# Health tests on the Nitrokey's output, in the spirit of NIST SP 800-90B 4.4 (bytes,
# assessed min-entropy taken as 4 bits per byte to keep false alarms negligible while
# still catching a stuck or badly biased source):
REPEAT_CUTOFF = 6  # no byte value repeated 6 times in a row (P ~ 2^-40 for a sound source)
WINDOW = 512  # adaptive proportion: in each 512-byte window, the first value appears
PROPORTION_CUTOFF = 13  # at most 13 times (expected 2)


class HealthError(RuntimeError):
    """The hardware random source failed a health test: no book is made from it."""


def round_now(now=None):
    """The current round number (rounds follow the clock)."""
    return int((time.time() if now is None else now) // ROUND_SECS)


def health_check(chunk, previous=None):
    """Refuse a stuck or biased chunk: repetition count, adaptive proportion, repeat chunk."""
    if previous is not None and chunk == previous:
        raise HealthError("the source repeated a whole chunk")
    run, last = 0, None
    for b in chunk:
        run = run + 1 if b == last else 1
        last = b
        if run >= REPEAT_CUTOFF:
            raise HealthError("repetition count test failed")
    for start in range(0, len(chunk) - WINDOW + 1, WINDOW):
        window = chunk[start : start + WINDOW]
        if window.count(window[0]) > PROPORTION_CUTOFF:
            raise HealthError("adaptive proportion test failed")


def nitropy_path(explicit=None):
    """`nitropy`, as an absolute path to a file nobody else can replace."""
    p = Path(explicit or shutil.which("nitropy") or "")
    if not p.is_absolute() or not p.is_file():
        raise RuntimeError("nitropy not found: a Nitrokey 3 and nitropy are required (no software fallback)")
    m = p.stat()
    if m.st_uid not in (0, os.geteuid()) or m.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("nitropy is writable by others: refused")
    return p


def nitrokey_bytes(n, nitropy=None, run=subprocess.run):
    """`n` bytes from the Nitrokey 3's random number generator, health-tested per chunk."""
    exe = nitropy_path(nitropy) if run is subprocess.run else Path(nitropy or "nitropy")
    out, previous = bytearray(), None
    while len(out) < n:
        want = min(NITROKEY_CHUNK, n - len(out))
        r = run([str(exe), "nk3", "rng", "--length", str(want)], capture_output=True, text=True, check=False)
        if r.returncode != 0:
            raise RuntimeError("the Nitrokey gave no random data: " + (r.stderr or r.stdout).strip()[-200:])
        hexdigits = "".join(line.strip() for line in r.stdout.splitlines() if is_hex(line.strip()))
        chunk = bytes.fromhex(hexdigits)
        if len(chunk) != want:
            raise RuntimeError("the Nitrokey returned %d bytes, not %d" % (len(chunk), want))
        if want >= WINDOW:
            health_check(chunk, previous)
        previous = chunk
        out += chunk
    return bytes(out)


def is_hex(s):
    """True for a non-empty, even-length hex string."""
    return bool(s) and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)


# --- The raw source: CPU timing jitter (jitterentropy's raw-noise recorder) ---------------
# The Nitrokey's output is a ChaCha8 stream seeded per boot (computational). An
# information-theoretic book needs raw physical noise: here the raw time deltas of the
# jitterentropy noise source, low 8 bits per delta (as its SP 800-90B analysis uses them),
# assessed once per machine with NIST's ea_non_iid, health-tested continuously, and run
# through a Toeplitz extractor. A contribution is the extractor's output XOR the Nitrokey.
JITTER_BLOCK = 1024  # 8-bit samples per extractor block (8192 raw bits)
JITTER_CHUNK = 65536  # samples per recorder run
EPSILON_LOG2 = 64  # Target bound under independent-seed/conditional-entropy assumptions.
SAFETY = 0.5  # the extractor counts half the assessed min-entropy per sample
ALPHA_LOG2 = 20  # health-test false-alarm probability 2^-20 (SP 800-90B 4.4)
APT_WINDOW = 512  # adaptive proportion test window for non-binary samples
ASSESS_SAMPLES = 1_000_000  # ea_non_iid needs at least a million samples
ASSESS_RUNS = 3  # separate recordings; the lowest estimate counts (runs differ by ~0.5 bit)


def rct_cutoff(h):
    """SP 800-90B 4.4.1 repetition count cutoff for min-entropy `h` bits per sample."""
    return 1 + math.ceil(ALPHA_LOG2 / h)


def apt_cutoff(h, window=APT_WINDOW):
    """SP 800-90B 4.4.2 adaptive proportion cutoff: 1 + CRITBINOM(W, 2^-h, 1 - alpha)."""
    p, target, cdf = 2.0**-h, 1.0 - 2.0**-ALPHA_LOG2, 0.0
    for k in range(window + 1):
        cdf += math.comb(window, k) * p**k * (1 - p) ** (window - k)
        if cdf >= target:
            return 1 + k
    return window


def raw_health(samples, h):
    """Both SP 800-90B continuous tests over raw samples; raises HealthError on failure."""
    rct, apt = rct_cutoff(h), apt_cutoff(h)
    run, last = 0, None
    for x in samples:
        run = run + 1 if x == last else 1
        last = x
        if run >= rct:
            raise HealthError("raw source: repetition count test failed")
    for start in range(0, len(samples) - APT_WINDOW + 1, APT_WINDOW):
        window = samples[start : start + APT_WINDOW]
        if window.count(window[0]) >= apt:
            raise HealthError("raw source: adaptive proportion test failed")


def extracted_bits(h_used):
    """Output bits per JITTER_BLOCK samples: the block's min-entropy minus 2 log2(1/eps),
    rounded down to whole bytes."""
    m = int(JITTER_BLOCK * h_used) - 2 * EPSILON_LOG2
    m -= m % 8
    if m < 8:
        raise ValueError("too little entropy per sample to extract anything")
    return m


def toeplitz_seed_bits(m):
    """Seed bits a Toeplitz extractor needs for JITTER_BLOCK samples in, m bits out."""
    return 8 * JITTER_BLOCK + m - 1


def toeplitz(x, n, seed, m):
    """The m-bit Toeplitz hash of the n-bit integer `x` under integer `seed` (n + m - 1
    bits): output bit i is the parity of row i, seed bits [i, i + n), AND x."""
    if x >> n:
        raise ValueError("x has more than n bits")
    out = 0
    for i in range(m):  # x has n bits, so AND-ing with it keeps only seed bits [i, i + n)
        if ((seed >> i) & x).bit_count() & 1:
            out |= 1 << i
    return out


def extract(samples, h_used, seed):
    """Whole JITTER_BLOCK blocks of raw 8-bit samples, Toeplitz-extracted to near-uniform
    bytes. `seed` is public and fixed per machine, but must not depend on the samples."""
    m, n = extracted_bits(h_used), 8 * JITTER_BLOCK
    if len(seed) * 8 < toeplitz_seed_bits(m):
        raise ValueError("Toeplitz seed too short")
    s, out = int.from_bytes(seed, "little"), bytearray()
    for start in range(0, len(samples) - JITTER_BLOCK + 1, JITTER_BLOCK):
        x = int.from_bytes(samples[start : start + JITTER_BLOCK], "little")
        out += toeplitz(x, n, s, m).to_bytes(m // 8, "little")
    return bytes(out)


def jitter_samples(count, recorder, run=subprocess.run):
    """`count` raw 8-bit samples (low byte of each time delta) from the jitterentropy
    raw-noise recorder; its own health failures abort."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        prefix = os.path.join(d, "raw")
        r = run([str(recorder), str(count), "1", prefix], capture_output=True, text=True, check=False)
        if r.returncode != 0:
            raise RuntimeError("the jitter recorder failed: " + (r.stderr or r.stdout).strip()[-200:])
        if "health testing failure" in r.stdout:
            raise HealthError("jitter source: " + r.stdout.strip().splitlines()[-1])
        values = Path(prefix + "-0001.data").read_text().split()
    if len(values) != count:
        raise RuntimeError("the jitter recorder returned %d samples, not %d" % (len(values), count))
    return bytes(int(v) & 0xFF for v in values)


def raw_bytes(n, raw, recorder, run=subprocess.run):
    """`n` extracted bytes from the assessed raw source described by `raw` (an
    assessment record: h_assessed, h_used, seed)."""
    seed = bytes.fromhex(raw["seed"])
    out = bytearray()
    while len(out) < n:
        samples = jitter_samples(JITTER_CHUNK, recorder, run)
        raw_health(samples, raw["h_assessed"])
        out += extract(samples, raw["h_used"], seed)
    return bytes(out[:n])


def contribution_bytes(n, raw=None, recorder=None, nitropy=None, getrandom=os.urandom, nitrokey=None, rawfn=None):
    """A member's contribution: kernel output XOR Nitrokey output, XOR (when `raw` is an
    assessment record) the extracted raw jitter source. The kernel and Nitrokey bytes are
    drawn first and the jitter recorded after, which establishes ordering, not statistical independence. Uniformity requires a
    justified conditional entropy bound, independent extractor seed and independent mixing. Kernel and Nitrokey add
    defence in depth (computational: ChaCha20, ChaCha8); only the raw part can make a
    book conditionally information-theoretic under the stated source assumptions."""
    nitrokey = nitrokey or nitrokey_bytes
    rawfn = rawfn or raw_bytes
    kernel = getrandom(n)
    out = combine_any(kernel, nitrokey(n, nitropy))
    if raw is not None:
        if recorder is None:
            raise ValueError("a raw source needs its recorder")
        out = combine_any(out, rawfn(n, raw, recorder))
    return out


def parse_ea_non_iid(output):
    """The min-entropy per sample from ea_non_iid's report ('Assessed min entropy: x')."""
    for line in output.splitlines():
        if line.strip().startswith("Assessed min entropy:"):
            return float(line.split(":", 1)[1])
    raise ValueError("no 'Assessed min entropy' in the ea_non_iid output")


def assessment(h_assessed, seed, recorder, tool_output_sha256):
    """The record a raw source is used under: what was measured, what is counted, and
    the public Toeplitz seed (drawn once, from the Nitrokey, before any sample is used)."""
    if not 0 < h_assessed <= 8:
        raise ValueError("min-entropy per 8-bit sample must be in (0, 8]")
    h_used = h_assessed * SAFETY
    m = extracted_bits(h_used)
    if len(seed) * 8 < toeplitz_seed_bits(m):
        raise ValueError("Toeplitz seed too short")
    return dict(
        schema=1,
        source="jitterentropy raw time deltas, low 8 bits",
        recorder_sha256=hashlib.sha256(Path(recorder).read_bytes()).hexdigest(),
        tool="NIST SP 800-90B ea_non_iid (initial, 8 bits per symbol)",
        tool_output_sha256=tool_output_sha256,
        h_assessed=h_assessed,
        h_used=h_used,
        epsilon_log2=EPSILON_LOG2,
        seed=seed.hex(),
    )


SEED = 32  # a chain's seed contribution


def header(cell, a, b, first_round, rounds):
    """What a book is for: one cell, one pair (sorted), rounds [first, first + rounds)."""
    a, b = sorted((str(a), str(b)))
    if a == b or rounds <= 0 or first_round < 0 or not 0 <= cell < 2**32:
        raise ValueError("invalid book")
    return dict(schema=1, kind="book", cell=cell, pair=[a, b], first_round=first_round, rounds=rounds)


def chain_header(cell, a, b, first_round):
    """What a chain is for: one cell, one pair (sorted), rounds from `first_round` on."""
    a, b = sorted((str(a), str(b)))
    if a == b or first_round < 0 or not 0 <= cell < 2**32:
        raise ValueError("invalid chain")
    return dict(schema=1, kind="chain", cell=cell, pair=[a, b], first_round=first_round)


def contribution_length(h):
    """Bytes each member contributes: the whole book, or a chain's 32-byte seed."""
    return SEED if h["kind"] == "chain" else h["rounds"] * PAD


def book_id(h):
    """A book's id: a hash of its header."""
    return hashlib.sha256(json.dumps(h, sort_keys=True).encode()).hexdigest()[:32]


# --- In transit: an envelope with nothing in the clear --------------------------------------
# representative(32) || ML-KEM-768 ciphertext(1088) || nonce(12) || AES-256-GCM(body).
# The X25519 ephemeral is a dirty key encoded with Elligator 2 (tools/elligator.py), so it
# looks like random bytes; the body (header, then the contribution) is padded to a bucket,
# so the size gives away only the kind and the 30-day bucket. Keys as keyguard's hybrid
# KEM (both shared secrets feed the KDF). Residual: ML-KEM ciphertext coefficients are
# near-uniform, not exactly uniform.
ENVELOPE_CONTEXT = b"cypherpunk-vpn/padbook/envelope/v3"
MLKEM_CT = 1088
CHAIN_BODY = 4096  # a chain envelope's padded body


def _body_size(h):
    if h["kind"] == "chain":
        return CHAIN_BODY
    return CHAIN_BODY + -(-h["rounds"] // BUCKET_ROUNDS) * BUCKET_ROUNDS * PAD


def seal_opaque(recipient_public, plaintext):
    """`plaintext` sealed to a hybrid public key as bytes indistinguishable from random
    (up to the ML-KEM residual)."""
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

    import elligator

    if len(recipient_public) != keyguard.KEM_PUBLIC:
        raise ValueError("wrong recipient key")
    sk, u, rep = elligator.ephemeral()
    eph = u.to_bytes(32, "little")
    classical = x25519.X25519PrivateKey.from_private_bytes(sk).exchange(
        x25519.X25519PublicKey.from_public_bytes(recipient_public[:32])
    )
    pq, ct = mlkem.MLKEM768PublicKey.from_public_bytes(recipient_public[32:]).encapsulate()
    key = keyguard._kem_key(classical, pq, ENVELOPE_CONTEXT, eph, ct, recipient_public)
    nonce = os.urandom(12)
    return rep + ct + nonce + AESGCM(key).encrypt(nonce, plaintext, ENVELOPE_CONTEXT)


def open_opaque(private, blob):
    """The inverse of `seal_opaque` with the hybrid private key; fails on any change."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

    import elligator

    if len(private) != 96 or len(blob) < 32 + MLKEM_CT + 12 + 16:
        raise ValueError("not an envelope")
    rep, ct = blob[:32], blob[32 : 32 + MLKEM_CT]
    nonce, ciphertext = blob[32 + MLKEM_CT : 44 + MLKEM_CT], blob[44 + MLKEM_CT :]
    eph = elligator.from_representative(rep).to_bytes(32, "little")
    a = x25519.X25519PrivateKey.from_private_bytes(private[:32])
    b = mlkem.MLKEM768PrivateKey.from_seed_bytes(private[32:])
    raw = serialization.Encoding.Raw
    recipient = a.public_key().public_bytes(raw, serialization.PublicFormat.Raw) + b.public_key().public_bytes(
        raw, serialization.PublicFormat.Raw
    )
    classical = a.exchange(x25519.X25519PublicKey.from_public_bytes(eph))
    key = keyguard._kem_key(classical, b.decapsulate(ct), ENVELOPE_CONTEXT, eph, ct, recipient)
    return AESGCM(key).decrypt(nonce, ciphertext, ENVELOPE_CONTEXT)


def seal_contribution(h, sender, delivery, recipient_public, contribution, raw=None):
    """A contribution sealed to its recipient as an opaque envelope: its book, sender,
    delivery and raw-source record (an `assessment` record, or None) travel inside."""
    if delivery not in DELIVERIES or sender not in h["pair"]:
        raise ValueError("invalid contribution")
    if len(contribution) != contribution_length(h):
        raise ValueError("contribution length does not match the book")
    head = json.dumps(dict(book=h, sender=sender, delivery=delivery, raw=raw), sort_keys=True).encode()
    body = len(head).to_bytes(4, "big") + head + contribution
    size = _body_size(h)
    if len(body) > size:
        raise ValueError("contribution too large for its bucket")
    return seal_opaque(recipient_public, body + bytes(size - len(body)))


def open_contribution(blob, me, private, own=False):
    """(book, sender, delivery, raw, contribution) of an envelope sealed to `me`: from the
    partner, or with `own`, this member's kept copy. Fails on any change or mismatch."""
    body = open_opaque(private, blob)
    n = int.from_bytes(body[:4], "big")
    head = json.loads(body[4 : 4 + n])
    h, sender, delivery, raw = head["book"], head["sender"], head["delivery"], head.get("raw")
    if me not in h["pair"] or sender not in h["pair"] or (sender == me) != own or delivery not in DELIVERIES:
        raise ValueError("this contribution is not for this member")
    data = body[4 + n : 4 + n + contribution_length(h)]
    if len(data) != contribution_length(h):
        raise ValueError("contribution length does not match the book")
    return h, sender, delivery, raw, data


def combine(mine, theirs):
    """The pair's pads: both contributions XORed (both are needed, either suffices for secrecy)."""
    if len(mine) != len(theirs) or not mine or len(mine) % PAD:
        raise ValueError("contributions differ in length")
    return combine_any(mine, theirs)


def combine_any(a, b):
    """XOR of two equal-length, non-empty byte strings (books, seeds, sources)."""
    if len(a) != len(b) or not a:
        raise ValueError("lengths differ")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _hkdf(key, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(bytes(key))


# --- At rest: nothing in the clear (after TrueCrypt's volume header: a random salt, then
# everything encrypted), and two unrelated ciphers (a cascade) ---------------------------
SALT = 32
BOOK_FILE, PADS_FILE = "book.bin", "pads.bin"
BUCKET_ROUNDS = 30 * ROUNDS_PER_DAY  # pads.bin grows in 30-day steps of random-looking records


def cascade_seal(keys, nonce, plaintext, aad):
    """ChaCha20-Poly1305 (outer) over AES-256-GCM (inner), each with its own 32-byte key from
    `keys` (64 bytes): one cipher broken alone opens nothing."""
    inner = AESGCM(keys[:32]).encrypt(nonce, plaintext, aad)
    return ChaCha20Poly1305(keys[32:]).encrypt(nonce, inner, aad)


def cascade_open(keys, nonce, ciphertext, aad):
    """The inverse of `cascade_seal`; any wrong key, nonce, aad or byte fails."""
    inner = ChaCha20Poly1305(keys[32:]).decrypt(nonce, ciphertext, aad)
    return AESGCM(keys[:32]).decrypt(nonce, inner, aad)


def file_keys(secret, meta, salt):
    """The cascade keys of one book file: from the Nitrokey's hmac-secret and the file's
    own random salt, never stored."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=keyguard.unb64(meta["salt"]),
        info=b"cypherpunk-vpn/padbook/v2|" + salt,
    ).derive(secret)


def _round_keys(chain):
    return _hkdf(chain, b"pad-cascade", 64)


def _nonce(k):
    return k.to_bytes(12, "big")


class DirFiles:
    """A book's files in a plain directory (created 0700): the default store. A layer of a
    deniable store (tools/padstore.py) offers the same five calls."""

    def __init__(self, path):
        self.path = Path(path)

    def transaction(self):
        """Exclusive ownership for a complete reload/check/advance/erase operation."""
        import state_transaction

        return state_transaction.directory(self.path)

    def create(self):
        """Make the directory; refuses one that exists."""
        self.path.mkdir(mode=0o700, parents=False, exist_ok=False)

    def read(self, name, limit):
        """A whole private file, at most `limit` bytes."""
        return keyguard.read_private(self.path / name, limit)

    def write(self, name, data):
        """Replace a whole file atomically (0600)."""
        keyguard.atomic(self.path / name, data)

    def read_at(self, name, offset, n):
        """`n` bytes at `offset`."""
        with open(self.path / name, "rb") as f:
            f.seek(offset)
            return f.read(n)

    def write_at(self, name, offset, data):
        """Overwrite bytes in place at `offset`, synced to the disk."""
        with open(self.path / name, "r+b") as f:
            f.seek(offset)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())


def files(where):
    """`where` as a file store: a directory path, or an object with DirFiles' calls."""
    return where if hasattr(where, "read_at") else DirFiles(where)


def _save(directory, salt, keys, info):
    """book.bin = salt || nonce || cascade(everything): indistinguishable from random bytes."""
    nonce = os.urandom(12)
    blob = json.dumps(info, sort_keys=True).encode()
    files(directory).write(BOOK_FILE, salt + nonce + cascade_seal(keys, nonce, blob, salt))


def _load(directory, secret, meta):
    """(salt, keys, info) of a book file; fails, as on random data, without this Nitrokey."""
    data = files(directory).read(BOOK_FILE, 1 << 20)
    salt, nonce, ciphertext = data[:SALT], data[SALT : SALT + 12], data[SALT + 12 :]
    keys = file_keys(secret, meta, salt)
    return salt, keys, json.loads(cascade_open(keys, nonce, ciphertext, salt))


RECORD = PAD + 32  # a pad under the cascade: two 16-byte tags


def write_book(directory, h, contributions, pads, secret, meta, chain_seed):
    """Store `pads` encrypted at rest in `directory` (created, 0700). `chain_seed`: 32
    bytes from the Nitrokey, the first link of the per-round key chain."""
    if h["kind"] != "book" or len(pads) != h["rounds"] * PAD or len(chain_seed) != 32:
        raise ValueError("pads or chain seed do not match the book")
    directory = files(directory)
    if isinstance(directory, DirFiles):
        directory.create()
    with directory.transaction():
        if not isinstance(directory, DirFiles):
            directory.create()
        salt, chain, records = os.urandom(SALT), chain_seed, bytearray()
        for k in range(h["rounds"]):
            records += cascade_seal(_round_keys(chain), _nonce(k), pads[k * PAD : (k + 1) * PAD], salt + b"|%d" % k)
            chain = _hkdf(chain, b"next")
        bucket = -(-h["rounds"] // BUCKET_ROUNDS) * BUCKET_ROUNDS
        records += os.urandom((bucket - h["rounds"]) * RECORD)  # filler, as random as the rest
        directory.write(PADS_FILE, bytes(records))
        info = dict(book=h, contributions=contributions, state=dict(next=0, chain=chain_seed.hex()))
        _save(directory, salt, file_keys(secret, meta, salt), info)


def edge_claim(contributions, kind="book"):
    """Conditional IT construction when provenance declares assessed physical noise and
    in-person custody. This does not verify source entropy, independence, seed quality,
    custody or secure erasure; the label certifies none of those. Otherwise computational:
    Nitrokey output is a ChaCha8 stream, a remote contribution is as strong as the hybrid
    KEM, and a chain's pads are derived with SHA-256."""
    if kind == "chain":
        return "computational"
    for c in contributions.values():
        if c.get("delivery") == "in_person" and c.get("raw") and c["raw"].get("h_used", 0) > 0:
            return "conditional-information-theoretic"
    return "computational"


def chain_pad(state, rnd):
    """A chain's pad of round `rnd` from that round's state (src/dcnet.rs Ratchet)."""
    r = rnd.to_bytes(8, "big")
    return hashlib.sha256(b"dc-pad-0" + state + r).digest() + hashlib.sha256(b"dc-pad-1" + state + r).digest()


def chain_next(state):
    """The next round's state: one way."""
    return hashlib.sha256(b"dc-next" + state).digest()


def write_chain(directory, h, contributions, seed, secret, meta):
    """Store a chain (its state for `first_round` is `seed`) in `directory` (created,
    0700), as an opaque book file."""
    if h["kind"] != "chain" or len(seed) != SEED:
        raise ValueError("not a chain seed")
    directory = files(directory)
    if isinstance(directory, DirFiles):
        directory.create()
    with directory.transaction():
        if not isinstance(directory, DirFiles):
            directory.create()
        salt = os.urandom(SALT)
        info = dict(book=h, contributions=contributions, state=dict(next=0, chain=seed.hex()))
        _save(directory, salt, file_keys(secret, meta, salt), info)


def reload_info(where, salt, keys):
    """Reload authenticated state under an already-held store transaction."""
    data = files(where).read(BOOK_FILE, 1 << 20)
    if data[:SALT] != salt:
        raise ValueError("state identity changed; reopen the store")
    return json.loads(cascade_open(keys, data[SALT : SALT + 12], data[SALT + 12 :], salt))


class _Stored:
    """A book or chain; every operation reloads its state under exclusive ownership."""

    kind = None

    def __init__(self, directory, secret, meta, clock=time.time):
        self.dir = files(directory)
        self.salt, keys, self.info = _load(self.dir, secret, meta)
        self.keys = Secret(keys)
        self.h = self.info["book"]
        if self.h.get("kind") != self.kind:
            raise ValueError("not a %s" % self.kind)
        self.clock = clock

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.keys.wipe()

    @contextlib.contextmanager
    def _transaction(self):
        with self.dir.transaction():
            info = reload_info(self.dir, self.salt, self.keys.bytes)
            if info["book"] != self.h:
                raise ValueError("state identity changed; reopen the store")
            self.info = info
            yield

    def _state(self):
        s = self.info["state"]
        return dict(next=s["next"], chain=bytes.fromhex(s["chain"]))

    @property
    def state(self):
        """A fresh snapshot, including advances made by other handles."""
        with self._transaction():
            return self._state()

    def _advance(self, next_k, chain):
        self.info["state"] = dict(next=next_k, chain=chain.hex())
        _save(self.dir, self.salt, self.keys.bytes, self.info)

    def _check(self, rnd):
        k = rnd - self.h["first_round"]
        if k < self._state()["next"] or rnd < round_now(self.clock()) - 1:
            raise ValueError("round already used or past")
        return k

    def claim(self):
        """A provenance-qualified claim, never a software certification of physical noise."""
        with self._transaction():
            return edge_claim(self.info["contributions"], self.kind)


class Chain(_Stored):
    """An at-rest chain; a completed operation consumes a round globally once."""

    kind = "chain"

    def take(self, rnd):
        """Commit the advanced state before releasing this round's pad."""
        with self._transaction():
            k = self._check(rnd)
            state = self._state()
            s = bytearray(state["chain"])
            try:
                for _ in range(state["next"], k):
                    s[:] = chain_next(s)
                pad = chain_pad(s, rnd)
                self._advance(k + 1, chain_next(s))
            finally:
                _memzero(s)
        return pad


class Book(_Stored):
    """An at-rest book; a completed operation consumes a round globally once."""

    kind = "book"

    def rounds_left(self):
        """Fresh count of the rounds not yet burned by any consumer."""
        with self._transaction():
            return self.h["rounds"] - self._state()["next"]

    def take(self, rnd):
        """Advance and erase under one transaction; a failure releases no pad."""
        with self._transaction():
            k = self._check(rnd)
            if k >= self.h["rounds"]:
                raise ValueError("book used up: the cell stops")
            state = self._state()
            chain, first = bytearray(state["chain"]), state["next"]
            try:
                for _ in range(first, k):
                    chain[:] = _hkdf(chain, b"next")
                record = self.dir.read_at(PADS_FILE, k * RECORD, RECORD)
                pad = cascade_open(_round_keys(chain), _nonce(k), record, self.salt + b"|%d" % k)
                self._advance(k + 1, _hkdf(chain, b"next"))
                self.dir.write_at(PADS_FILE, first * RECORD, bytes((k + 1 - first) * RECORD))
            finally:
                _memzero(chain)
        return pad


def kem_keygen(secret, meta):
    """A hybrid key pair for receiving contributions; the private half sealed under the
    Nitrokey's hmac-secret (keyguard envelope, bound to the public half)."""
    private, public = keyguard.kem_keypair()
    sealed = keyguard.seal_bytes(secret, meta, "padbook-kem", public, private)
    return public, dict(schema=1, public=keyguard.b64(public), sealed=sealed)


def kem_private(secret, meta, value):
    """Open a sealed `kem_keygen` private key (fails unless this vault sealed it)."""
    public = keyguard.unb64(value["public"])
    return keyguard.open_bytes(secret, meta, "padbook-kem", public, value["sealed"])


def harden():
    """Attempt memory locking/dump restrictions and install wiping; OS success is not certified."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mlockall(3)  # MCL_CURRENT | MCL_FUTURE: keep this process's pages out of swap
        libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0: no ptrace, no /proc/<pid>/mem read
    except (OSError, AttributeError):
        pass
    _install_wipe_on_exit()


def _unlock_book(args):
    """(secret, meta, where the book lives): a directory, or with --store the layer its
    passphrase opens (one PIN + touch either way)."""
    if not args.store:
        secret, meta = keyguard.hardware_secret(args.vault)
        return secret, meta, args.book
    import getpass

    import padstore

    secret, meta, layer = padstore.unlock(args.vault, args.store, getpass.getpass("layer passphrase: "))
    return secret, meta, padstore.LayerFiles(layer, args.book.name)


def main():
    """The command line: assess, keygen, make, accept, status."""
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s_ = sub.add_parser("assess", help="assess this machine's raw jitter source (once, on an idle machine)")
    s_.add_argument("--recorder", type=Path, required=True, help="jitterentropy-hashtime (raw-noise recorder)")
    s_.add_argument("--ea-non-iid", type=Path, required=True, help="NIST SP 800-90B ea_non_iid")
    s_.add_argument("--out", type=Path, required=True, help="write the assessment record here")
    s_.add_argument("--nitropy")
    k = sub.add_parser("keygen", help="a hybrid key pair for receiving contributions (Nitrokey-sealed)")
    k.add_argument("--vault", type=Path, required=True, help="keyguard vault (Nitrokey hmac-secret)")
    k.add_argument("--public", type=Path, required=True, help="write the public key here (give it out)")
    k.add_argument("--sealed", type=Path, required=True, help="write the sealed private key here")
    m = sub.add_parser("make", help="make this member's contribution for a partner (Nitrokey)")
    m.add_argument("--cell", type=int, required=True)
    m.add_argument("--me", required=True)
    m.add_argument("--partner", required=True)
    m.add_argument("--first-round", type=int, help="default: the round 10 minutes from now")
    m.add_argument("--kind", choices=("book", "chain"), required=True, help="book: met in person; chain: cannot meet")
    m.add_argument("--days", type=float, help="book only: days of pads")
    m.add_argument("--partner-key", type=Path, required=True, help="the partner's hybrid public key (raw)")
    m.add_argument("--delivery", choices=DELIVERIES, required=True)
    m.add_argument("--out", type=Path, required=True, help="the sealed contribution to hand over")
    m.add_argument("--keep", type=Path, required=True, help="your own copy, sealed to your key")
    m.add_argument("--my-key", type=Path, required=True, help="your hybrid public key (raw)")
    m.add_argument("--raw", type=Path, help="an `assess` record: mix in the raw jitter source (needed for an IT book)")
    m.add_argument("--recorder", type=Path, help="jitterentropy-hashtime, with --raw")
    m.add_argument("--nitropy")
    a = sub.add_parser("accept", help="combine the partner's contribution with yours into a book")
    a.add_argument("--me", required=True)
    a.add_argument("--theirs", type=Path, required=True)
    a.add_argument("--mine", type=Path, required=True, help="your --keep file")
    a.add_argument("--kem-sealed", type=Path, required=True, help="your keygen --sealed file")
    a.add_argument("--vault", type=Path, required=True, help="keyguard vault (Nitrokey hmac-secret)")
    a.add_argument("--book", type=Path, required=True, help="new directory for the book (with --store: its name)")
    a.add_argument("--store", type=Path, help="a deniable store (tools/padstore.py): the book goes in a layer")
    a.add_argument("--nitropy")
    s = sub.add_parser("status", help="rounds and days left, and the edge's claim")
    s.add_argument("--book", type=Path, required=True)
    s.add_argument("--vault", type=Path, required=True)
    s.add_argument("--store", type=Path, help="the book is in a layer of this deniable store")
    args = p.parse_args()
    harden()
    if args.cmd == "assess":
        import tempfile

        estimates, outputs = [], []
        for _ in range(ASSESS_RUNS):  # separate recordings; the lowest estimate counts
            samples = jitter_samples(ASSESS_SAMPLES, args.recorder)
            raw_health(samples, 1.0)  # a gross failure stops the assessment before it starts
            with tempfile.TemporaryDirectory() as d:
                f = Path(d) / "samples.bin"
                f.write_bytes(samples)
                cmd = [str(args.ea_non_iid), "-a", "-v", "-v", "-v", str(f), "8"]
                r = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if r.returncode != 0:
                raise SystemExit("ea_non_iid failed: " + (r.stderr or r.stdout)[-300:])
            estimates.append(parse_ea_non_iid(r.stdout))
            outputs.append(r.stdout)
        h = min(estimates)
        m = extracted_bits(h * SAFETY)
        seed = nitrokey_bytes(math.ceil(toeplitz_seed_bits(m) / 8), args.nitropy)
        record = assessment(h, seed, args.recorder, hashlib.sha256("".join(outputs).encode()).hexdigest())
        record["runs"] = estimates
        keyguard.atomic(args.out, json.dumps(record, sort_keys=True).encode())
        print(
            json.dumps(dict(runs=estimates, h_assessed=h, h_used=record["h_used"], bits_per_block=m, out=str(args.out)))
        )
    elif args.cmd == "keygen":
        secret, meta = keyguard.hardware_secret(args.vault)
        public, value = kem_keygen(secret, meta)
        keyguard.atomic(args.sealed, json.dumps(value).encode())
        args.public.write_bytes(public)
        print(json.dumps(dict(public=str(args.public), sealed=str(args.sealed))))
    elif args.cmd == "make":
        first = args.first_round if args.first_round is not None else round_now() + 20
        if args.kind == "chain":
            h = chain_header(args.cell, args.me, args.partner, first)
        else:
            if not args.days:
                raise SystemExit("a book needs --days")
            h = header(args.cell, args.me, args.partner, first, int(args.days * ROUNDS_PER_DAY))
        n = contribution_length(h)
        raw = None
        if args.raw:
            if not args.recorder:
                raise SystemExit("--raw needs --recorder")
            raw = json.loads(args.raw.read_text())
        else:
            print("note: kernel and Nitrokey output only, so this contribution is computational", file=sys.stderr)
        mine = contribution_bytes(n, raw, args.recorder, args.nitropy)
        keyguard.atomic(
            args.out, seal_contribution(h, args.me, args.delivery, args.partner_key.read_bytes(), mine, raw)
        )
        keyguard.atomic(args.keep, seal_contribution(h, args.me, args.delivery, args.my_key.read_bytes(), mine, raw))
        print(json.dumps(dict(book=book_id(h), kind=h["kind"], first_round=first, bytes=n, raw=bool(raw))))
    elif args.cmd == "accept":
        secret, meta, where = _unlock_book(args)  # one PIN + touch for the key, the book (and the layer)
        private = kem_private(secret, meta, json.loads(keyguard.read_private(args.kem_sealed)))
        h_t, s_t, d_t, r_t, theirs = open_contribution(args.theirs.read_bytes(), args.me, private)
        h, s_m, d_m, r_m, mine = open_contribution(
            keyguard.read_private(args.mine, 1 << 31), args.me, private, own=True
        )
        if h_t != h:
            raise SystemExit("the two contributions are for different books")
        combined = combine_any(mine, theirs)
        contributions = {s_m: dict(delivery=d_m, raw=r_m), s_t: dict(delivery=d_t, raw=r_t)}
        if h["kind"] == "chain":
            write_chain(where, h, contributions, combined, secret, meta)
        else:
            write_book(where, h, contributions, combined, secret, meta, nitrokey_bytes(32, args.nitropy))
        args.mine.unlink()
        print(json.dumps(dict(book=book_id(h), kind=h["kind"], claim=edge_claim(contributions, h["kind"]))))
    else:
        secret, meta, where = _unlock_book(args)
        kind = _load(where, secret, meta)[2]["book"]["kind"]
        if kind == "chain":
            print(json.dumps(dict(kind="chain", rounds_left=None, claim=Chain(where, secret, meta).claim())))
        else:
            b = Book(where, secret, meta)
            left = b.rounds_left()
            print(
                json.dumps(
                    dict(kind="book", rounds_left=left, days_left=round(left / ROUNDS_PER_DAY, 2), claim=b.claim())
                )
            )


if __name__ == "__main__":
    main()

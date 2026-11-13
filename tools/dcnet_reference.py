#!/usr/bin/env python3
"""Reference implementation of the DC-net round core (byte-exact mirror of
src/dcnet.rs) + golden-vector generator for the Rust tests.

Construction (DCNET_CONTROL_DESIGN.md §2–§4):
  seed_ij(cell)  = HKDF-SHA256(ikm=K_ij, salt=zeros32, info="dc-pad"||cell_id_be4)[..32]
  pad_ij(round)  = PRG(seed_ij, "dc-round-<round decimal>")   # SHA256-CTR expansion
  body_i         = (event_i?) XOR (XOR over partners j of pad_ij)
  frame          = magic(2)||cell_id(4)||round(8)||flags(1)||body(64)||mac(32)
  group decode   = XOR of all bodies; null => all-zero; CRC-8(poly 0x07) guards
                   event encoding; anything else => Garbled.

Outputs vectors.json consumed by the Rust #[cfg(test)] module.
"""

import hashlib
import hmac as hmac_mod
import json
from pathlib import Path

BODY_LEN = 64
FRAME_LEN = 111


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def prg(seed: bytes, ctx: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += sha256(seed + ctx + ctr.to_bytes(4, "big"))
        ctr += 1
    return out[:n]


def hkdf_sha256(ikm: bytes, info: bytes, n: int) -> bytes:
    # RFC 5869, salt = 32 zero bytes (the default)
    prk = hmac_mod.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, ctr = b"", b"", 1
    while len(out) < n:
        t = hmac_mod.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        out += t
        ctr += 1
    return out[:n]


def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


class CellPads:
    """Mirrors Rust CellPads: pairwise master keys K_ij indexed by partner
    (own index skipped), symmetric across members."""

    def __init__(self, n: int, my_index: int, pairwise: list):
        assert my_index < n and len(pairwise) == n - 1
        self.n, self.i, self.pw = n, my_index, pairwise

    def k(self, partner: int) -> bytes:
        return self.pw[partner if partner < self.i else partner - 1]

    def round_pad(self, partner: int, cell_id: int, rnd: int) -> bytes:
        seed = hkdf_sha256(self.k(partner), b"dc-pad" + cell_id.to_bytes(4, "big"), 32)
        return prg(seed, b"dc-round-%d" % rnd, BODY_LEN)

    def body(self, cell_id: int, rnd: int, event: bytes = b"") -> bytes:
        b = b"\x00" * BODY_LEN
        for j in range(self.n):
            if j != self.i:
                b = xor(b, self.round_pad(j, cell_id, rnd))
        if event:
            b = xor(b, event)
        return b


def encode_event(kind: int, nonce: int, payload: bytes) -> bytes:
    assert len(payload) <= 46
    b = bytearray(BODY_LEN)
    b[0] = kind
    b[1:9] = nonce.to_bytes(8, "big")
    b[9 : 9 + len(payload)] = payload
    b[55] = crc8(bytes(b[:55]))
    return bytes(b)


def decode_event(slot: bytes):
    if slot == b"\x00" * BODY_LEN:
        return "null"
    if any(slot[56:64]):
        return "garbled"
    if crc8(slot[:55]) != slot[55]:
        return "garbled"
    if slot[0] not in (1, 2, 3, 4):
        return "garbled"
    return ("event", slot[0], int.from_bytes(slot[1:9], "big"), slot[9:55])


def build_frame(cell_id: int, rnd: int, body: bytes) -> bytes:
    f = bytearray(FRAME_LEN)
    f[0:2] = b"\xdc\x4e"
    f[2:6] = cell_id.to_bytes(4, "big")
    f[6:14] = rnd.to_bytes(8, "big")
    f[14] = 0  # flags: constant — never encodes sender state
    f[15:79] = body
    # mac filled by integration layer (seal)
    return bytes(f)


def group_sum(bodies):
    s = b"\x00" * BODY_LEN
    for b in bodies:
        s = xor(s, b)
    return s


# ------------------------------------------------------------------
# Golden vectors
# ------------------------------------------------------------------
def gen_vectors():
    n, cell_id, rnd = 4, 0xA17C4D, 77
    # symmetric pairwise master keys K_ij
    k = {}
    for a in range(n):
        for b in range(n):
            if a < b:
                k[(a, b)] = sha256(b"vec-k-%d-%d" % (a, b))[:32]

    def pw(i):  # partner list for member i, own index skipped
        return [k[(min(i, j), max(i, j))] for j in range(n) if j != i]

    members = [CellPads(n, i, pw(i)) for i in range(n)]

    event = encode_event(2, 0x1122334455667788, b"chain-setup-commit-payload-0123456789")
    sender = 2

    bodies = [m.body(cell_id, rnd, event if i == sender else b"") for i, m in enumerate(members)]
    s = group_sum(bodies)
    null_bodies = [m.body(cell_id, rnd) for m in members]
    s_null = group_sum(null_bodies)

    vec = {
        "n": n,
        "cell_id": cell_id,
        "round": rnd,
        "sender": sender,
        "k_01": k[(0, 1)].hex(),
        "k_23": k[(2, 3)].hex(),
        "pad_m0_p1": members[0].round_pad(1, cell_id, rnd).hex(),
        "pad_m2_p3": members[2].round_pad(3, cell_id, rnd).hex(),
        "event_encoding": event.hex(),
        "body_m2_event": bodies[2].hex(),
        "body_m0_silent": bodies[0].hex(),
        "sum_bodies": s.hex(),
        "sum_null": s_null.hex(),
        "frame_m2": build_frame(cell_id, rnd, bodies[2]).hex(),
    }

    # --- self-checks (same properties as harness section F) ---
    sent_payload = event[9:55]  # as it appears padded inside the encoding

    def ev(nonce):
        return ("event", 2, nonce, sent_payload)

    checks = {}
    checks["decode_sum_is_event"] = decode_event(s) == ev(0x1122334455667788)
    checks["null_round"] = decode_event(s_null) == "null"
    # stale replay: member 0 replays round-76 body into round 77
    stale = members[0].body(cell_id, 76)
    mixed = [stale] + [members[i].body(cell_id, 77) for i in (1, 2, 3)]
    checks["stale_garbled"] = decode_event(group_sum(mixed)) == "garbled"
    # collision: two senders with DIFFERENT nonces -> undecodable
    ev_b = encode_event(2, 0x9988776655443322, b"chain-setup-commit-payload-0123456789")
    col = [members[i].body(cell_id, rnd, event if i == 1 else (ev_b if i == 3 else b"")) for i in range(n)]
    checks["collision_garbled"] = decode_event(group_sum(col)) == "garbled"
    # collision of two IDENTICAL encodings cancels to null (documented edge)
    col_same = [members[i].body(cell_id, rnd, event if i in (1, 3) else b"") for i in range(n)]
    checks["identical_collision_null"] = decode_event(group_sum(col_same)) == "null"
    # jam: member 0 xors garbage
    jam = [xor(members[0].body(cell_id, rnd), prg(b"jam", b"x", 64))] + [
        members[i].body(cell_id, rnd, event if i == 2 else b"") for i in (1, 2, 3)
    ]
    checks["jam_garbled"] = decode_event(group_sum(jam)) == "garbled"
    # round binding: pads differ across rounds
    checks["pads_differ"] = members[0].round_pad(1, cell_id, 76) != members[0].round_pad(1, cell_id, 77)
    # sender-position independence, n=24
    n24 = 24
    k24 = {(a, b): sha256(b"vec24-%d-%d" % (a, b))[:32] for a in range(n24) for b in range(n24) if a < b}
    m24 = [CellPads(n24, i, [k24[(min(i, j), max(i, j))] for j in range(n24) if j != i]) for i in range(n24)]
    ok_pos = all(
        decode_event(group_sum([m.body(cell_id, rnd, event if i == s else b"") for i, m in enumerate(m24)]))
        == ev(0x1122334455667788)
        for s in range(n24)
    )
    checks["all_sender_positions_n24"] = ok_pos

    assert all(checks.values()), checks
    vec["self_checks"] = {k: bool(v) for k, v in checks.items()}
    return vec


if __name__ == "__main__":
    # --check: regenerate in memory and compare with the committed vectors (CI).
    import sys

    out = Path(__file__).resolve().parents[1] / "docs/evidence/DCNET_VECTORS.json"
    if "--check" in sys.argv[1:]:
        fresh = json.dumps(gen_vectors(), indent=2) + "\n"
        if fresh != out.read_text():
            raise SystemExit("DCNET_VECTORS.json does not match the reference construction")
        print("DC-net vectors match the reference construction")
        raise SystemExit(0)
    v = gen_vectors()
    out.write_text(json.dumps(v, indent=2) + "\n")
    print("self-checks:", v["self_checks"])
    print("vectors written:", out)
    print("pad_m0_p1[:16] =", v["pad_m0_p1"][:32])
    print("sum_bodies[:16] =", v["sum_bodies"][:32])

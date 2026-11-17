#!/usr/bin/env python3
"""Reference implementation of the DC-net round core (byte-exact mirror of
src/dcnet.rs) + golden-vector generator for the Rust tests.

Construction (DCNET_CONTROL_DESIGN.md §2–§4):
  book_ij        = one-time pads for the pair in one cell, 64 bytes per round from
                   first_round (in use: Nitrokey bytes, tools/padbook.py; here: fixed
                   test bytes, sha256("vec-book-a-b-k") blocks)
  pad_ij(round)  = book_ij[(round - first_round) * 64 : +64], used once   (in person)
                 | SHA256("dc-pad-0"||s_r||r_be8) || SHA256("dc-pad-1"||s_r||r_be8),
                   s_{r+1} = SHA256("dc-next"||s_r), s_first = seed      (over the network)
  body_i         = (event_i?) XOR (XOR over partners j of pad_ij)
  frame          = magic(2)||cell_id(4)||round(8)||flags(1)||body(64)||mac(32)
  event          = kind(1)||nonce(8)||payload(46)||tag(9),
                   tag = SHA256("dc-event/v2"||kind||nonce||payload)[:9]
  group decode   = XOR of all bodies; null => all-zero; a valid tag and kind => the
                   event; anything else => Garbled. (v1 used CRC-8, which is linear: the XOR
                   of two events passed it, so collisions decoded as events.)

Outputs vectors.json consumed by the Rust #[cfg(test)] module.
"""

import hashlib
import json
from pathlib import Path

BODY_LEN = 64
FRAME_LEN = 111


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


FIRST_ROUND = 70  # the test books' first round
BOOK_ROUNDS = 16  # rounds in each test book


def test_book(a: int, b: int, tag: bytes = b"vec-book") -> bytes:
    """The pair (a, b)'s test book: fixed, public bytes standing in for Nitrokey output."""
    return b"".join(sha256(tag + b"-%d-%d-%d" % (a, b, k)) for k in range(BOOK_ROUNDS * BODY_LEN // 32))


TAG_LEN = 9


def event_tag(head: bytes) -> bytes:
    """Public truncated SHA-256 check, not event authentication. A member knowing an
    event can XOR its encoding with a replacement's encoding to substitute it."""
    return hashlib.sha256(b"dc-event/v2" + head).digest()[:TAG_LEN]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def ratchet_pad(seed: bytes, first_round: int, rnd: int) -> bytes:
    """Mirrors Rust Ratchet: the pad of `rnd` from a chain seeded at `first_round`."""
    s = seed
    for _ in range(rnd - first_round):
        s = sha256(b"dc-next" + s)
    r = rnd.to_bytes(8, "big")
    return sha256(b"dc-pad-0" + s + r) + sha256(b"dc-pad-1" + s + r)


class Ratchet:
    """A pair's chain, as one of CellPads' partners."""

    def __init__(self, seed: bytes, first_round: int = FIRST_ROUND):
        self.seed, self.first = seed, first_round


class CellPads:
    """Mirrors Rust CellPads: one pad book per partner (own index skipped), the same
    bytes at both ends of a pair. (The Rust side also wipes each pad once used.)"""

    def __init__(self, n: int, my_index: int, books: list, first_round: int = FIRST_ROUND):
        assert my_index < n and len(books) == n - 1
        self.n, self.i, self.books, self.first = n, my_index, books, first_round

    def round_pad(self, partner: int, rnd: int) -> bytes:
        book = self.books[partner if partner < self.i else partner - 1]
        if isinstance(book, Ratchet):
            return ratchet_pad(book.seed, book.first, rnd)
        at = (rnd - self.first) * BODY_LEN
        if not 0 <= at <= len(book) - BODY_LEN:
            raise ValueError("no pad for this round")
        return book[at : at + BODY_LEN]

    def body(self, cell_id: int, rnd: int, event: bytes = b"") -> bytes:
        b = b"\x00" * BODY_LEN
        for j in range(self.n):
            if j != self.i:
                b = xor(b, self.round_pad(j, rnd))
        if event:
            b = xor(b, event)
        return b


def encode_event(kind: int, nonce: int, payload: bytes) -> bytes:
    assert len(payload) <= 46
    b = bytearray(BODY_LEN)
    b[0] = kind
    b[1:9] = nonce.to_bytes(8, "big")
    b[9 : 9 + len(payload)] = payload
    b[55:64] = event_tag(bytes(b[:55]))
    return bytes(b)


def decode_event(slot: bytes):
    if slot == b"\x00" * BODY_LEN:
        return "null"
    if event_tag(slot[:55]) != slot[55:64]:
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
    # one test book per pair, the same at both ends
    k = {(a, b): test_book(a, b) for a in range(n) for b in range(n) if a < b}

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
        "first_round": FIRST_ROUND,
        "book_rounds": BOOK_ROUNDS,
        "book_01_first_pad": k[(0, 1)][:BODY_LEN].hex(),
        "book_23_first_pad": k[(2, 3)][:BODY_LEN].hex(),
        "pad_m0_p1": members[0].round_pad(1, rnd).hex(),
        "pad_m2_p3": members[2].round_pad(3, rnd).hex(),
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
    jam = [xor(members[0].body(cell_id, rnd), sha256(b"jam") * 2)] + [
        members[i].body(cell_id, rnd, event if i == 2 else b"") for i in (1, 2, 3)
    ]
    checks["jam_garbled"] = decode_event(group_sum(jam)) == "garbled"
    # round binding: pads differ across rounds
    checks["pads_differ"] = members[0].round_pad(1, 76) != members[0].round_pad(1, 77)
    # sender-position independence, n=24
    n24 = 24
    k24 = {(a, b): test_book(a, b, b"vec24") for a in range(n24) for b in range(n24) if a < b}
    m24 = [CellPads(n24, i, [k24[(min(i, j), max(i, j))] for j in range(n24) if j != i]) for i in range(n24)]
    ok_pos = all(
        decode_event(group_sum([m.body(cell_id, rnd, event if i == s else b"") for i, m in enumerate(m24)]))
        == ev(0x1122334455667788)
        for s in range(n24)
    )
    checks["all_sender_positions_n24"] = ok_pos
    # A mixed cell: pairs (0,1) and (2,3) on chains, the rest on books.
    chains = {(0, 1), (2, 3)}
    km = {
        (a, b): Ratchet(sha256(b"vec-ratchet-%d-%d" % (a, b))) if (a, b) in chains else test_book(a, b)
        for a in range(n)
        for b in range(n)
        if a < b
    }
    mixed_cell = [CellPads(n, i, [km[(min(i, j), max(i, j))] for j in range(n) if j != i]) for i in range(n)]
    msum = group_sum([m.body(cell_id, rnd, event if i == 1 else b"") for i, m in enumerate(mixed_cell)])
    checks["mixed_cell_decodes"] = decode_event(msum) == ev(0x1122334455667788)
    vec["ratchet_seed_01"] = sha256(b"vec-ratchet-0-1").hex()
    vec["ratchet_pad_01"] = ratchet_pad(sha256(b"vec-ratchet-0-1"), FIRST_ROUND, rnd).hex()
    vec["mixed_sum"] = msum.hex()

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

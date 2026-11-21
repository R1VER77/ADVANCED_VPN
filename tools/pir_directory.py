#!/usr/bin/env python3
"""Private retrieval of a directory record (roadmap section 6: the PIR item).

"Implement/authenticate a consistent PIR directory with secure
randomness and explicit independent-operator assumptions. Distinguish
XOR reference timings from deployed DPF results and from network
reservations."

A member wants node descriptor i from the mesh directory without
revealing WHICH node it is interested in. Two constructions, both real,
honestly labelled:

  XOR-PIR (the reference; information-theoretic)
    TWO non-colluding servers each hold the directory. The client sends
    a uniform random mask m (n bits) to server A and m XOR e_i to
    server B; each returns the XOR of the records its mask selects; the
    XOR of the answers is record i. Privacy is information-theoretic
    against each server alone, and the independent-operator assumption
    is explicit: colluding servers trivially reconstruct the query.
    Reference timings only — never deployed results.

  DPF-PIR (the deployment candidate; computational)
    The Boyle-Gilboa-Ishai distributed point function over a GGM tree:
    Gen(i) produces two keys (seed + party bit + per-level correction
    words) such that each server's full-domain evaluation yields a
    pseudorandom 0/1 selector vector, and the two vectors XOR to
    exactly e_i. Each server answers with the XOR of the records its
    selector picks; the answers XOR to record i. Each server's view is
    computationally independent of i (PRG security, semi-honest model).
    The PRG here is hashlib-based: a control-plane implementation whose
    timings are deployment-CANDIDATE timings; a constant-time data
    plane needs the vendored-crate review the mesh credits' VOPRF
    verifier is waiting on too.

What this module does NOT claim: network reservations (live-relay
latency is a deployment measurement), and no anonymity claim beyond
query privacy against one semi-honest server.

Randomness: every seed, mask and correction word is drawn with
`secrets` (CSPRNG).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time

SCHEMA = 1
PRG_DOMAIN = b"avpn-pir/prg/v1|"
SEED_BYTES = 16


def _prg(seed: bytes) -> tuple[bytes, bytes, int, int]:
    """One GGM expansion: seed -> (left seed, right seed, left bit,
    right bit). Deterministic; control-plane (hashlib) PRG."""
    out = hashlib.sha512(PRG_DOMAIN + b"expand|" + seed).digest()
    left, right = out[:SEED_BYTES], out[SEED_BYTES : 2 * SEED_BYTES]
    t_l = out[2 * SEED_BYTES] & 1
    t_r = out[2 * SEED_BYTES + 1] & 1
    return left, right, t_l, t_r


def _lsb(seed: bytes) -> int:
    return seed[0] & 1


# ----------------------------------------------------------------- DPF


class DPFKey:
    """One server's key: its root seed, its party bit (0 or 1) and the
    shared correction words. Structurally identical for both parties
    except seed/party, so neither key alone carries the index."""

    __slots__ = ("seed", "party", "cws", "final_cw", "domain")

    def __init__(self, seed: bytes, party: int, cws: list, final_cw: int, domain: int):
        self.seed = seed
        self.party = party
        self.cws = cws  # per level: (seed_cw, tL_cw, tR_cw)
        self.final_cw = final_cw  # the leaf conversion bit
        self.domain = domain

    def to_bytes(self) -> bytes:
        """The key's wire encoding."""
        return json.dumps(
            {
                "seed": self.seed.hex(),
                "party": self.party,
                "cws": [[s.hex(), tl, tr] for s, tl, tr in self.cws],
                "final_cw": self.final_cw,
                "domain": self.domain,
            }
        ).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "DPFKey":
        """Decode a key from its wire encoding, refusing malformed input."""
        doc = json.loads(data)
        return cls(
            bytes.fromhex(doc["seed"]),
            doc["party"],
            [(bytes.fromhex(s), tl, tr) for s, tl, tr in doc["cws"]],
            doc["final_cw"],
            doc["domain"],
        )


def dpf_gen(index: int, domain: int) -> tuple[bytes, bytes]:
    """Gen for the point function e_index over [0, domain): two keys.

    Invariants maintained down the tree (the BGI construction, with the
    party whose control bit is 1 applying each level's correction word):
      - on-path nodes: the two parties' seeds differ, control bits differ;
      - off-path nodes: the two parties' seeds are EQUAL, control bits
        are equal — the correction words enforce both at every level.
    The final conversion word makes the leaf output bits XOR to
    e_index exactly.
    """
    if not 0 <= index < domain:
        raise ValueError("index out of the domain")
    nbits = max(1, (domain - 1).bit_length())
    s0, s1 = secrets.token_bytes(SEED_BYTES), secrets.token_bytes(SEED_BYTES)
    root0, root1 = s0, s1  # the seeds Eval re-expands from; the loop below
    # advances (s0, s1) to the target leaf for the final conversion word only
    t0, t1 = 0, 1  # control bits: differ at the (on-path) root
    cws = []
    for lvl in range(nbits):
        l0, r0, tl0, tr0 = _prg(s0)
        l1, r1, tl1, tr1 = _prg(s1)
        bit = (index >> (nbits - 1 - lvl)) & 1
        if bit == 0:
            # Walking left: RIGHT is off-path. The seed correction
            # equalizes the off-path children; the control-bit
            # correction equalizes off-path control bits and keeps the
            # on-path pair APART (the +1 belongs on the on-path side).
            s_cw = _xor(r0, r1)
            t_l_cw = tl0 ^ tl1 ^ 1  # on-path: parties stay apart
            t_r_cw = tr0 ^ tr1  # off-path: parties equalize
            on0, on1, ton0, ton1 = l0, l1, tl0, tl1
        else:
            # Walking right: LEFT is off-path.
            s_cw = _xor(l0, l1)
            t_l_cw = tl0 ^ tl1  # off-path: parties equalize
            t_r_cw = tr0 ^ tr1 ^ 1  # on-path: parties stay apart
            on0, on1, ton0, ton1 = r0, r1, tr0, tr1
        # Advance on-path, mirroring Eval exactly: the party whose
        # control bit is 1 applies this level's correction word.
        s0 = on0 if t0 == 0 else _xor(on0, s_cw)
        s1 = on1 if t1 == 0 else _xor(on1, s_cw)
        t0 = ton0 ^ (t0 * t_l_cw if bit == 0 else t0 * t_r_cw)
        t1 = ton1 ^ (t1 * t_l_cw if bit == 0 else t1 * t_r_cw)
        cws.append((s_cw, t_l_cw, t_r_cw))
    # (s0, t0) and (s1, t1) are now the two parties' states at the
    # target leaf: seeds differ, control bits differ. The final
    # conversion word makes the leaf bits XOR to 1 at the target; every
    # other leaf has both parties equal (equal seeds, equal control
    # bits), so their output bits cancel.
    final_cw = _lsb(s0) ^ _lsb(s1) ^ 1  # leaf states: seeds differ, bits differ
    # The keys carry the ROOT seeds (and the root control bits 0/1 as the
    # party bit); Eval walks the same tree the loop above walked on-path.
    k0 = DPFKey(root0, 0, cws, final_cw, domain)
    k1 = DPFKey(root1, 1, cws, final_cw, domain)
    return k0.to_bytes(), k1.to_bytes()


def dpf_eval(key_bytes: bytes) -> list[int]:
    """Full-domain evaluation: the selector vector (one 0/1 per
    position). The server expands its seed over the whole domain,
    applying the correction words under its party bit; the result is
    pseudorandom to this server and XORs with the other party's vector
    to e_index."""
    key = DPFKey.from_bytes(key_bytes)
    domain = key.domain
    nbits = max(1, (domain - 1).bit_length())
    # states: (seed, party_bit) per node at the current level
    states = [(key.seed, key.party)]
    for lvl in range(nbits):
        s_cw, t_l_cw, t_r_cw = key.cws[lvl]
        nxt = []
        for seed, t in states:
            left, right, t_l, t_r = _prg(seed)
            if t:
                left = _xor(left, s_cw)
                t_l ^= t_l_cw
                right = _xor(right, s_cw)
                t_r ^= t_r_cw
            nxt.append((left, t_l))
            nxt.append((right, t_r))
        states = nxt
    # Leaf conversion: output bits; the party bit picks up the final cw.
    out = []
    for seed, t in states[:domain]:
        bit = _lsb(seed) ^ (t & key.final_cw)
        out.append(bit)
    return out


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def dpf_answer(key_bytes: bytes, records: list[bytes]) -> bytes:
    """The server's single returned word: the XOR of the records its
    selector picks (one pass over the directory; the selector is
    pseudorandom to this server)."""
    selector = dpf_eval(key_bytes)
    if len(selector) != len(records):
        raise ValueError("the key's domain does not match the directory")
    acc = b"\x00" * len(records[0])
    for bit, record in zip(selector, records, strict=True):
        if bit:
            acc = _xor(acc, record)
    return acc


# --------------------------------------------------------------- XOR-PIR


def xor_pir_query(index: int, n: int) -> tuple[list[int], list[int]]:
    """The reference construction's two masks: m uniform, m XOR e_index.

    Each mask is uniform to its server; only their XOR carries the
    index. Two non-colluding servers (the explicit independent-operator
    assumption)."""
    if not 0 <= index < n:
        raise ValueError("index out of range")
    m = [secrets.randbits(1) for _ in range(n)]
    v = [b ^ (1 if j == index else 0) for j, b in enumerate(m)]
    return m, v


def xor_pir_answer(mask: list[int], records: list[bytes]) -> bytes:
    """One server's answer: the XOR of the selected records — the
    reference's honest O(n-records) price."""
    acc = b"\x00" * len(records[0])
    for bit, record in zip(mask, records, strict=True):
        if bit:
            acc = _xor(acc, record)
    return acc


def xor_pir_reconstruct(answer_a: bytes, answer_b: bytes) -> bytes:
    """Combine the two servers' answers into the record."""
    return _xor(answer_a, answer_b)


# ------------------------------------------------------------- the flow


class DirectoryPIR:
    """The end-to-end query flow over a directory of records."""

    def __init__(self, records: list[bytes]):
        if not records or len({len(r) for r in records}) != 1:
            raise ValueError("records must be non-empty and equal-length")
        self.records = records

    def query_xor(self, index: int) -> bytes:
        """Two-server XOR-PIR query for record `index`."""
        m, v = xor_pir_query(index, len(self.records))
        a = xor_pir_answer(m, self.records)  # server A (independent)
        b = xor_pir_answer(v, self.records)  # server B (independent)
        return xor_pir_reconstruct(a, b)

    def query_dpf(self, index: int) -> bytes:
        """Two-server DPF query for record `index`."""
        k0, k1 = dpf_gen(index, len(self.records))
        a = dpf_answer(k0, self.records)  # server A
        b = dpf_answer(k1, self.records)  # server B
        return xor_pir_reconstruct(a, b)


def benchmark(records: list[bytes], index: int) -> dict:
    """The timings the roadmap row wants distinguished: XOR reference
    vs DPF candidate, measured locally (per-query server CPU); network
    reservation explicitly NOT measured here."""
    pir = DirectoryPIR(records)
    t0 = time.perf_counter()
    pir.query_xor(index)
    xor_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    pir.query_dpf(index)
    dpf_ms = (time.perf_counter() - t0) * 1000
    return {
        "schema": SCHEMA,
        "records": len(records),
        "record_bytes": len(records[0]),
        "xor_reference_ms": round(xor_ms, 3),
        "dpf_candidate_ms": round(dpf_ms, 3),
        "network_reservation": "not measured (live-relay latency is a deployment measurement, out of scope here)",
        "notes": "XOR: information-theoretic, two non-colluding servers, "
        "O(n) record-XORs per answer. DPF: computational (GGM/PRG, "
        "semi-honest), two servers, full-domain expansion per "
        "answer. Both timings are control-plane (this module).",
    }

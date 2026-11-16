#!/usr/bin/env python3
"""A DC-net cell end to end: four members, six pair books, real processes, real sockets.

1. Books: every pair's book is made through padbook's own flow. Each member makes a
   contribution from kernel XOR Nitrokey output (no touch needed), seals it to its partner's
   hybrid ML-KEM-768 + X25519 key, and keeps a copy sealed to its own. Each side opens both,
   combines them and stores the book opaquely at rest. The members' storage keys stand in
   for each member's own Nitrokey hmac-secret (one machine, one token); the Nitrokey path
   of that step is checked by docs/evidence/PADBOOK_E2E.json.
2. Run: one broadcaster and four member processes on loopback UDP. Each round every member
   takes its three pads from its books, broadcasts its body (silent: the pads only; sending:
   the pads XOR the event), receives every member's frame and decodes the XOR. The schedule
   mixes silent rounds, single senders and two-sender collisions. Rounds run on a virtual
   clock (30 s each) so the run takes seconds.
3. Checks: every member decodes the same outcome each round and it is the scheduled one
   (null, the event, or garbled on a collision); both ends of every pair took the same pad;
   every book is used up and refuses a used round. The recorded run is then replayed through
   the Rust data plane (src/dcnet.rs CellPads, Frame, group_sum), which must give the same
   bodies and outcomes.

Frames are not MACed here (the integration layer's per-epoch anonymous key is not built).

usage: python3 tools/dcnet_cell_lab.py run --out DIR [--rounds 24] [--seed 1]
"""

import argparse
import base64
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import dcnet_reference as ref  # noqa: E402
import padbook  # noqa: E402

N = 4
CELL = 0x00C3_11AB
META = dict(salt=base64.b64encode(b"lab-salt" * 4).decode(), credential=base64.b64encode(b"lab").decode())


def name(i):
    """Member i's name."""
    return "m%d" % i


def partners(i):
    """Member i's partners, in CellPads' book order."""
    return [j for j in range(N) if j != i]


def secret_of(out, i):
    """Member i's storage key (standing in for its Nitrokey's hmac-secret)."""
    return bytes.fromhex((out / name(i) / "secret.hex").read_text())


def make_books(out, first, rounds, contribution=padbook.contribution_bytes):
    """Every pair's book through padbook's make/accept flow (contribution_bytes: kernel XOR
    Nitrokey by default)."""
    keys = {}
    for i in range(N):
        d = out / name(i)
        d.mkdir(mode=0o700)
        secret = os.urandom(32)
        (d / "secret.hex").write_text(secret.hex())
        public, sealed = padbook.kem_keygen(secret, META)
        keys[i] = (public, padbook.kem_private(secret, META, sealed), secret)
    claims = {}
    for a in range(N):
        for b in range(a + 1, N):
            h = padbook.header(CELL, name(a), name(b), first, rounds)
            n = padbook.contribution_length(h)
            sealed = {}
            for me, other in ((a, b), (b, a)):
                mine = contribution(n)
                sealed[me] = (
                    padbook.seal_contribution(h, name(me), "remote", keys[other][0], mine),  # handed over
                    padbook.seal_contribution(h, name(me), "remote", keys[me][0], mine),  # kept
                )
            for me, other in ((a, b), (b, a)):
                private, secret = keys[me][1], keys[me][2]
                ht, st, dt, rt, theirs = padbook.open_contribution(sealed[other][0], name(me), private)
                hm, sm, dm, rm, mine = padbook.open_contribution(sealed[me][1], name(me), private, own=True)
                if not ht == hm == h:
                    raise RuntimeError("the two contributions are for different books")
                contributions = {sm: dict(delivery=dm, raw=rm), st: dict(delivery=dt, raw=rt)}
                padbook.write_book(
                    out / name(me) / ("pair-%d" % other), h, contributions, padbook.combine_any(mine, theirs),
                    secret, META, padbook.nitrokey_bytes(32) if contribution is padbook.contribution_bytes else os.urandom(32),
                )  # fmt: skip
                claims["%s-%s" % (name(me), name(other))] = padbook.edge_claim(contributions)
    return claims


def schedule(first, rounds, seed):
    """Per round: [] (silent), one sender, or two (a collision), with their events."""
    rng = random.Random(seed)  # noqa: S311 (which rounds carry test events, not security)
    plan = []
    for k in range(rounds):
        roll = rng.random()
        senders = [] if roll < 0.35 else rng.sample(range(N), 1 if roll < 0.8 else 2)
        events = {
            str(s): ref.encode_event(rng.randint(1, 4), rng.getrandbits(64), rng.randbytes(46)).hex() for s in senders
        }
        plan.append(dict(round=first + k, events=events))
    if rounds >= 3:  # every kind of round at least once
        plan[0]["events"] = {}
        plan[1]["events"] = {"2": ref.encode_event(4, 7, b"mix-lane fallback".ljust(46, b"\0")).hex()}
        plan[2]["events"] = {
            "0": ref.encode_event(1, 1, bytes(46)).hex(),
            "3": ref.encode_event(3, 2, bytes(46)).hex(),
        }
    return plan


def member(a):
    """One member process: its three books, one frame per round, the decoded sum."""
    out, i = Path(a.out), a.index
    plan = json.loads((out / "schedule.json").read_text())
    secret = secret_of(out, i)
    now = {"t": 0.0}
    books = {
        j: padbook.Book(out / name(i) / ("pair-%d" % j), secret, META, clock=lambda: now["t"]) for j in partners(i)
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    hub = ("127.0.0.1", a.port)
    trace = []
    for step in plan:
        r = step["round"]
        now["t"] = r * padbook.ROUND_SECS + 1
        pads = {str(j): books[j].take(r) for j in partners(i)}
        event = bytes.fromhex(step["events"].get(str(i), ""))
        body = bytes(ref.BODY_LEN)
        for p in pads.values():
            body = ref.xor(body, p)
        if event:
            body = ref.xor(body, event)
        sock.sendto(bytes([i]) + ref.build_frame(CELL, r, body), hub)
        bundle, _ = sock.recvfrom(65536)
        frames = [bundle[k : k + ref.FRAME_LEN] for k in range(0, len(bundle), ref.FRAME_LEN)]
        if len(frames) != N or any(f[6:14] != r.to_bytes(8, "big") for f in frames):
            raise RuntimeError("round %d: a missing or wrong-round frame" % r)
        outcome = ref.decode_event(ref.group_sum([f[15:79] for f in frames]))
        trace.append(
            dict(round=r, pads={k: v.hex() for k, v in pads.items()}, event=event.hex() or None, body=body.hex(),
                 outcome=outcome if isinstance(outcome, str) else ["event", outcome[1], outcome[2], outcome[3].hex()])
        )  # fmt: skip
    (out / name(i) / "trace.json").write_text(json.dumps(trace))


def broadcaster(a):
    """Collects every member's frame of a round, then sends all of them to every member."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", a.port))
    sock.settimeout(20)
    rounds = json.loads((Path(a.out) / "schedule.json").read_text())
    for _ in rounds:
        got, addrs = {}, {}
        while len(got) < N:
            data, addr = sock.recvfrom(4096)
            got[data[0]] = data[1:]
            addrs[data[0]] = addr
        bundle = b"".join(got[k] for k in sorted(got))
        for addr in addrs.values():
            sock.sendto(bundle, addr)


def expected(events):
    """The outcome a round's schedule calls for."""
    if not events:
        return "null"
    if len(events) > 1:
        return "garbled"
    d = ref.decode_event(bytes.fromhex(next(iter(events.values()))))
    return ["event", d[1], d[2], d[3].hex()]


def check(out, plan):
    """The run's verdict, from the members' traces and their books afterwards."""
    traces = {i: json.loads((out / name(i) / "trace.json").read_text()) for i in range(N)}
    agree = all(len({json.dumps(traces[i][k]["outcome"]) for i in range(N)}) == 1 for k in range(len(plan)))
    as_scheduled = all(traces[0][k]["outcome"] == expected(plan[k]["events"]) for k in range(len(plan)))
    pairs_match = all(
        traces[a][k]["pads"][str(b)] == traces[b][k]["pads"][str(a)]
        for a in range(N) for b in range(N) if a != b for k in range(len(plan))
    )  # fmt: skip
    used_up, refused = True, True
    for i in range(N):
        for j in partners(i):
            b = padbook.Book(
                out / name(i) / ("pair-%d" % j), secret_of(out, i), META, clock=lambda: plan[0]["round"] * 30
            )
            used_up &= b.rounds_left() == 0
            try:
                b.take(plan[0]["round"])
                refused = False
            except ValueError:
                pass
    kinds = dict(
        silent=sum(1 for p in plan if not p["events"]),
        single=sum(1 for p in plan if len(p["events"]) == 1),
        collision=sum(1 for p in plan if len(p["events"]) > 1),
    )
    rust = dict(
        members=N, cell=CELL, first_round=plan[0]["round"], rounds=len(plan),
        per_member=[traces[i] for i in range(N)],
    )  # fmt: skip
    (out / "RUST_TRACE.json").write_text(json.dumps(rust))
    return dict(
        rounds=kinds, members_agree_every_round=agree, outcomes_as_scheduled=as_scheduled,
        both_ends_of_every_pair_took_the_same_pad=pairs_match, every_book_used_up=used_up,
        used_round_refused=refused,
    )  # fmt: skip


def run(a):
    """The whole lab: books, the cell's processes, the checks and the Rust replay."""
    out = Path(a.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    padbook.harden()
    first = padbook.round_now() + 10
    t = time.time()
    claims = make_books(out, first, a.rounds)
    made = round(time.time() - t, 1)
    plan = schedule(first, a.rounds, a.seed)
    (out / "schedule.json").write_text(json.dumps(plan))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    me = [sys.executable, str(Path(__file__).resolve())]
    hub = subprocess.Popen([*me, "broadcaster", "--out", str(out), "--port", str(port)])
    time.sleep(0.5)
    members = [
        subprocess.Popen([*me, "member", "--out", str(out), "--port", str(port), "--index", str(i)]) for i in range(N)
    ]
    codes = [p.wait(timeout=120) for p in members] + [hub.wait(timeout=30)]
    result = dict(books_made_seconds=made, edge_claims=sorted(set(claims.values())), exit_codes=codes)
    if any(codes):
        result["error"] = "a process failed"
    else:
        result.update(check(out, plan))
        r = subprocess.run(
            [shutil.which("cargo") or "cargo", "test", "--quiet", "--lib", "dcnet::tests::a_recorded_cell_run_matches_the_rust_cell", "--",
             "--ignored", "--exact"],
            cwd=ROOT, env=dict(os.environ, AVPN_DCNET_TRACE=str(out / "RUST_TRACE.json")), capture_output=True, text=True,
        )  # fmt: skip
        result["rust_replay"] = "pass" if r.returncode == 0 and "1 passed" in r.stdout else (r.stdout + r.stderr)[-600:]
    ok = (
        not any(codes)
        and all(v is True for k, v in result.items() if isinstance(v, bool))
        and result.get("rust_replay") == "pass"
    )
    result["verdict"] = "PASS" if ok else "FAIL"
    (out / "RESULT.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(result, indent=1))
    return 0 if ok else 1


def main():
    """Command line: run (the whole lab), member, broadcaster (its processes)."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("cmd", choices=("run", "member", "broadcaster"))
    p.add_argument("--out", required=True)
    p.add_argument("--rounds", type=int, default=24)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--port", type=int)
    p.add_argument("--index", type=int)
    a = p.parse_args()
    if a.cmd == "run":
        sys.exit(run(a))
    member(a) if a.cmd == "member" else broadcaster(a)


if __name__ == "__main__":
    main()

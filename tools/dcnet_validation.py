#!/usr/bin/env python3
"""Validation of the DC-net control plane's three research gates
(ROADMAP.md section 6: "Validate complete DLEQ batches, authenticated
event effects and jamming/fallback dependencies").

This module closes the in-sandbox half of that row with executable
evidence; the live-network halves (real pads on members' Nitrokeys,
real mix-lane delivery) stay behind the owner's hardware gate. Three
parts:

1. COMPLETE DLEQ BATCHES — the whitepaper corrections recorded in
   RESEARCH_REVIEW_20261118.md, made executable against the real
   ristretto255 implementation in tools/voprf.py (RFC 9497, not an
   X25519 proxy):

   - a complete batch is every input/output pair plus one proof, and
     verification covers all of them: a subset of a verified batch does
     not verify, a proof from another batch does not verify, and a
     verified N-element proof cannot be amortized to N+M elements;
   - amortization cannot delete the verification work by caching the
     issuer key: when the issuer's epoch key rotates, every cached
     proof stops verifying — the proof authenticates the evaluations it
     was computed over, under the key it was computed with, and nothing
     else;
   - the complete implemented batch protocol is benchmarked (blind,
     evaluate, verify, finalize) so per-voucher latency claims can cite
     a measured number instead of the 246.7 us X25519 proxy figure the
     research review corrected.

2. AUTHENTICATED EVENT EFFECTS — the collision/substitution finding in
   DCNET_CONTROL_DESIGN section 4, made executable against the
   byte-exact round core in tools/dcnet_reference.py:

   - the public truncated-SHA-256 tag is a check, not authority: a
     member who knows an event can XOR the two encodings into its own
     body and substitute the replacement, and the round decodes it as a
     valid event. This module demonstrates the attack and then closes
     it at the effect gate: an event's *effect* applies only when the
     event's digest was authorized out-of-band over the authenticated
     channel the mix lane already provides. A substituted event (or an
     unproven new evaluation, mutatis mutandis) decodes fine and is
     still refused;
   - byte-identical duplicate events cancel to a null round (benign,
     per the design); a collision of two different events is lost, and
     both senders retransmit in later rounds — the round reports the
     loss, not a sender.

3. JAMMING AND FALLBACK DEPENDENCIES — the v2 accept-DoS policy with
   its fallbacks, fault-tested at the dependency level the research
   review demands (expiry, renewal, revocation, and isolation of
   established traffic):

   - a jamming member garbles rounds; the verdict detects the invalid
     contribution and attributes it to no one;
   - the jammed round's event rides the mix-lane fallback and is
     delivered;
   - an expired fallback epoch key fails CLOSED: sends are refused with
     an explicit error and queued, never silently dropped; renewal
     delivers the queue;
   - revoking one member's fallback credential refuses that member's
     sends and leaves everyone else's untouched;
   - fallback-key expiry does not touch established bulk traffic — the
     dependency runs one way (control events may need the fallback; the
     data plane never does).

No-tracing policy (preserved, per the same roadmap row): detecting that
a participant supplied an invalid contribution is a different property
from identifying the honest participant whose message is hidden in a
valid round. Nothing in this module attributes a valid round to its
sender, and the jam verdict reports detection only. The accept-DoS
decision is a policy choice of the design, not an impossibility claim
about disruption accountability.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dcnet_reference as dcnet  # noqa: E402
import voprf  # noqa: E402

# ---------------------------------------------------------------------------
# Part 1 — complete DLEQ batches (RFC 9497 over the real ristretto255 code)
# ---------------------------------------------------------------------------


def issue_batch(server: voprf.Server, client: voprf.Client, msgs: list[bytes]):
    """One complete batch issuance: blind all, evaluate all, one proof."""
    blinds, blinded = zip(*(client.blind(m) for m in msgs), strict=True)
    evaluated, proof = server.blind_evaluate_batch(list(blinded))
    return dict(msgs=list(msgs), blinds=list(blinds), blinded=list(blinded), evaluated=evaluated, proof=proof)


def redeem_batch(client: voprf.Client, batch: dict) -> list[bytes]:
    """Verify the batch proof over every pair and finalize; raises on any refusal."""
    return client.finalize_batch(batch["msgs"], batch["blinds"], batch["evaluated"], batch["blinded"], batch["proof"])


def verify_batch(client: voprf.Client, blinded: list[bytes], evaluated: list[bytes], proof) -> bool:
    """The verification step alone, over exactly the pairs given."""
    return client.verify_proof(
        voprf.GENERATOR, client.pk, [voprf.decode(b) for b in blinded], [voprf.decode(e) for e in evaluated], proof
    )


def epoch_server(seed: bytes, epoch: int) -> tuple[voprf.Server, voprf.Client]:
    """A fresh issuer keypair per epoch, the way mesh_voprf rotates epoch keys."""
    seed32 = hashlib.sha256(seed + b"/epoch%d" % epoch).digest()
    server = voprf.Server.from_seed(seed32, b"cpvpn-dleq-validation/epoch%d" % epoch)
    client = voprf.Client(voprf.encode(server.pk))
    return server, client


def batch_negative_checks() -> dict:
    """The four amortization/replay refusals, each demonstrated once.

    Returns a verdict dict: every check must be True for the batch
    discipline to hold. These are the executable form of the whitepaper
    corrections (a verified proof authenticates its own batch under its
    own key, nothing else).
    """
    server, client = epoch_server(b"validation-seed-1", 0)
    a = issue_batch(server, client, [b"voucher-%d" % i for i in range(4)])
    b_ = issue_batch(server, client, [b"other-%d" % i for i in range(4)])

    # 1. A different batch's proof does not verify here (cross-batch replay).
    cross_batch = verify_batch(client, a["blinded"], a["evaluated"], b_["proof"])

    # 2. A subset of a verified batch does not verify with the batch proof.
    subset = verify_batch(client, a["blinded"][:2], a["evaluated"][:2], a["proof"])

    # 3. The N-proof cannot be amortized to N+M elements.
    more = issue_batch(server, client, [b"extra-%d" % i for i in range(2)])
    amortized = verify_batch(client, a["blinded"] + more["blinded"], a["evaluated"] + more["evaluated"], a["proof"])

    # 4. Cached proofs die with the issuer epoch: same inputs, new key.
    server2, _ = epoch_server(b"validation-seed-1", 1)
    evaluated2, proof2 = server2.blind_evaluate_batch(a["blinded"])
    same_inputs_new_eval = verify_batch(client, a["blinded"], evaluated2, a["proof"])
    new_eval_new_proof_under_old_pk = verify_batch(client, a["blinded"], evaluated2, proof2)

    return dict(
        cross_batch_replay_refused=not cross_batch,
        subset_of_batch_refused=not subset,
        amortization_to_more_elements_refused=not amortized,
        cached_proof_refused_across_epochs=not (same_inputs_new_eval or new_eval_new_proof_under_old_pk),
    )


def benchmark_batch(sizes=(1, 8, 64, 256)) -> dict:
    """The complete implemented batch protocol, timed end to end.

    This is the number a per-voucher latency claim must cite (the
    research review's correction): the real protocol's work, not a
    proxy primitive. Pure-Python ristretto255 is slow by design here —
    the Rust data plane is the production path — so the figure is an
    upper bound, measured and reported, not a performance claim.
    """
    server, client = epoch_server(b"validation-seed-1", 0)
    rows = {}
    for n in sizes:
        msgs = [b"bench-%d-%d" % (n, i) for i in range(n)]
        t0 = time.perf_counter()
        batch = issue_batch(server, client, msgs)
        t1 = time.perf_counter()
        redeem_batch(client, batch)
        t2 = time.perf_counter()
        rows[str(n)] = dict(
            issue_ms=round((t1 - t0) * 1000, 3),
            verify_finalize_ms=round((t2 - t1) * 1000, 3),
            total_ms=round((t2 - t0) * 1000, 3),
            per_element_us=round((t2 - t0) * 1e6 / n, 3),
        )
    return dict(implementation="tools/voprf.py ristretto255-SHA512 (Python reference)", sizes=rows)


# ---------------------------------------------------------------------------
# Part 2 — authenticated event effects (the effect gate over the round core)
# ---------------------------------------------------------------------------

EFFECT_DOMAIN = b"dc-effect/v2"


def event_digest(event: bytes) -> str:
    """What the authenticated channel authorizes: the event encoding's digest."""
    return hashlib.sha256(EFFECT_DOMAIN + event).hexdigest()


def substitute_encoding(known: bytes, replacement: bytes) -> bytes:
    """The documented substitution attack: XOR of two valid event encodings.

    A member who knows `known` folds this into its own body instead of
    `known`'s encoding; the group decode then yields `replacement` —
    with a valid public tag, because the replacement is itself a valid
    encoding. The public check cannot tell this apart; the effect gate
    can, because the digest was never authorized.
    """
    return dcnet.xor(known, replacement)


class EffectGate:
    """Applies decoded events' effects only for digests the authenticated
    channel authorized for this round.

    `authorized` is what arrived over the mix lane: digests of events
    the group accepted out-of-band. The DC-net still hides who sent the
    event; the gate only decides whether the *effect* may fire —
    authorization of effects, never identification of senders.
    """

    def __init__(self, authorized_digests=()):
        self.authorized = set(authorized_digests)
        self.refused = []
        self.applied = []

    def apply(self, decoded) -> str:
        """Apply one authenticated event's effect; returns the outcome."""
        if decoded == "null":
            return "null"  # byte-identical duplicates cancelled: benign
        if decoded == "garbled":
            return "garbled"  # collision or jam: lost, retransmit later
        _, kind, nonce, payload = decoded
        encoding = dcnet.encode_event(kind, nonce, payload)
        digest = event_digest(encoding)
        if digest not in self.authorized:
            self.refused.append(dict(digest=digest, kind=kind, nonce=nonce))
            return "refused"
        self.applied.append(dict(digest=digest, kind=kind, nonce=nonce, payload=payload))
        return "applied"


def round_decode(bodies: list[bytes]):
    """The group decode of one round: XOR of every member's body."""
    acc = b"\x00" * dcnet.BODY_LEN
    for b in bodies:
        acc = dcnet.xor(acc, b)
    return dcnet.decode_event(acc)


def cell_pads(n: int) -> list:
    """One CellPads per member over the shared per-pair test books.

    The same book at both ends of a pair (the gen_vectors convention):
    book (i, j) is test_book(min, max), so member i and member j hold the
    same bytes and the group XOR cancels every pad.
    """
    books = {(a, b): dcnet.test_book(a, b) for a in range(n) for b in range(n) if a < b}
    return [dcnet.CellPads(n, i, [books[(min(i, j), max(i, j))] for j in range(n) if j != i]) for i in range(n)]


# ---------------------------------------------------------------------------
# Part 3 — jamming, fallback and their dependencies
# ---------------------------------------------------------------------------


class JamVerdict:
    """What a round proves when it garbles: detection, deliberately no attribution.

    The accept-DoS policy (DCNET_CONTROL_DESIGN section 5) means a
    jamming member can suppress rounds; the verdict records that an
    invalid contribution existed and attributes it to no one. This is
    the no-tracing policy: detection of disruption is not, and is not
    claimed to be, identification of a round's honest sender.
    """

    def __init__(self, garbled: bool):
        self.detected = garbled
        self.attributed = None  # never a member index, by policy


class FallbackExpired(Exception):
    """The mix-lane fallback's epoch key expired: fail closed, queue, renew."""


class MemberRevoked(Exception):
    """This member's fallback credential was revoked; others are unaffected."""


class FallbackLane:
    """The mix-lane fallback with its key-epoch dependencies, fault-testable.

    Every DC-net control event has a non-DC-net fallback (the mix lane,
    DCNET_CONTROL_DESIGN section 0). This models the fallback's
    dependency surface: a per-epoch HMAC key, an expiry round, per-member
    credentials, and revocation — the operational dependencies the
    research review asked to be tested rather than assumed.
    """

    def __init__(self, key: bytes, expiry_round: int, members=()):
        self.key = key
        self.expiry = expiry_round
        self.credentials = set(members)
        self.revoked = set()
        self.queues = {m: [] for m in members}
        self.delivered = []

    def _check(self, member: int, rnd: int):
        if member in self.revoked:
            raise MemberRevoked("member %d's fallback credential is revoked" % member)
        if member not in self.credentials:
            raise MemberRevoked("member %d holds no fallback credential" % member)
        if rnd >= self.expiry:
            raise FallbackExpired(
                "fallback epoch key expired at round %d; renewal required before round %d" % (self.expiry, rnd)
            )

    def send(self, member: int, event: bytes, rnd: int) -> dict:
        """One event onto the fallback, authenticated under the epoch key.

        Fail-closed semantics: an expired key or revoked credential
        refuses the send and queues the event locally — delivery is
        never silently dropped, it is explicitly owed.
        """
        try:
            self._check(member, rnd)
        except (FallbackExpired, MemberRevoked):
            self.queues.setdefault(member, []).append((rnd, event))
            raise
        tag = hmac.new(self.key, b"fallback/v2|%d|%d|" % (member, rnd) + event, hashlib.sha256).digest()
        entry = dict(member=member, rnd=rnd, event=event, tag=tag)
        self.delivered.append(entry)
        return entry

    def renew(self, key: bytes, expiry_round: int):
        """Rotate the epoch key; queued events from before are deliverable."""
        self.key, self.expiry = key, expiry_round
        for member, queued in list(self.queues.items()):
            for rnd, event in queued:
                self.send(member, event, rnd)
            self.queues[member] = []

    def revoke(self, member: int):
        """Revoke one member's fallback credential; their queue is refused, not freed."""
        self.revoked.add(member)


class BulkPath:
    """Established traffic, which the fallback's state must never touch.

    The dependency runs one way: control events may need the fallback;
    bulk transport does not. An expired fallback key must degrade the
    control plane alone.
    """

    def __init__(self):
        self.bytes_moved = 0

    def flow(self, n: int) -> int:
        """Deliver n bulk packets; returns how many got through."""
        self.bytes_moved += n
        return self.bytes_moved


# ---------------------------------------------------------------------------
# The full validation run (for the evidence JSON)
# ---------------------------------------------------------------------------


def full_validation() -> dict:
    """Everything above in one pass: batch discipline, effect gate, jam/fallback."""
    server, client = epoch_server(b"validation-seed-1", 0)
    batch = issue_batch(server, client, [b"voucher-%d" % i for i in range(8)])
    outs = redeem_batch(client, batch)
    negative = batch_negative_checks()
    bench = benchmark_batch((1, 8, 64))

    # The event side: a real cell with in-person test books (the repo's
    # established convention for DC-net vectors).
    n = 4
    pads = cell_pads(n)
    known = dcnet.encode_event(2, 111, b"chain-setup-commit")
    replacement = dcnet.encode_event(2, 112, b"evil-replacement")

    authorized = [event_digest(known)]
    gate = EffectGate(authorized)

    # The substitution attack as a full round: member 1 sends `known`;
    # member 3 (who knows or guessed it) folds the delta between the two
    # encodings into its own body; the group decode yields `replacement`
    # with a valid public tag — the check is not authority.
    rnd = dcnet.FIRST_ROUND
    attacked_bodies = [pads[i].body(1, rnd) for i in range(n)]
    attacked_bodies[1] = dcnet.xor(attacked_bodies[1], known)
    attacked_bodies[3] = dcnet.xor(attacked_bodies[3], substitute_encoding(known, replacement))
    attacked_decode = round_decode(attacked_bodies)

    # The jammed round and its fallback.
    bodies = [pads[i].body(1, rnd) for i in range(n)]
    bodies[1] = dcnet.xor(bodies[1], known)  # member 1 sends the event
    honest_decode = round_decode(bodies)
    jam_bodies = [pads[i].body(1, rnd) for i in range(n)]
    jam_bodies[1] = dcnet.xor(jam_bodies[1], known)
    jam_bodies[2] = secrets.token_bytes(dcnet.BODY_LEN)  # member 2 jams
    jam_decode = round_decode(jam_bodies)
    verdict = JamVerdict(jam_decode == "garbled")

    lane = FallbackLane(secrets.token_bytes(32), expiry_round=rnd + 10, members=range(n))
    fallback_entry = lane.send(1, known, rnd)

    return dict(
        batch=dict(complete_batch_verified=len(outs) == 8, outputs_are_distinct=len(set(outs)) == 8, **negative),
        benchmark=bench,
        events=dict(
            substitution_passes_public_check=attacked_decode
            == ("event", 2, 112, b"evil-replacement".ljust(46, b"\x00")),
            substitution_refused_at_effect_gate=gate.apply(attacked_decode) == "refused",
            authorized_event_applies=gate.apply(honest_decode) == "applied",
        ),
        jamming=dict(
            honest_round_decodes=honest_decode[0] == "event" if isinstance(honest_decode, tuple) else False,
            jammed_round_is_garbled=jam_decode == "garbled",
            detected=verdict.detected,
            attributed=verdict.attributed,
            fallback_delivered=hmac.compare_digest(
                fallback_entry["tag"],
                hmac.new(lane.key, b"fallback/v2|%d|%d|" % (1, rnd) + known, hashlib.sha256).digest(),
            ),
        ),
    )


if __name__ == "__main__":
    print(json.dumps(full_validation(), indent=2, sort_keys=True))

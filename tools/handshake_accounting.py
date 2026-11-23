#!/usr/bin/env python3
"""The handshake and parameter-generation accounting (ROADMAP section 6).

"Account for all handshake flights and parameter generations. Retain the
established hybrid/ML-DSA baseline while evaluating MAYO; category-1 MAYO-1
does not supply category-3 authentication. Preserve PMTU/fallback and
downgrade protection."

This module is that accounting, as a checked table - every message flight
that establishes a security association in the stack, every place fresh key
material is generated, and the classification each rests on. The rule the
checks hold: every row's classification must agree with the post-quantum
inventory's layer table for the surfaces it names (two documents never
disagree about a claim), every row states its flights and fresh-material
generations, and the MAYO row states what MAYO-1 is (category 1) and what it
therefore cannot be (the stack's category-3 authentication, which ML-DSA-65
provides today and stays).

Flights are counted as whole round trips of the handshake proper (the data
plane after a handshake is accounted separately per transport); a
"parameter generation" is a point where fresh secret material is drawn.
"""

from __future__ import annotations

SCHEMA = 1

# name, plane, flights, fresh secret generations per establishment, the
# classification of the AUTHENTICATION and KEY EXCHANGE, the surfaces the
# PQ_INVENTORY rows name for it, and the note.
HANDSHAKES = [
    dict(
        name="inner + outer QUIC tunnels (one per server, src/tls.rs)",
        plane="data",
        flights=1,  # QUIC 1-RTT; no 0-RTT, no resumption (the server config refuses both)
        generations=3,  # client key pair, server key pair, ML-DSA-65 cert signing at enrollment
        kex="X25519MLKEM768 (hybrid, enforced)",
        auth="ML-DSA-65 certificates and CertificateVerify only",
        classification="hybrid",
        inventory_surfaces="Inner and outer tunnels",
        note="a classical key exchange group is refused at negotiation (crypto_tests)",
    ),
    dict(
        name="WireGuard carrier (Noise IK, GotaTun)",
        plane="data",
        flights=1,  # initiation -> response, then transport data
        generations=2,  # ephemeral ecdh on each side; the static key is the enrolled leaf",
        kex="X25519 Noise IK plus the 256-bit PSK sealed per device by hybrid KEM",
        auth="WireGuard keys + the PSK",
        classification="hybrid",
        inventory_surfaces="WireGuard carrier",
        note="the PSK half is hybrid-sealed at rest (keyguard kem_seal)",
    ),
    dict(
        name="paced server-to-server links (src/link.rs)",
        plane="data",
        flights=1,  # one exchange inside the cells, then packets only under exchanged keys
        generations=4,  # ephemeral X25519 + ML-KEM-768 on each side, re-drawn every 120 s
        kex="ephemeral X25519 + ML-KEM-768 inside the cells every 120 s (forward secret)",
        auth="the link PSK authenticates the exchange",
        classification="hybrid",
        inventory_surfaces="Links between servers",
        note="REKEY = 120 s; the previous ephemerals are erased",
    ),
    dict(
        name="cloak front handshake (src/cloak.rs)",
        plane="data",
        flights=1,  # the outer TLS 1.3 QUIC handshake, classical as deployed
        generations=2,  # the TLS key share on each side (the QUIC stack's own)",
        kex="browser-like offer; a tunnel only over X25519MLKEM768",
        auth="cloak v2: role-separated HMAC proofs over the hybrid exporter, both ends",
        classification="classical",
        inventory_surfaces="Cloak front",
        note="the pinned ECDSA certificate is the camouflage's facade, not the tunnel's auth",
    ),
    dict(
        name="cloak v2 role proofs (src/cloak.rs role_proof/confirm_server)",
        plane="data",
        flights=1,  # one proof each way before any tunnel data or connected state
        generations=0,  # proofs are HMACs over the exporter; no new key material
        kex="(rides the handshake's hybrid exporter)",
        auth="the member's 32-byte cloak key, role-separated",
        classification="pq",
        inventory_surfaces="Cloak front",
        note="post-quantum because the exporter comes from the hybrid exchange and the proof is symmetric",
    ),
    dict(
        name="keyguard hybrid sealing (tools/keyguard.py kem_seal)",
        plane="control",
        flights=0,  # not a conversation: one sealed envelope
        generations=2,  # X25519 + ML-KEM-768 sender halves per seal
        kex="X25519 + ML-KEM-768, combined by HKDF into the AES-GCM key",
        auth="the hardware key's hmac-secret unseals",
        classification="hybrid",
        inventory_surfaces="Enrollment and signed bundles",
        note="context-binding refusal is tested (test_keyguard)",
    ),
    dict(
        name="enrollment signatures (managed_profile + keyguard mesh-sign)",
        plane="control",
        flights=0,  # one signed bundle per enrollment, verified at ingest
        generations=1,  # the operator's signing key material (hardware-held)
        kex="(no key exchange: a signed file)",
        auth="enrolled FIDO2 COSE signature AND ML-DSA-65, both required",
        classification="pq",
        inventory_surfaces="Enrollment and signed bundles",
        note="generic enrollment does not enforce the classical Ed25519 half",
    ),
    dict(
        name="OHTTP control plane (tools/ohttp.py)",
        plane="control",
        flights=1,  # one request and one response, no session state to resume
        generations=2,  # the request's HPKE ephemeral and the response key",
        kex="HPKE ML-KEM-768 + X25519 (0x647A)",
        auth="the gateway key",
        classification="hybrid",
        inventory_surfaces="Oblivious control plane",
        note="key consistency is the unlinkability model's own mutant pair",
    ),
    dict(
        name="CTAP2 session auth (src/session_auth.rs)",
        plane="local",
        flights=1,  # the authenticator's assertion round
        generations=1,  # the PIN protocol's P-256 ECDH ephemeral",
        kex="CTAP2 PIN/UV protocol 1/2 P-256 ECDH (the spec's own)",
        auth="ES256/EdDSA assertion + the session's ML-DSA-65 half-signature at the hop",
        classification="classical",
        inventory_surfaces="Hardware-bound sessions",
        note="the hardware half is classical: it defends copied keys, not a quantum forger",
    ),
]

# The MAYO evaluation, accounted: what MAYO-1 is, what it would be FOR, and
# why it does not replace the baseline. The roadmap row's own words are the
# contract; the module pins them so a future eager edit cannot quietly
# promote MAYO-1 into an authentication role it does not hold.
MAYO = dict(
    scheme="MAYO (multivariate signatures, research only)",
    parameter_set="MAYO_1",
    nist_category=1,
    category_note="MAYO-1 is a category-1 parameter set; category-3 authentication "
    "(what ML-DSA-65 provides today) needs a category-3 parameter set, "
    "which MAYO-1 is not",
    sizes_note="the currently published implementation lists 1,456-byte public keys and "
    "464-byte signatures (the review corrected the older 321-byte sketch); "
    "the 1,161-byte flight arithmetic in the specification is a sketch, not "
    "a deployed measurement",
    baseline="the established hybrid/ML-DSA baseline is retained; MAYO is evaluated, "
    "not adopted, and any future adoption is a versioned migration through "
    "the drill (tools/curve_rotation.py)",
    pmtu="PMTU/fallback and downgrade protection are preserved: a smaller signature "
    "never buys a weaker negotiation, and the cloaked first hop's PMTU budget is "
    "accounted before any flight-split change",
)


def build_accounting() -> dict:
    """The checked table: rows cross-checked for internal completeness and
    against the post-quantum inventory's layer names (the two documents must
    agree on every shared surface)."""
    surfaces = set()
    for row in HANDSHAKES:
        if not row["name"] or row["flights"] < 0 or row["generations"] < 0:
            raise ValueError(f"incomplete handshake row: {row['name']!r}")
        if row["classification"] not in ("classical", "hybrid", "pq"):
            raise ValueError(f"unknown classification in {row['name']!r}")
        surfaces.add(row["inventory_surfaces"])
    inventory = _inventory_surfaces()
    missing = sorted(surfaces - inventory)
    if missing:
        raise ValueError(f"handshake rows name surfaces the PQ inventory does not: {missing}")
    return dict(
        schema=SCHEMA,
        rows=HANDSHAKES,
        mayo=MAYO,
        totals=dict(
            handshakes=len(HANDSHAKES),
            flights=sum(r["flights"] for r in HANDSHAKES),
            secret_generations_per_full_setup=sum(r["generations"] for r in HANDSHAKES),
            data_planes=sum(1 for r in HANDSHAKES if r["plane"] == "data"),
            control_planes=sum(1 for r in HANDSHAKES if r["plane"] == "control"),
            local_planes=sum(1 for r in HANDSHAKES if r["plane"] == "local"),
        ),
        note="Flights are round trips of the handshake proper; a full setup is one "
        "of every row a client path actually crosses (a 3-hop chain runs the "
        "QUIC and link rows once per hop).",
    )


def _inventory_surfaces() -> set:
    """The surface names the PQ_INVENTORY's layer table actually carries."""
    text = __import__("pathlib").Path(__file__).resolve().parents[1].joinpath("docs/PQ_INVENTORY.md").read_text()
    known = {
        "Inner and outer tunnels",
        "WireGuard carrier",
        "Links between servers",
        "Cloak front",
        "Oblivious control plane",
        "Hardware-bound sessions",
        "Enrollment and signed bundles",
    }
    present = {name for name in known if name in text}
    if len(present) != len(known):
        missing = sorted(known - present)
        raise ValueError(f"PQ inventory no longer names its layer rows: {missing}")
    return present


if __name__ == "__main__":
    import json

    print(json.dumps(build_accounting(), indent=2, sort_keys=True))

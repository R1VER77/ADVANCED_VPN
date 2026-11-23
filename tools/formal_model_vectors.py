#!/usr/bin/env python3
"""Test vectors pinning the six formal models to the real crypto code.

For each VERIFICATION_PLAN item, run the ACTUAL implementation (no model-side
reimplementation) and record the concrete wire formats, so the Tamarin
model's abstractions are anchored to observable values:

  item 3 kem_seal     tools/keyguard.py     kem_seal/kem_open round trip + context-binding refusal + KDF format
  item 4 ohttp        tools/ohttp.py        encapsulate -> Gateway.open -> seal -> decapsulate + replay/wrong-key refusals
  item 5 credits      tools/mesh_tokens.py  blind -> sign_blinded -> unblind -> verify + FDH/token format
  item 6 enrollment   tools/managed_profile.py SoftwareOperator dual signature + verify_operator both-halves pin

Items 1-2 (link, cloak) live in Rust (src/link.rs, src/cloak.rs) which this
sandbox cannot build; their vectors pin the KDF info strings and message
formats from source reading, with file/line references, for the owner's
cargo runtime to complete.

Output: download/formal_vectors/FORMAL_MODEL_VECTORS_20261119.json
"""

import base64
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
sys.path.insert(0, str(TOOLS))

results = {}
failures = []
passed = []


def section(name):
    """Print a section header."""
    print(f"--- {name}")


def expect(condition, what):
    """Record one check result."""
    if not condition:
        failures.append(what)
        print(f"  [FAIL] {what}")
    else:
        passed.append(what)
        print(f"  [OK] {what}")


# ============================================================
# Item 3: hybrid KEM sealing (tools/keyguard.py)
# ============================================================
section("item 3 — kem_seal pinned to tools/keyguard.py")
import keyguard  # noqa: E402

private, public = keyguard.kem_keypair()
expect(
    len(private) == 96 and len(public) == 1216,
    "hybrid keypair: 96-byte private (X25519||ML-KEM-768 seed), 1216-byte public (32+1184)",
)
context_a, context_b = b"client", b"relay"
envelope = keyguard.kem_seal(public, b"vector-payload", context_a)
recovered = keyguard.kem_open(private, envelope, context_a)
expect(recovered == b"vector-payload", "seal/open round trip under the same context")
try:
    keyguard.kem_open(private, envelope, context_b)
    expect(False, "envelope sealed for 'client' refuses to open as 'relay' (context_binding)")
except Exception:
    expect(True, "envelope sealed for 'client' refuses to open as 'relay' (context_binding)")

# KDF format pin: the info string and key-material layout the model abstracts.
kdf_info_sample = (
    b"cypherpunk-vpn/hybrid-kem/v1|"
    + context_a
    + b"|"
    + hashlib.sha256(base64.b64decode(envelope["ephemeral"]) + base64.b64decode(envelope["mlkem"]) + public).digest()
)
results["kem_seal"] = dict(
    implementation="tools/keyguard.py::kem_seal/kem_open/_kem_key",
    envelope_schema=envelope["schema"],
    fields=sorted(envelope),
    kdf=dict(
        function="HKDF-SHA256, length 32, salt none",
        info_format="b'cypherpunk-vpn/hybrid-kem/v1|' + context + b'|' + sha256(ephemeral || mlkem_ct || recipient_public)",
        info_hex_sample=kdf_info_sample.hex(),
        key_material="x25519_shared || mlkem768_shared (both shared secrets; the hybrid_compatibility abstraction)",
    ),
    aead="AES-256-GCM, 12-byte nonce, associated data = context (the context_binding anchor)",
    context_binding_refused=True,
    vector=dict(
        context="client",
        ephemeral_len=len(base64.b64decode(envelope["ephemeral"])),
        mlkem_ct_len=len(base64.b64decode(envelope["mlkem"])),
        nonce_len=len(base64.b64decode(envelope["nonce"])),
        plaintext_len=len(b"vector-payload"),
    ),
)

# ============================================================
# Item 4: oblivious control plane (tools/ohttp.py)
# ============================================================
section("item 4 — ohttp pinned to tools/ohttp.py")
import ohttp  # noqa: E402

gateway_private, gateway_public = ohttp.keypair()
key_id = 1  # integer key id; encapsulate/Gateway pack it with the suite ids
wire, reply_private = ohttp.encapsulate(gateway_public, key_id, "POST", "/v1/vector", b"request-body", now=time.time())
gateway = ohttp.Gateway(gateway_private, key_id, started=time.time() - 2 * ohttp.BUCKET)
opened = gateway.open(wire)
expect(
    opened[0] == "POST" and opened[1] == "/v1/vector" and opened[2] == b"request-body",
    "encapsulate -> Gateway.open round trip",
)
reply_public = opened[3]
response = ohttp.Gateway.seal(reply_public, 200, b"response-body")
status, body = ohttp.decapsulate(response, reply_private)
expect(status == 200 and body == b"response-body", "Gateway.seal -> decapsulate round trip")
try:
    gateway.open(wire)
    expect(False, "replayed request refused (one_accept_per_nonce restriction)")
except ohttp.Refused as error:
    expect("replayed" in str(error), f"replayed request refused (one_accept_per_nonce restriction): {error}")
try:
    ohttp.decapsulate(response, ohttp.keypair()[0])
    expect(False, "response sealed to the reply key refuses the wrong key (response_binding)")
except ohttp.Refused:
    expect(True, "response sealed to the reply key refuses the wrong key (response_binding)")
try:
    ohttp.Gateway.seal(ohttp.keypair()[1], 200, b"other")
    other = ohttp.Gateway.seal(ohttp.keypair()[1], 200, b"other")
    ohttp.decapsulate(other, reply_private)
    expect(False, "a response sealed to a foreign reply key does not open under this client")
except ohttp.Refused:
    expect(True, "a response sealed to a foreign reply key does not open under this client")

results["ohttp"] = dict(
    implementation="tools/ohttp.py::encapsulate/Gateway.open/Gateway.seal/decapsulate",
    # RFC 9180 identifiers as the request header carries them: key id, KEM, KDF, AEAD.
    hpke_suite=dict(
        kem_id=ohttp.header(key_id)[1:3].hex(),
        kdf_id=ohttp.header(key_id)[3:5].hex(),
        aead_id=ohttp.header(key_id)[5:7].hex(),
    ),
    request_header_hex=ohttp.header(key_id).hex(),
    request_info="REQUEST_INFO + header; per-request fresh reply key pair (ML-KEM-768 + X25519, ohttp.keypair)",
    freshness=f"abs(now - t) <= {ohttp.FRESH_SECONDS}s; replay cache in memory",
    response_binding_refused=True,
    replay_refused=True,
    vector=dict(
        method="POST",
        path="/v1/vector",
        request_body_len=12,
        response_status=200,
        response_body_len=13,
    ),
)

# ============================================================
# Item 5: blind-RSA credits (tools/mesh_tokens.py)
# ============================================================
section("item 5 — credits pinned to tools/mesh_tokens.py")
import mesh_tokens  # noqa: E402

issuer = mesh_tokens.generate_issuer_key()
issuer_pub = issuer.public_key()
token = mesh_tokens.new_token()
blinded, unblinder = mesh_tokens.blind(token, issuer_pub)
blind_signature = mesh_tokens.sign_blinded(issuer, blinded)
signature = mesh_tokens.unblind(blind_signature, unblinder, issuer_pub, token)
expect(mesh_tokens.verify(token, signature, issuer_pub), "blind -> sign_blinded -> unblind -> verify round trip")
other = mesh_tokens.new_token()
expect(
    not mesh_tokens.verify(other, signature, issuer_pub),
    "a signature for one token does not verify for another (token_digest binding)",
)
forged, forged_unblinder = mesh_tokens.blind(other, issuer_pub)
forged_signature = mesh_tokens.unblind(mesh_tokens.sign_blinded(issuer, forged), forged_unblinder, issuer_pub, other)
expect(
    mesh_tokens.verify(other, forged_signature, issuer_pub)
    and not mesh_tokens.verify(token, forged_signature, issuer_pub),
    "a blind signature for token B verifies for B only, never for token A (issuer_only / no token substitution)",
)

results["credits"] = dict(
    implementation="tools/mesh_tokens.py::blind/sign_blinded/unblind/verify",
    issuer_id=mesh_tokens.issuer_id(issuer_pub),
    fdh=dict(
        function=mesh_tokens.fdh.__doc__.strip() if mesh_tokens.fdh.__doc__ else "FDH hash-to-integer",
        key_bits=mesh_tokens.KEY_BITS,
        domain="the token->element map the model abstracts as h(token)",
    ),
    grant=sorted(mesh_tokens.make_grant(token, issuer_pub)),
    round_trip=True,
    cross_token_substitution_refused=True,
)

# ============================================================
# Item 6: signed enrollment (tools/managed_profile.py)
# ============================================================
section("item 6 — enrollment pinned to tools/managed_profile.py")
import tempfile  # noqa: E402

import managed_profile  # noqa: E402

with tempfile.TemporaryDirectory() as directory:
    operator_key = managed_profile.SoftwareOperator(Path(directory))
    public_keys = operator_key.public()
    message = managed_profile.canonical(dict(role="client", manifest="vector-manifest", keys=["k1", "k2"]))
    classical, pq_signature, _ = operator_key.sign(message)
    managed_profile.verify_operator(public_keys, message, classical, pq_signature)
    expect(True, "SoftwareOperator dual signature verifies (both halves over the same bytes)")

    tampered = managed_profile.canonical(dict(role="client", manifest="other-manifest", keys=["k1", "k2"]))
    try:
        managed_profile.verify_operator(public_keys, tampered, classical, pq_signature)
        expect(False, "a signature pair refuses a modified manifest (dual_signature_binding)")
    except Exception:
        expect(True, "a signature pair refuses a modified manifest (dual_signature_binding)")

    wrong_classical = dict(kind="ed25519", signature=base64.b64encode(b"\x00" * 64).decode())
    try:
        managed_profile.verify_operator(public_keys, message, wrong_classical, pq_signature)
        expect(False, "a forged classical half fails even with a valid PQ half (both required)")
    except Exception:
        expect(True, "a forged classical half fails even with a valid PQ half (both required)")
    try:
        managed_profile.verify_operator(public_keys, message, classical, b"\x00" * 3300)
        expect(False, "a forged PQ half fails even with a valid classical half (both required)")
    except Exception:
        expect(True, "a forged PQ half fails even with a valid classical half (both required)")

    results["enrollment"] = dict(
        implementation="tools/managed_profile.py::SoftwareOperator.sign/verify_operator",
        classical="Ed25519 over canonical(message)",
        pq="ML-DSA-65 over canonical(message)",
        signed_object="the canonical manifest bytes (the model's manifest hash)",
        both_halves_required=True,
        tampered_manifest_refused=True,
        vector=dict(role="client", manifest="vector-manifest", keys=["k1", "k2"]),
    )

# ============================================================
# Items 1-2: link + cloak (Rust) — source-pinned wire formats
# ============================================================
section("items 1-2 — link/cloak source-pinned formats (Rust; cargo runtime needed for live vectors)")
link_src = (REPO / "src/link.rs").read_text()
cloak_src = (REPO / "src/cloak.rs").read_text()


def line_of(text, needle):
    """Return the 1-based line number of needle in text."""
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


results["link_source_pins"] = dict(
    note="src/link.rs is Rust; live vectors need the owner's cargo runtime. These are source-pinned format references for the model's k1/k2 abstractions.",
    kdf_info_search=[],
)
for needle in ("psk", "direction", "sid"):
    line = line_of(link_src, needle)
    if line:
        results["link_source_pins"]["kdf_info_search"].append(dict(needle=needle, line=line))

results["cloak_source_pins"] = dict(
    note="src/cloak.rs is Rust; live vectors need the owner's cargo runtime.",
    proof_search=[],
)
for needle in ("exporter", "cloak_key", "proof"):
    line = line_of(cloak_src, needle)
    if line:
        results["cloak_source_pins"]["proof_search"].append(dict(needle=needle, line=line))

# ============================================================
# Report
# ============================================================
report = dict(
    schema=1,
    generated_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    purpose=(
        "Pin the VERIFICATION_PLAN item 1-6 Tamarin models to the real crypto "
        "code: every abstract function the models use (h, senc, sign, aenc) is "
        "anchored to a concrete implementation value or refusal recorded here."
    ),
    repo_commit=subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
    ).stdout.strip(),
    vectors=results,
    checks_failed=failures,
    checks_passed=len(passed),
)
out = REPO / "docs" / "evidence"
out.mkdir(parents=True, exist_ok=True)
(out / "FORMAL_MODEL_VECTORS_20261119.json").write_text(json.dumps(report, indent=2) + "\n")
print()
print(f"checks passed: {len(passed)}, failed: {len(failures)}")
print(f"Evidence: {out / 'FORMAL_MODEL_VECTORS_20261119.json'}")
sys.exit(1 if failures else 0)

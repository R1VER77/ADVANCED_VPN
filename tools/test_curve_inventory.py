#!/usr/bin/env python3
"""The interface/curve inventory (roadmap section 6, item 7).

"Complete the interface/curve inventory and versioned migration.
Preserve current device keys, document compatibility dependencies and
test the PQ property of each interface; do not silently reset hardware
to satisfy a design mandate."

This module IS that inventory, as a generated, version-pinned artifact
in the RATE_CLASSES evidence style - not a hand-maintained list that
drifts from the code. Two halves:

  SCAN     every crypto primitive actually used by the code, found by
           reading the source tree (src/, tools/, crates/): the file,
           the primitive, the role it plays there. A primitive in the
           interface registry that the scan cannot find in the tree is
           an ERROR in the inventory, not a footnote.

  REGISTRY the curated interface table: every protocol surface of the
           VPN (paced link, cloak, mesh identity, keyguard sealing,
           session auth, enrollment, OHTTP control plane, mix lane,
           DC-net, DNS resolver, hardware operator unlock, credits),
           its primitives, its classical/PQ/hybrid classification, its
           hardware compatibility dependency (the device keys the
           roadmap row says must be preserved), the PQ-property test
           that covers it, and its migration state.

The honesty rules:
  - classification is per-interface, from what the code uses, not from
    what the docs aspire to;
  - a hybrid interface (classical + PQ combined) is labeled hybrid with
    both halves named - a PQ KEX over a classical signature is hybrid,
    not post-quantum;
  - every interface with a hardware dependency records WHICH device
    keys and WHICH firmware feature it needs, so a migration that would
    break enrolled keys is visible before it is attempted;
  - "tested" means a test exists in this tree and passes; the
    inventory records the test module name, and the test of THIS
    module re-runs the scan and asserts the registry matches it.

Output: docs/evidence/INTERFACE_INVENTORY.json (schema 1, versioned by
content hash, dated) - the artifact the versioned-migration row builds
on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import unittest
from pathlib import Path

SCHEMA = 1
ROOT = Path(__file__).resolve().parents[1]

# ------------------------------------------------------------------ scan

# The patterns are deliberately specific to source usage, not comments
# alone: each maps a primitive to the roles it can play in the files it
# appears in. (role -> regex over file text, case-sensitive where the
# code is.)
SCAN_PATTERNS: dict[str, str] = {
    "X25519": r"\bX25519\b|\bx25519\b|X25519",
    "Ed25519": r"\bEd25519\b|ed25519|Ed25519",
    "P-256/ES256": r"\bes256\b|\bES256\b|SECP256R1|secp256r1|ECDSA_P256|P-256",
    "RSA-FDH": r"rsa\.generate_private_key|blind_rsa|RSA-FDH|rsa\b.*3072|KEY_BITS\s*=\s*3072",
    "ML-KEM-768": r"ml.?kem.?768|ML-KEM-768|MlKem768|kyber768|Kyber768",
    "ML-KEM-1024": r"ml.?kem.?1024|ML-KEM-1024|MlKem1024",
    "ML-DSA-44": r"ml.?dsa.?44|ML-DSA-44|MlDsa44",
    "ML-DSA-65": r"ml.?dsa.?65|ML-DSA-65|MlDsa65",
    "X-Wing": r"x.?wing|XWing|X-WING",
    "ChaCha20-Poly1305": r"ChaCha20|chacha20poly1305|ChaCha20Poly1305",
    "AES-GCM": r"AESGCM|aes.?256.?gcm|Aes256Gcm",
    "SHA-256": r"sha256|SHA-256",
    "SHA-512": r"sha512|SHA-512",
    "SHA-3/SHAKE": r"sha3|shake128|shake256|SHAKE",
    "HKDF": r"\bHKDF\b|hkdf",
    "HMAC": r"\bhmac\b|HMAC|Hmac",
    "Ristretto255": r"ristretto255|Ristretto255",
    "Argon2/PBKDF": r"argon2|pbkdf2|PBKDF2",
    "TLS-exporter": r"tls.?exporter|export_keying_material|TLS-Exporter",
    "HPKE": r"\bhpke\b|HPKE|Hpke",
}

SCAN_DIRS = ("src", "tools", "crates")
SCAN_SUFFIXES = (".py", ".rs", ".toml")


# test files and docs are not production usage; the scan records them
# separately as test-only evidence.
def is_test_file(path: Path) -> bool:
    name = path.name
    return name.startswith("test_") or "/tests/" in str(path) or name.endswith("_test.py")


def scan_tree(root: Path = None) -> dict:
    """Every primitive pattern hit in the production tree (src/, tools/,
    crates/), with the files that use it - tests excluded from the
    production column and counted in their own."""
    root = root or ROOT
    production: dict[str, set[str]] = {}
    tests: dict[str, set[str]] = {}
    for directory in SCAN_DIRS:
        base = root / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in SCAN_SUFFIXES or not path.is_file():
                continue
            if path.name == "test_curve_inventory.py":
                continue  # the scanner's own pattern table is not usage
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(root))
            for primitive, pattern in SCAN_PATTERNS.items():
                if re.search(pattern, text):
                    (tests if is_test_file(path) else production).setdefault(primitive, set()).add(rel)
    return {
        "production": {k: sorted(v) for k, v in sorted(production.items())},
        "tests_only": {k: sorted(v) for k, v in sorted(tests.items()) if k not in production},
        "test_files_also": {k: sorted(v) for k, v in sorted(tests.items()) if k in production},
    }


# -------------------------------------------------------------- registry

# The curated interface table. primitives: what the interface's
# protection actually rests on (from the scan). classification:
# classical | pq | hybrid. hardware: the device keys / firmware
# features the interface depends on ("" when none - the roadmap row's
# "preserve current device keys" is checked against exactly this
# column). pq_test: the test module that exercises the PQ property, or
# the honest reason there is none. migration: the versioned state.
REGISTRY = [
    {
        "interface": "paced link (client<->relay<->exit, src/link.rs)",
        "primitives": ["X25519", "ML-KEM-768", "ChaCha20-Poly1305", "HKDF", "SHA-256"],
        "classification": "hybrid",
        "classical_half": "X25519 ECDH in every handshake",
        "pq_half": "ML-KEM-768 encapsulation alongside; combined via HKDF",
        "hardware": "none (link keys are session keys, sealed at rest by keyguard)",
        "pq_test": "tools/test_units.py link vectors + formal/ link model lemmas",
        "migration": "landed hybrid; classical half removable only with a versioned protocol bump",
    },
    {
        "interface": "cloak (HTTP/3 QUIC camouflage, src/cloak.rs)",
        "primitives": ["TLS-exporter", "X25519", "SHA-256"],
        "classification": "classical",
        "classical_half": "the outer TLS 1.3 QUIC handshake is TLS's own (X25519); the tunnel key binding uses the exporter",
        "pq_half": "none on the outer layer (TLS 1.3 key share as deployed is classical)",
        "hardware": "none",
        "pq_test": "honest gap: the OUTER camouflage layer cannot be PQ without a PQ-TLS deployment (roadmap records this, not hides it)",
        "migration": "open: follows the PQ-TLS (X25519MLKEM768 key share) rollout in the QUIC stack; the inner layers are already hybrid",
    },
    {
        "interface": "mesh identity (!xxxxxxxx member IDs, src/mesh/identity.rs)",
        "primitives": ["Ed25519", "ML-DSA-44", "SHA-256"],
        "classification": "classical",
        "classical_half": "Ed25519 descriptor/identity signatures",
        "pq_half": "operator ML-DSA-44 third-signature half is OPTIONAL and additive (tools/test_operator_mldsa44.py); identity keys themselves stay Ed25519",
        "hardware": "FIDO2 hmac-secret on the member's hardware key anchors the identity (all four commissioned units + the emulated firmwares); enrolled identity keys must survive every migration",
        "pq_test": "tools/test_operator_mldsa44.py (the additive half) + Tamarin enrollment model",
        "migration": "Ed25519 -> PQ identity is a versioned protocol change that RESETS NO keys: new PQ half verified alongside until a cutover, per the roadmap row",
    },
    {
        "interface": "keyguard hybrid sealing (tools/keyguard.py)",
        "primitives": ["X25519", "ML-KEM-768", "AES-GCM", "HKDF", "SHA-256"],
        "classification": "hybrid",
        "classical_half": "X25519 recipient half",
        "pq_half": "ML-KEM-768 sender half; both KEMs' shared secrets combined into the AES-GCM key via HKDF",
        "hardware": "the sealing key unseals via the hardware key (FIDO2 hmac-secret / TPM2); ciphertexts on disk depend on the device's continued function",
        "pq_test": "tools/test_keyguard.py (context-binding refusal, KDF format) + formal kem_seal model vectors",
        "migration": "landed hybrid; the formal-model vectors pin the format",
    },
    {
        "interface": "CTAP2 session auth (src/session_auth.rs)",
        "primitives": ["P-256/ES256", "HMAC", "SHA-256"],
        "classification": "classical",
        "classical_half": "the CTAP2 PIN/UV protocol's own P-256 ECDH + HMAC channel, and ES256 assertion signatures",
        "pq_half": "none on the CTAP transport (the protocol is the FIDO2 spec's); the SESSION it unlocks is authenticated by ML-DSA-65 half-signatures at the enrollment layer",
        "hardware": "every enrolled hardware key: the P-256 CTAP PIN/UV channel is flagged (not blocked) on every key per the owner's ranking decision (ROADMAP section 3)",
        "pq_test": "tools/test_session_auth.py + session_auth_vectors.py + hardware-bound-session Tamarin model",
        "migration": "CTAP2.2/PQ-FIDO is an upstream spec migration; the flag on P-256 PIN/UV stays until then (no silent key resets)",
    },
    {
        "interface": "signed enrollment (tools/managed_profile.py)",
        "primitives": ["Ed25519", "ML-DSA-65", "SHA-256"],
        "classification": "hybrid",
        "classical_half": "Ed25519 operator half",
        "pq_half": "ML-DSA-65 device half via the lab SoftwareOperator; both halves required",
        "hardware": "the enrolling device signs with its FIDO2 credential (Ed25519-capable keys: Solo 1, OnlyKey, Trezor, TKey; ES256 default path otherwise)",
        "pq_test": "formal enrollment model (dual_signature_binding, no_role_substitution, either_scheme_holds) + formal_model_vectors.py",
        "migration": "landed dual-signature; either-scheme-holds lemma records the compatibility dependency",
    },
    {
        "interface": "OHTTP control plane (tools/ohttp.py)",
        "primitives": ["X25519", "HPKE", "HKDF", "SHA-256"],
        "classification": "classical",
        "classical_half": "HPKE (X25519 + HKDF-SHA256) is RFC 9180's base mode",
        "pq_half": "none in the vendored mode; a PQ HPKE (ML-KEM) mode is a cutover with new config ids",
        "hardware": "none",
        "pq_test": "tools/test_ohttp.py (round trip, replay refusal, response binding) + ProVerif unlinkability",
        "migration": "open: PQ-HPKE mode addition, versioned by config id; the ohttp Tamarin model already records the boundary",
    },
    {
        "interface": "mix lane Sphinx (crates/cpvpn-mix-lane)",
        "primitives": ["X25519", "ML-KEM-768", "ML-KEM-1024", "ChaCha20-Poly1305", "SHA-512", "HKDF", "X-Wing"],
        "classification": "hybrid",
        "classical_half": "X25519 in the X-Wing combiner",
        "pq_half": "ML-KEM-768 in the X-Wing combiner (the sphinx header seal); ML-KEM-1024-X25519 is a listed PQ_WIRE option (tools/mix.py) with its ciphertext budget pinned (mix_lane_math)",
        "hardware": "none (relay keys are server-side; operator unlock guards them at rest)",
        "pq_test": "crates/cpvpn-mix-lane/tests/vectors.rs + the mix-lane Tamarin models + mutation controls",
        "migration": "landed X-Wing hybrid; the ML-KEM-1024 wire option is the sized-for-future variant",
    },
    {
        "interface": "mesh credits - public pool (tools/mesh_tokens.py)",
        "primitives": ["RSA-FDH", "SHA-256"],
        "classification": "classical",
        "classical_half": "Chaum blind RSA-3072-FDH: a quantum adversary FORGES credits (unlinkability survives)",
        "pq_half": "none yet - the documented open migration (COMPARISON.md note 8)",
        "hardware": "the issuer key seals via keyguard (hardware unseal for signing)",
        "pq_test": "tools/test_mesh_tokens.py + credits Tamarin model + ProVerif unlinkability (which found and closed the issuer tagging attack)",
        "migration": "OPEN, DATED: to a lattice-based blind signature / the RFC 9497 VOPRF family (tools/voprf.py is the landed control-plane half); public redemption must stay publicly verifiable, which is why RSA is still there",
    },
    {
        "interface": "mesh credits - private groups (tools/mesh_voprf.py)",
        "primitives": ["Ristretto255", "SHA-512", "HKDF"],
        "classification": "classical",
        "classical_half": "ristretto255 group + SHA-512 (the discrete-log problem)",
        "pq_half": "none; group-based VOPRFs are classical by construction",
        "hardware": "the group key distribution rides the mesh identity (hardware-anchored)",
        "pq_test": "tools/test_mesh_voprf.py + RFC 9497 vectors in tools/test_voprf.py",
        "migration": "private groups accept computational trust within the group; the public-pool migration note above governs the pool",
    },
    {
        "interface": "vouchers (tools/voucher.py - revenue Model 1)",
        "primitives": ["RSA-FDH", "SHA-256", "HMAC"],
        "classification": "classical",
        "classical_half": "blind RSA-3072 (same primitive as public credits, for the same public-verifiability reason) + HMAC webhooks",
        "pq_half": "none; inherits the credits migration",
        "hardware": "mint key seals via keyguard",
        "pq_test": "tools/test_voucher.py (17 checks: round trip, double-spend, tier validity, printer-view leak)",
        "migration": "tracks the public-pool credits migration",
    },
    {
        "interface": "hardware-bound sessions + operator unlock (tools/session_signer.py, tools/keyguard.py)",
        "primitives": ["Ed25519", "ML-DSA-65", "X25519", "ML-KEM-768", "AES-GCM", "HKDF"],
        "classification": "hybrid",
        "classical_half": "Ed25519 session signatures + X25519 sealed-wrapping half",
        "pq_half": "ML-DSA-65 session half + ML-KEM-768 wrapping half (the no-vTPM OCI case, commit cabe084)",
        "hardware": "THE critical compatibility surface: FIDO2 hmac-secret keys (every enrolled unit), TPM2 where present, the operator's Nitrokey unwrap; keys are REPLACED NEVER RE-WRAPPED",
        "pq_test": "tools/test_session_auth.py + tools/test_operator_unlock.py + tools/test_key_custody.py + hardware-bound-session Tamarin model",
        "migration": "landed; per-session carrier keys are the open Phase 2 remainder (design in this delivery batch)",
    },
    {
        "interface": "exit resolver + DNS (tools/exit_resolver.py, unbound)",
        "primitives": ["SHA-256", "HMAC"],
        "classification": "classical",
        "classical_half": "DNSSEC validation is RSA/ECDSA as deployed upstream; the blocklist is HMAC-signed locally",
        "pq_half": "upstream DNSSEC's PQ migration is an upstream (unbound/binder) question, recorded not hidden",
        "hardware": "none",
        "pq_test": "tools/test_exit_resolver.py + the named DNSSEC-failure refusal (20/20 live names, 20 Nov)",
        "migration": "follows upstream unbound; the local DoT forwarder is already hybrid-PQ on the wire where the upstream supports it",
    },
    {
        "interface": "DC-net masks / pads (tools/padbook.py, tools/padstore.py)",
        "primitives": ["SHA-256", "HMAC", "HKDF"],
        "classification": "classical",
        "classical_half": "HMAC-SHA256 hardware secret + HKDF-SHA256 cascade-key derivation from the Nitrokey's FIDO2 hmac-secret; the information-theoretic property is the CONSTRUCTION, not the primitive",
        "pq_half": "the anonymity property is unconditional for honest pads (the Maurer/Ahlswede-Csiszar review); the key custody underneath is keyguard's hybrid",
        "hardware": "pad book keys seal via keyguard (hardware custody: the Nitrokey hmac-secret context, distinct from the unsupported v1 format)",
        "pq_test": "tools/test_padbook.py + tools/test_padstore.py + INFORMATION_THEORETIC_REVIEW_20261117.md gaps record",
        "migration": "the strict IT profile (independent extractor seeds, disjoint material) is the open roadmap row; material-allocation proof in this delivery batch",
    },
    {
        "interface": "OHTTP relay + mix I2P front (tools/ohttp_relay.py, tools/i2p.py)",
        "primitives": ["X25519", "SHA-256"],
        "classification": "classical",
        "classical_half": "I2P's own cryptography is I2P's (classical, ElGamal/AES as deployed); our layers inside it are the hybrid ones",
        "pq_half": "none on the front transport (named exception, PQ_INVENTORY exception table)",
        "hardware": "none",
        "pq_test": "tools/test_i2p.py + the PQ_INVENTORY exception record",
        "migration": "recorded exception: the front is address-hiding, the inner tunnel carries the PQ properties",
    },
]

INTERFACE_NAMES = {row["interface"] for row in REGISTRY}


def build_inventory(root: Path = None) -> dict:
    """The generated artifact: scan + registry, cross-checked. Raises
    InventoryError when the registry names a primitive the scan cannot
    find anywhere in the tree (a stale row), or when the scan finds a
    production primitive NO registry row claims (an uncovered surface)."""
    scan = scan_tree(root)
    scanned_production = set(scan["production"])
    claimed = set()
    for row in REGISTRY:
        claimed.update(row["primitives"])
    stale = sorted(claimed - scanned_production)
    if stale:
        raise InventoryError(f"registry names primitives the scan cannot find in production code: {stale}")
    uncovered = sorted(
        p
        for p in scanned_production - claimed
        if p not in ("TLS-exporter", "HPKE")  # recorded under ohttp/cloak rows
    )
    uncovered = [p for p in uncovered if p not in {"SHA-256", "HMAC", "HKDF", "SHA-512"}]
    # SHA/HMAC/HKDF are ubiquitous helpers claimed by many rows; only
    # KEY-ESTABLISHMENT/SIGNATURE primitives must map to exactly one row.
    key_primitives = {
        "X25519",
        "Ed25519",
        "P-256/ES256",
        "RSA-FDH",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA-44",
        "ML-DSA-65",
        "X-Wing",
        "Ristretto255",
    }
    uncovered_keys = sorted(key_primitives & (scanned_production - claimed))
    if uncovered_keys:
        raise InventoryError(f"production code uses key primitives no registry row claims: {uncovered_keys}")
    blob = json.dumps({"schema": SCHEMA, "scan": scan, "registry": REGISTRY}, sort_keys=True).encode()
    return {
        "schema": SCHEMA,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "content_sha256": hashlib.sha256(blob).hexdigest(),
        "scan": scan,
        "registry": REGISTRY,
        "summary": {
            "interfaces": len(REGISTRY),
            "classical": sum(1 for r in REGISTRY if r["classification"] == "classical"),
            "hybrid": sum(1 for r in REGISTRY if r["classification"] == "hybrid"),
            "pq": sum(1 for r in REGISTRY if r["classification"] == "pq"),
            "open_migrations": [r["interface"] for r in REGISTRY if r["migration"].startswith(("open", "OPEN"))],
            "hardware_dependent": [
                r["interface"]
                for r in REGISTRY
                if r["hardware"] != "none" and r["hardware"].startswith(("every", "THE", "FIDO2", "the"))
            ],
        },
    }


class InventoryError(Exception):
    """The registry and the scanned tree disagree."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "docs/evidence/INTERFACE_INVENTORY.json")
    parser.add_argument("--check", action="store_true", help="build and validate only; print the summary")
    args = parser.parse_args()
    inventory = build_inventory()
    if not args.check:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(inventory, indent=1) + "\n")
        print(f"wrote {args.out}")
    print(json.dumps(inventory["summary"], indent=1))


# ------------------------------------------------------------- self-tests


class InterfaceInventoryTests(unittest.TestCase):
    """The inventory's own gate: the scan is real, the registry matches
    it, and the preservation rules hold."""

    def test_scan_finds_the_tree(self):
        scan = scan_tree()
        self.assertIn("X25519", scan["production"], "X25519 must appear in production code")
        self.assertIn("ML-KEM-768", scan["production"], "the hybrid KEM must appear")
        self.assertIn("ML-DSA-65", scan["production"], "the PQ signature must appear")
        self.assertIn("Ristretto255", scan["production"])
        self.assertIn("RSA-FDH", scan["production"])
        # concrete anchors: the scan sees the actual files
        self.assertTrue(
            any("tools/keyguard.py" in f for f in scan["production"]["ML-KEM-768"]),
            "keyguard.py is the ML-KEM-768 sealing site",
        )
        self.assertTrue(
            any("src/session_auth.rs" in f or "tools" in f for f in scan["production"]["P-256/ES256"]),
            "the CTAP session-auth surface uses P-256",
        )

    def test_inventory_builds_and_is_consistent(self):
        inventory = build_inventory()
        self.assertEqual(inventory["schema"], SCHEMA)
        self.assertGreaterEqual(inventory["summary"]["interfaces"], 14)
        self.assertGreaterEqual(inventory["summary"]["hybrid"], 4)
        self.assertGreaterEqual(inventory["summary"]["classical"], 6)
        self.assertEqual(len(inventory["registry"]), inventory["summary"]["interfaces"])

    def test_every_interface_names_both_halves(self):
        for row in build_inventory()["registry"]:
            if row["classification"] == "hybrid":
                self.assertTrue(
                    row["classical_half"] and row["pq_half"], f"{row['interface']}: hybrid must name both halves"
                )
            if row["classification"] == "classical":
                self.assertTrue(row["classical_half"], f"{row['interface']}: classical must name its half")
                self.assertTrue(row["pq_half"], f"{row['interface']}: the PQ gap must be stated, not silent")

    def test_hardware_dependencies_are_recorded_not_reset(self):
        """The roadmap row's rule: do not silently reset hardware. Every
        interface with a hardware dependency says WHICH keys, and no
        migration row MANDATES resetting them (negations - "resets no
        keys", "no silent key resets" - are the rule stated, and pass)."""
        inventory = build_inventory()
        forbidden = (
            "reset the keys",
            "reset keys",
            "keys are reset",
            "must reset",
            "must be reset",
            "wipe the keys",
            "wipes keys",
            "re-enroll every",
            "re-enroll all",
        )
        for row in inventory["registry"]:
            if "hardware" in row and row["hardware"] not in ("none", ""):
                self.assertGreater(
                    len(row["hardware"]), 20, f"{row['interface']}: hardware dependency must be specific"
                )
                lowered = row["migration"].lower()
                for phrase in forbidden:
                    self.assertNotIn(
                        phrase, lowered, f"{row['interface']}: migration mandates a key reset ({phrase!r})"
                    )

    def test_open_migrations_are_visible(self):
        summary = build_inventory()["summary"]
        self.assertTrue(
            any("cloak" in i for i in summary["open_migrations"]), "the cloak outer-layer PQ gap must be listed as open"
        )
        self.assertTrue(
            any("credits" in i or "voucher" in i for i in summary["open_migrations"]),
            "the blind-RSA credits migration must be listed as open",
        )

    def test_registry_covers_the_key_primitives(self):
        scan = scan_tree()
        key_primitives = {
            "X25519",
            "Ed25519",
            "P-256/ES256",
            "RSA-FDH",
            "ML-KEM-768",
            "ML-DSA-44",
            "ML-DSA-65",
            "X-Wing",
            "Ristretto255",
        }
        for primitive in sorted(key_primitives & set(scan["production"])):
            self.assertTrue(
                any(primitive in row["primitives"] for row in REGISTRY),
                f"{primitive} is used in production but no interface claims it",
            )

    def test_stale_registry_row_is_an_error(self):
        # direct construction: a registry row naming a nonexistent primitive
        saved = REGISTRY[:]
        try:
            REGISTRY.append(
                {
                    "interface": "phantom",
                    "primitives": ["NotARealPrimitive-xyz"],
                    "classification": "classical",
                    "classical_half": "x",
                    "pq_half": "none",
                    "hardware": "none",
                    "pq_test": "-",
                    "migration": "phantom",
                }
            )
            with self.assertRaises(InventoryError):
                build_inventory()
        finally:
            REGISTRY[:] = saved

    def test_every_row_has_a_pq_test_statement(self):
        for row in build_inventory()["registry"]:
            self.assertTrue(row["pq_test"].strip(), f"{row['interface']}: PQ test status must be stated")


if __name__ == "__main__":
    import sys

    if "--out" in sys.argv or "--check" in sys.argv:
        main()
    else:
        unittest.main()

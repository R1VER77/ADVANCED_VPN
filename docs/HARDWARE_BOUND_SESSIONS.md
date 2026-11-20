# Hardware-bound sessions

Owner request, 19 November 2026: the laptop must not receive credentials that work
without the hardware key. This applies to the basic flow of every supported key.

## The problem

At connect, one PIN and touch return the FIDO2 hmac-secret to the computer. It unseals a
vault holding every long-term private key the client uses: the ML-DSA-65 TLS identities
(`outer`, `middle`, `inner`), the WireGuard key and the cloak token derived from it
(`tools/avpnctl.py`, `load_keys` → `memory_fd`). Malware on the computer at that moment can
copy them and connect from anywhere, later, without the key. Entering the PIN on the device
(Trezor, Ledger) protects the PIN, not these keys.

## How others do it

- **OpenVPN with PKCS#11, strongSwan IKEv2 with a smartcard**: the private key is generated
  on the token and never leaves it; the token signs each handshake. The session's traffic
  keys are derived on the computer, because the computer encrypts the packets.
- **Trezor Suite**: the computer prepares a request, the device shows it, the user confirms
  on the device, and only the signature returns. Keys never reach the computer.

Both put a non-exportable signature in every session. A computer that runs the tunnel
always holds that session's traffic keys and plaintext; only a tunnel on separate hardware
(a router) removes those.

## Design: a hardware session authorization in every leaf

Every supported key can make a FIDO2 assertion: a signature by a credential whose private
key never leaves the device, after a touch and the PIN (on the device for Trezor and
Ledger). That is the common ground.

1. **At connect and at each leaf rotation (at most 12 h)** the client builds a session
   authorization: the SHA-256 of each layer's public key (`outer`, `middle`, `inner`), the
   validity window, and a version tag. The same PIN and touch that unseals the vault
   (`keyguard.hardware_assertion`) also signs it: the WebAuthn challenge is the SHA-256 of
   the canonical authorization.
2. **The authorization and the assertion travel in each fresh leaf certificate** as a
   non-critical extension, so TLS itself is unchanged.
3. **Every hop verifies it** (`src/tls.rs`, `authenticated`) against the device's credential
   public key, pinned for that peer at enrollment: relying party, user present and
   verified, challenge, signature, its own layer's key hash named, and a window that
   covers now and is no longer than 12 h. A leaf without it is refused once the peer has a
   pinned device key.
4. **Both halves are required.** The ML-DSA-65 identity signs TLS (post-quantum); the
   hardware assertion authorizes the session (classical on every key except Solo 2's
   Hacker build). Stolen identity keys need the hardware for every session after the
   current leaf expires; a quantum forger of the assertion still needs the ML-DSA-65 key.

## What it does not remove

- The current session's traffic keys and plaintext, held by the computer that runs the
  tunnel. A stolen leaf and identity key work until that leaf expires (at most 12 h).
- Malware present while the key is plugged in can ask it to sign; the touch is what
  stops it acting unseen.
- The WireGuard carrier key, its PSK and the cloak token stay long-term in the vault in
  this phase. They reach only the entry's carrier, inside which both TLS layers refuse
  without a fresh authorization. Phase 2 makes them per-session.

## Status (19 November 2026): phase 1 implemented

- **Code.** `tools/session_auth.py` (statement, extension, reference verifier);
  `managed_profile.authorize_session` (the connect's one PIN and touch also signs the
  statement) and `refresh_leaves(session=...)`; `tools/avpnctl.py` asks again an hour
  before a session ends and keeps the old leaves if nobody answers, so the hops refuse them
  when they expire: it fails closed. `src/session_auth.rs` verifies; `src/tls.rs`
  `authenticated` calls it for every peer with a pinned `peer_device`.
- **Enrollment.** A client protected by a hardware key sends its credential's public key in
  its request (`device_public`); `avpn init` pins it on every hop facing the client. A key
  whose credential is neither ES256 nor EdDSA is refused then, with its algorithm named.
  Clients enrolled before this change, and software-protected ones, are unchanged: a
  client gains hardware-bound sessions when it is enrolled again with its key.
- **Evidence.** 17 shared vectors, on which Python and Rust agree, one per check; ten
  mutants of each verifier (every check removed in turn) fail them. An enrollment test runs
  the real request → init → enroll flow. The real firmware of Solo 1, Solo 2, CanoKey and
  TKey (emulated, `tools/device_compatibility_lab.py`, phase
  `hardware_session_authorization`) each signed a session that the exit accepted, and an
  expired one and an unauthorized leaf were refused. `formal/session/session_auth.spthy`
  proves the four properties above, with two mutants falsified.
- **Open.** Physical Nitrokey 3, YubiKey, Trezor and Ledger runs (they need the owner);
  a live chain on the lab's network namespaces.

## Phase 2: no long-term key in the data plane

The owner's follow-up (the YubiKey-Guide's agent-and-card model, Qubes' split keys): the
data-plane processes should hold only per-session keys, and the long-term identity should be
in plaintext only inside a short-lived signer.

1. Each session gets fresh TLS keys, in memory only; the hops pin the long-term identity as
   their issuer instead of the leaf's own key.
2. A separate signer process, sandboxed, with locked memory excluded from core dumps,
   unseals the long-term ML-DSA-65 key only after the hardware approves, certifies the
   session keys, erases the key and exits: seconds, about twice a day.
3. The WireGuard carrier key, its PSK and the cloak token become per-session too.

Root-level malware present while the signer runs can still read it; only a separate signing
VM, or a key that holds ML-DSA itself (today Solo 2's Hacker build), removes that.

## Gates

- Python and Rust verify the same vectors; every refusal is tested with real signatures.
- A mutant that skips any check must fail a test.
- Lab: real assertions from the emulated Solo 1, Solo 2, CanoKey and TKey firmware verify
  in the Rust verifier; an end-to-end chain refuses a leaf without authorization.
- Physical units (Nitrokey 3, YubiKey, Trezor, Ledger) need the owner.
- A Tamarin model: a session is accepted only with both halves, unless both are broken.

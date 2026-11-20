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

## Status (19 November 2026): phase 1 implemented (superseded in part by phase 2 below)

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

## Phase 2: no long-term identity in the VPN's processes (implemented 20 November 2026)

The owner's follow-up (the YubiKey-Guide's agent-and-card model, Qubes' split keys): the
VPN's long-running processes hold only per-session keys; the long-term identity is in
plaintext only inside a short-lived signer.

1. **Session keys.** At connect and at each renewal the supervisor makes a fresh ML-DSA-65
   key per layer, in memory (`managed_profile.sign_session`); the data plane receives only
   these, as sealed memfds.
2. **The signer** (`tools/session_signer.py`) is a separate process for those seconds: it
   makes itself undumpable (no core dumps, no ptrace by same-user processes) and locks its
   memory where the kernel allows; it gets the session public keys on stdin, asks the key
   for one touch and its PIN (the statement now names the session keys), unseals only the
   identities, certifies each session key under its layer's identity, prints the leaves
   and exits. The kernel reclaims its memory on exit.
3. **Every hop** (`src/tls.rs`, `issued_by_pinned`) accepts a leaf for a key other than the
   pinned identity only if the pinned identity signed it, and only where a device key is
   pinned, so the session authorization is mandatory for it.
4. **Still long-term:** the WireGuard carrier key, its PSK and the cloak token, which the
   signer returns as before. They reach only the entry's carrier, and both TLS layers inside
   it refuse once the hardware session ends.

   **Assessed, 20 November 2026, not built (owner's decision):** making them per-session
   needs the entry to learn a new carrier key each session, before the carrier exists: the
   cloak would have to carry the session's authorization. The cloak's proof today is 32
   bytes on one QUIC stream (or an `If-None-Match` header on the TCP fallback, whose header
   the server bounds to 4 KB); a session leaf is about 7 KB (an ML-DSA-65 key and signature
   plus the statement), so every connection would open with a visible upload, changing the
   very shape the cloak exists to hide. What it would buy is small: copied carrier keys reach
   the entry's carrier, never past it. Recommended: leave the carrier as it is. (A short hash
   of the statement would keep the shape but cannot be checked: the entry never sees the
   statement it would stand for.)

**Evidence.** Six Rust QUIC handshake tests, among them: a session key certified by the
identity and named by the device connects; without a pinned device key, or certified by
another identity (also when the hop trusts that one too), or with a statement naming the
identity instead, it is refused; removing the signature check or the device-key condition
fails them. Signer tests: the leaves carry the session keys and are issued by the
identities, the supervisor receives no identity, the process is undumpable with core dumps
off, and malformed or unprotected requests are refused. The real firmware of Solo 1, Solo
2, CanoKey and TKey signed sessions whose session-key leaves the exit accepted (lab phase
`hardware_session_authorization`, `session_key_certified_by_identity`). Tamarin adds
`stolen_session_key_expires`: a session key taken from the data plane is accepted only in
its own window, unless both long-term keys leaked (mutant falsified).

## A signer process, a separate VM, or both

They protect against different malware, and the signer is built so that both are possible:
its whole interface is one JSON request on stdin and one reply on stdout.

| Where the identity is unsealed | Who can still read it while it is | Who can read the session keys |
|---|---|---|
| Before phase 2: the VPN's long-running processes | anyone who reads those processes' memory, for the whole session (an exploit of the network-facing data plane, root, a crash dump) | the same |
| Phase 2: the short-lived signer process (implemented) | root on this computer, during those seconds about twice a day; not the data plane, not same-user processes (undumpable), not crash dumps | root, or an exploit of the data plane, until the session ends (at most 12 h) |
| Phase 2 inside a separate signing VM (Qubes-style split, not implemented) | only someone who controls the hypervisor or that VM; root in the VPN's own VM cannot | as above: the VPN's VM still holds them |

A separate VM goes beyond the process because a VM boundary holds against root in the
other VM, which a process boundary does not. It only helps where the host itself is small
and trusted, as in Qubes OS, where everyday software runs in VMs and the hardware key is
attached to the signing VM; on an ordinary desktop, root on the host reads every VM's
memory. So the two combine rather than compete: the signer is the unit, the VM is where it
can run. Running it in a Qubes vault VM (qrexec service, key attached there) needs only a
transport for the same request and reply; it is not built or tested yet. Neither removes the
session keys and plaintext that any VPN running on this computer holds.

## Gates

- Python and Rust verify the same vectors; every refusal is tested with real signatures.
- A mutant that skips any check must fail a test.
- Lab: real assertions from the emulated Solo 1, Solo 2, CanoKey and TKey firmware verify
  in the Rust verifier; an end-to-end chain refuses a leaf without authorization.
- Physical units (Nitrokey 3, YubiKey, Trezor, Ledger) need the owner.
- A Tamarin model: a session is accepted only with both halves, unless both are broken.

# Changelog

User-visible changes per release, newest first. Defects that affected security, privacy,
availability or a published claim are in [docs/INCIDENTS.md](docs/INCIDENTS.md). Every
measured figure in the docs names the version it was measured on.

## Unreleased

- `avpn cloud azure server`: an Azure chain server made by OpenTofu (the `azure-server`
  module, `hashicorp/azurerm` 5.13.0 locked): a Trusted Launch VM (secure boot, virtual
  TPM, so its keys are TPM-sealed and it restarts unattended), the tunnel port from the
  previous hop only, SSH only from the relay (administered through the relay's Instance
  Connect Endpoint, never your address), a static address, teardown by its OpenTofu state.
- OpenTofu provisioning, step 1 of the setup flow (D007): a pinned OpenTofu 1.13.9
  (`tools/tofu.py`; SHA256SUMS verified against OpenTofu's signing key, fingerprint
  cross-checked; refused unless the archive matches the pin), an `oci-server` module that
  mirrors `cloud oci server` (provider `oracle/oci` 9.12.1, hashes locked for amd64 and
  arm64), and a workspace runner (`tools/tofu_run.py`): read-only lock file, an exact saved
  plan, state and plans encrypted by OpenTofu with a key sealed in the operator's Nitrokey
  vault (`avpn state-key`), passed only in the environment. A live read-only plan matched
  the hand-written path resource for resource.
- A broken chain is obvious (owner, 20 November): when a connected client's chain stops
  answering for a minute, or never answers after a start, a desktop notification and
  `avpn status` say so and point to `avpn cloud health`, which finds whether a server was
  stopped by its provider (free tiers stop idle servers), is locked after a reboot, gone or
  unreachable, and whether AWS credits or a free plan are running out, each with its fix.
  The providers are asked only on request, never on a timer from your address.
- `avpn cloud oci server --bastion OCID`: an Oracle server administered only through its
  bastion (no SSH address rule, sessions renewed automatically). A launch refused for lack
  of capacity (or rate-limited) keeps its network and resumes on the next `--apply`, or
  retries itself with `--wait-capacity MINUTES`.
- The installer knows the server key rule: `install.py --apply --role relay|middle|exit
  --protect systemd-creds` first seals and opens a test credential with the TPM2 and refuses,
  before installing anything, when that fails; `--protect operator --unlock-key FILE` locks
  the keys to the operator's Nitrokey instead. `avpnctl request` applies the same rule
  (`tools/sealing.py`), and both preflights accept `--protect operator`.
- Fixed (owner's first physical connect, 20 November): `sudo avpnctl connect` in a terminal
  failed for a hardware-protected client, because the session signer had no terminal for the
  PIN ([incident](docs/INCIDENTS.md)). A locked server's refusal now says how to unlock it.
- `avpn cloud host bastion`: a server reached through an OCI Bastion gets a new session
  (3 hours) whenever the recorded one is gone or ending, so `avpn cloud unlock` and every
  other SSH work at any time.
- Servers without a TPM no longer keep plain keys ([design](docs/HARDWARE_BOUND_SESSIONS.md),
  servers without a TPM). Setup tests the host first: keys are sealed to its TPM2 when
  systemd-creds can use one, otherwise locked to the operator's Nitrokey (`--protect
  operator`): encrypted under a data key that only the operator can unwrap, held in RAM until
  the next reboot. The chain's signing touch also unlocks such servers; after a reboot,
  `avpn cloud unlock NAME`. Plain keys and keys sealed with the host key alone are no longer
  made, and existing ones are replaced at the next `chain` (new keys, so clients enroll the
  new chain). New commands: `avpn unlock-key`, `avpn unwrap`, `avpn server-unlock`,
  `avpn cloud unlock`; `avpn init --emit-unlock`; `avpn cloud host setup --vault`.
- Fixed (found upgrading the owner's laptop, 20 November): `install.py --adopt-legacy`
  refused every installation whose venv names the system interpreter (all source and
  pre-bundled-runtime installs), and so did a source install's own new slot; exactly those
  interpreter links (`venv/bin/python*` to a root-owned `/usr/bin/python3*`) are now
  accepted, every other link out of a slot still refused. And the system launchers, called
  through `/usr/local/bin/avpnctl` (a symlink), looked for `/usr/local/venv`: they now
  resolve themselves first.
- Admin SSH without address rules: `avpn cloud aws admin-endpoint` (EC2 Instance Connect
  Endpoint, IAM-authorised from any network).

- Hardware-bound sessions ([design](docs/HARDWARE_BOUND_SESSIONS.md)): a client protected by
  a hardware key now has its FIDO2 key, touched and PIN-unlocked, sign each session (at most
  12 hours), and every hop pinned to that key refuses leaves it did not authorize, so keys
  copied off the computer stop working when the session ends. The connect's one PIN and
  touch does both; renewal asks again an hour before the end and fails closed. Takes effect
  when a client is enrolled again with its key; software-protected clients are unchanged.
- Hardware-bound sessions, phase 2: the VPN's processes no longer hold the long-term
  identities. Each session gets fresh layer keys, certified by a short-lived, undumpable
  signer process that alone unseals the identities after the key's touch and PIN; hops
  accept such a leaf only if the pinned identity signed it and the device named its key.
- Oblivious requests no longer reveal a member's clock skew: the timestamp is a 30-second
  bucket of the relay's clock (`GET /time`, refreshed by every answer), so members of a relay
  send the same value and no third party is asked the time; the gateway refuses other
  values, and refuses requests for up to 30 s after it restarts. A Tails-style multi-pool
  clock (`tools/timesync.py`) remains for callers without a relay.
- Oblivious routes check gateway key consistency (RFC 9458 section 7), the condition the
  OHTTP unlinkability proof rests on: a beacon signs its gateway key into its descriptor
  (`avpn mesh publish --gateway-key`), and a member uses a route beyond directory fetches
  only once two other beacons show that same signed key; equivocation is refused.
- Fixed: mesh descriptor signatures could never be verified (wrong ML-DSA module name,
  hidden by stubbed tests); see docs/INCIDENTS.md.
- `avpn init --dns-recursive`: the exit resolves names with its own Unbound (DNSSEC,
  QNAME minimisation) instead of one public DoT resolver. Opt-in: its queries to
  authoritative servers are plain DNS (docs/PQ_INVENTORY.md exception 5).
- Assurance: Kani proves the link's replay window and reply credit; every parser of
  outside bytes is fuzzed in CI; the Python mutation fuzzer found three exception types
  escaping the enrollment and session-leaf parsers, now refused as `ValueError`.
- Formal: ProVerif proves OHTTP and credit unlinkability; Tamarin proves hardware-bound
  sessions. Credits now refuse an issuer's tagged blind signature (RFC 9474 Finalize).
- Security keys are ranked (open firmware and on-device PIN entry preferred) and the P-256
  CTAP PIN/UV channel is flagged on every key. An optional ML-DSA-44 FIDO2 credential on a
  separate key adds a third operator signature half.

- Traffic-analysis research: record relay-only wire-clock look-ahead, add fixed-window
  A/B scoring with whole-round holdouts and block-label permutation checks, and publish
  the 30 ms versus 5 ms result with its collection limitations. No defense default changes.
  The collector accepts a recorded `--seed` and propagates failed worker exits.
- Installation/setup: `avpn preflight` checks host requirements with a Python 3.8+
  standalone bootstrap; doctor shares its host checks. Optional provider checks stay
  unprivileged and opt-in. Missing or failed required checks block readiness.
- `avpn setup`: private, locked and durable checkpoints; every step is rechecked. Guard
  and protection completion require a live supervisor and fresh route evidence. Saved
  public credentials are not described as proof of possession.
- Typed hardware diagnostics and individually confirmed repair plans. On-device user
  verification is supported, probes have a deadline, and vendor evidence plus an exact
  target are required before enabling USB FIDO2. No reset or credential deletion is
  offered. GUI/model integration and the remaining installation-plan phases are pending.
- Physical setup validation: Nitrokey, YubiKey, Trezor and Ledger passed fresh-assertion
  vault round trips and actual missing-access/confirmed-udev-repair/restoration trials.
  Wallet rules are restricted to FIDO interfaces. Use current udev event tags rather
  than historical tags after a rule change; keep vendor output out of JSON results.
  See [hardware setup evidence](docs/evidence/SETUP_HARDWARE_20261117.json).
- README: three setup tiers (General VPN, Hardened, Cypherpunk) and the Intel ME. `avpn doctor`
  reports the management coprocessor read-only: the Intel ME version and operating mode,
  whether me_cleaner recognises that version (it lists ME up to 11.x), or AMD's PSP.
- **Website fingerprinting on a busy CPU is now in the README**, next to the synthetic
  results: `fast` leaks (81% on 20 real sites) when the browser shares the data plane's CPU.
  `metered` is stated as a messaging class (31 of 900 real page loads completed), and the
  default is stated as it is (`--rate auto`).
- `avpn disconnect` also stops a supervisor started with `connect --foreground`, and
  confirms it exited.
- Device keys are created in a hidden directory and renamed into place, so a failed setup
  leaves nothing half-made behind.
- Cloud host setup probes systemd-creds sealing and, on hosts that cannot seal (systemd
  <250, e.g. Ubuntu 22.04), keeps plain keys with loud warnings: `[PLAINTEXT KEYS]` in
  `avpn cloud status`, explained by `doctor`.
- Carrier restarts after a stall wait a random 8–16 s instead of a fixed 12 s, drawn from
  the operating system's CSPRNG.
- WebRTC/STUN leak test in the managed lab.
- The busy-CPU leak reproduces locally: `throughput_bench.py --cpu-probe` scores the packet
  count and the timing per window; catch-up restores the count but not the timing
  (`docs/evidence/CPU_LEAK_PROBE.json`).
- Experimental (off by default): the cloak's wire clock, `AVPN_WIRE_CLOCK_PPS`, a first step of
  the busy-CPU fix: kernel-paced departure with decoys in empty slots
  (`docs/evidence/KERNEL_PACING.json`). With a fixed congestion window and slots kept on
  failed sends, it passes the busy-CPU probe 3 of 3; not yet confirmed on real websites.
  Fixed: under the clock the relay's BBR window collapsed to about 11 packets within a few
  minutes and stayed there (the clock delays every acknowledgement; the handshake set a
  sub-millisecond minimum RTT), so the downstream lost 96% and real pages failed (1 of 8
  loads). A clocked chain's relay now sends with the fixed window too: 8 of 8 loads, no
  reconnects (`docs/evidence/KERNEL_PACING.json`, `downstream_collapse`).
- Experimental: the relay clocks its downstream too (with `AVPN_WIRE_CLOCK_PPS` set on the
  relay; its egress link needs the `fq` qdisc): one grid per member session, every slot a
  WireGuard reply or a decoy the client's WireGuard drops. Measured on real websites (600
  page loads, interleaved, same day): with only the client clocked k-FP still scores 10.4%
  (p = 0.03, replicating the first re-run's 9.5%); with both directions clocked it scores
  5.15%, chance, equal to its shuffled-label mean (p = 0.58). Cost: page loads succeed 93.0%
  instead of 96.5% (heavy sites time out) and take 8.9 s instead of 8.1 s at the median.
  Caveats: downstream packets alone still score 9.3% (p = 0.03 uncorrected), and where the
  client-only residual sits did not replicate between runs (`docs/evidence/WF_REAL_RERUN2.json`).
- DC-net pads come from hardware only, in two kinds: one-time pad books for pairs who met
  in person and a forward-secure chain for pairs who cannot meet (computational). The
  derived `PRG(HKDF(K_ij))` pads are gone. A book is information-theoretic, conditionally
  on stated source assumptions (labelled `conditional-information-theoretic`), only when a
  contribution mixes in an assessed raw noise source and is handed over in person: raw
  CPU timing jitter (jitterentropy's recorder), assessed with NIST SP 800-90B `ea_non_iid`,
  health-tested, and Toeplitz-extracted, XORed with kernel and Nitrokey output drawn before
  the noise is recorded (defence in depth). The Nitrokey alone is computational: verified in
  its firmware source, its RNG command returns a ChaCha8 stream seeded once per boot.
  Contributions are sealed in transit to the partner's ML-KEM-768 + X25519 key and at
  rest under the Nitrokey's hmac-secret with a per-round key chain, so a seized disk
  opens no used round; a pad is used once, a used-up book stops the cell.
  `tools/padbook.py` assesses, makes, seals and combines them; cells are 4–60 members,
  rounds every 30 s.
- `avpn status --json` says whether traffic is actually protected, not just whether the
  supervisor runs: `protection` is "protected" only with fresh evidence of all three of the
  cloak's v2 key confirmation, a WireGuard handshake, and a probe answered through the whole
  chain (a DNS query from the app namespace to the exit's resolver every 5 s, retried after
  1 s when lost); otherwise "blocked", as `lifecycle` "connecting" or "reconnecting", with
  `stale` naming the missing evidence (`tools/protection.py`). In the lab it read
  "protected" after every page load through a working chain, and "blocked, reconnecting"
  within one load of the relay's cloak being frozen, recovering by itself when it resumed.
  This is what the GUI's "Connected" will show.
- The exit's DNS answers names under `.invalid` itself with NXDOMAIN and never forwards them
  (RFC 6761), so the path probe never reaches the upstream resolver.
- Docs separate key exchange from authentication (from the same independent audit): every
  layer refuses a classical key exchange, but the exit's DNS upstream still authenticates its
  resolver with classical WebPKI (a fourth named exception in `docs/PQ_INVENTORY.md`).
  `SECURITY.md` lists the known boundaries; the threat model says what the wire clock does
  not cover (the TCP fallback and the I2P front) and that a single owner's exit provider can
  tie exit activity to its customer; the README's tier 3 says it reduces hardware trust, not
  removes it.
- **Breaking: cloak protocol v2.** The relay now proves it holds the member's cloak key too,
  with an HMAC over the session's TLS exporter, before the client sends anything or reports
  "connected"; before, the server was authenticated only by its pinned ECDSA certificate,
  which a quantum-capable attacker could forge to impersonate it. Over the hybrid
  post-quantum exchange this makes the cloak's authentication post-quantum on both sides
  (from an independent audit, reviewed here). The TCP fallback no longer offers h2, which
  it never spoke. v1 and v2 cannot talk: re-sign chains (`avpn cloud chain --apply`, or
  `avpn init`) and enroll the new bundles with `--replace`; a v1 chain is refused at
  connect with that instruction instead of failing silently.
- Pad books, chains and the zk identity can no longer hand out a used pad or move an
  identity back an epoch when two handles or processes use them: every operation locks,
  reloads from disk and commits before returning (found by an independent audit;
  `docs/INCIDENTS.md`). Deniable store format v2: two header generations per layer and
  copy-on-write data, so a power loss no longer loses a layer (fresh stores only). A book
  made with an assessed raw source in person is now labelled
  `conditional-information-theoretic`: the source assumptions are stated, not claimed as
  proven.
- DC-net events are checked with a 72-bit truncated SHA-256 instead of CRC-8. CRC-8 is
  linear, so a two-sender collision could decode as an event nobody sent and a member could
  rewrite another's event (`docs/INCIDENTS.md`). Found by the first end-to-end cell run
  (`tools/dcnet_cell_lab.py`: four member processes, six pair books from padbook, frames
  over UDP, replayed through the Rust data plane; `docs/evidence/DCNET_CELL_LAB.json`).
- Deniable pad storage (`tools/padstore.py`): books and chains can live in nested layers of
  one random-looking store, each layer opened by the Nitrokey and its own passphrase (one
  touch; `padbook.py accept/status --store`). Under coercion a member opens the decoy, and
  nothing on disk shows more layers. One seizure is covered, not repeated disk images
  (`docs/evidence/PADSTORE_E2E.json`).
- ZK membership: `tools/zkid.py` keeps a member's forward-private secret at rest, only the
  current epoch's, stepped forward and saved before use; its hashes match the prototype's.
- DC-net pad files and envelopes have nothing in the clear (after TrueCrypt's volume header).
  A stored book is a random salt plus ciphertext, under a ChaCha20-Poly1305 over
  AES-256-GCM cascade. An envelope encodes its X25519 ephemeral with Elligator 2 (dirty
  keys, `tools/elligator.py`, checked against RFC 9380's vectors), so a lost USB stick or
  a seized disk shows random bytes, not who pairs with whom. Deniable multi-layer storage
  is designed, not built.
- `tools/padbook.py` keeps key material in buffers it zeroes in place: per-round chain
  state after use, the stored book's file key on exit, and every live secret on normal
  exit and SIGTERM/SIGINT/SIGHUP. The process is also non-dumpable (`PR_SET_DUMPABLE`,
  after VeraCrypt's RAM key protection and Tails' wipe on shutdown). CPython's own copies
  cannot be reached, so this reduces exposure; the guarantee is the Rust data plane's
  `zeroize`.
- The ZK membership design compares its nullifier with Zcash Orchard and Tornado Cash
  (both discrete-log, Tornado with a trusted setup). That comparison found a gap: v1's
  proof did not commit to the action it authorizes, so it could be replayed onto another
  one. The v2 prototype commits `SHA-256(request)`, and its nullifiers are forward-private:
  the member's secret walks a hash chain one step per epoch, so a seized device reveals
  no earlier epoch's nullifier (Tamarin: `formal/zk/forward_private_nullifiers.spthy`).
  Its run passed all eight checks over 2^20 members; a proof takes 458 s on a 2018
  laptop, against v1's 120 s (`docs/evidence/ZK_MEMBERSHIP.json`).
- DC-net models: pad exposure at the 4-member boundary (one colluder: no honest pad;
  two: the round's pad, modelled from the colluders' view), one-time pads used once and
  known only when leaked, and the chain's forward secrecy (unrolled to three rounds), each
  with mutants Tamarin must falsify; the whole set proves in about 7 minutes. End to end on
  the real Nitrokey and jitter source: both sides take identical pads, used and past rounds
  are refused, nothing readable at rest or in transit (`docs/evidence/PADBOOK_E2E.json`). The design doc explains
  the pads in plain terms and what a cell does not give; its old true-random pad estimate
  was per day, not per month. The 4-member floor is justified by the anonymity set (a
  sender is one of three against one colluder), not by pad exposure, which the models
  show is worth one round at any size.
- Both cloaks' status files report the QUIC path (window, round trip, losses);
  `throughput_bench.py --cpu-probe` records both directions and the client's reconnects;
  `wf_real.py` keeps each failed load's reason and the chain's logs.
- `avpn cloud chain --apply` shows a live checklist; PIN prompts are a desktop pop-up
  (also under sudo), and `avpn status` works without root while the service runs.
- Formal models now run and are proved in CI (Tamarin 1.12.0), each with a broken variant
  the prover must falsify. DC-net: frame authenticity across rounds, cancellation, pad
  secrecy without collusion. Mix-lane re-blinding: element and pad hidden from an entry-link
  observer. Both earlier model files had never been run (one did not parse). Sender
  anonymity is proved by hand (an equivalence the tools could not finish).
- Docs: README states the DNS trade-off (post-quantum-only DoT, Cloudflare default) and
  DC-net's status; `CHANGELOG.md` and `docs/INCIDENTS.md` added.

## v0.10.2 (14 Nov 2026)
- Fixes from the first real-internet rebuild:
  - a first hop's firewall admits the TLS/TCP 443 fallback;
  - chains are signed with installed copies;
  - server keys older than the release are renewed;
  - Nitrokey PINs are asked on the terminal;
  - `avpn status` says when the service waits for the PIN;
  - `avpn cloud status` lists OCI servers.
- Releases carry signed build provenance (Sigstore), checked before publishing.
- The release gate requires every verify run on the commit to pass.

## v0.10.1 (14 Nov 2026)
- Kill-switch tables are replaced atomically (the v0.10.0 race; see INCIDENTS).

## v0.10.0 (14 Nov 2026), superseded by v0.10.1
- Daemons confined with seccomp and Landlock; hardened systemd units.
- The HTTP/3 cloak runs on BBR, fixing the tunnel stall on real-systemd guests.
- Hardware wallet keys (Trezor, Ledger) with on-device verification.
- Forward-secret server links; post-quantum enforcement on every layer; provider
  diversity per chain; TLS/TCP fallback below a 1448-byte path.
- Real-website fingerprinting pilot evidence.

## v0.9.0 / v0.9.1 (12 Nov 2026), not published (verify failed)
- I2P front (`avpn init --front i2p`); Katzenpost mix lane (`avpn mix`) with
  post-quantum Sphinx; software verification plan.

## v0.8.0 (12 Nov 2026)
- Per-hop shaping: paced, encrypted constant-rate cells on every server-to-server link.
- Self-healing chains (standby exit failover); oblivious control plane.

## v0.7.0 (12 Nov 2026)
- Constant-rate stream classes (`metered`, `standard`, `fast`, `line`); one defense
  posture, strong.
- TCP/TLS fallback; DNS blocklist.
- AVPN/Mesh: hardware identity, signed descriptors, directory, blind-RSA credits.

## v0.6.0 (10 Nov 2026)
- The carrier is camouflaged as HTTP/3; DAITA machine and handshake fixes.

## v0.5.0 (9 Nov 2026)
- Server logs kept in RAM from first boot, checked and enforced.

## v0.4.0 (9 Nov 2026)
- Free-endpoint onboarding, automatic chaining, always-on constant-cell padding.

## v0.3.1 – v0.3.3 (8–9 Nov 2026)
- First public release: one-step install.

# Changelog

User-visible changes per release, newest first. Defects that affected security, privacy,
availability or a published claim are in [docs/INCIDENTS.md](docs/INCIDENTS.md). Every
measured figure in the docs names the version it was measured on.

## Unreleased
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
  WireGuard reply or a decoy the client's WireGuard drops. The real-website re-run had
  located the clock's residual leak in the downstream (k-FP 10.5% on downstream packets
  alone, p = 0.0099 over 100 shuffled-label runs; upstream alone 9.0%, not significant).
  Not yet re-measured with both directions clocked.
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

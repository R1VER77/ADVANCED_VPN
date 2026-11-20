# Incidents

Every defect found in a release, in CI or in a live deployment that affected security,
privacy or availability, or a claim the project made. Each entry says what was affected,
what was not, how it was found, and the fix. Newest first. Reports go through GitHub's
private vulnerability reporting (see [SECURITY.md](../SECURITY.md)).

## Open

### Website fingerprinting leaks on a busy CPU (found 13–14 Nov 2026)
- **What:** with the browser and the client's data plane on the same CPU cores, as on most
  laptops, k-FP recognised 81% of 20 real websites through the `fast` class (chance 5%;
  9.9% without that contention).
- **Cause:** the shaper's grid skips ticks it misses (`decoy_expiry()` in
  `vendor/gotatun/src/device/daita/types.rs`), so the missed ticks trace the page's own
  CPU work.
- **Not affected:** packet sizes (constant), the server-to-server links (separate hosts),
  the mix lane.
- **Measured mitigations** (none sufficient):
  - priority: 75%;
  - a 50 ms catch-up: about 50%;
  - a dedicated core or `SCHED_FIFO`: 27–42%.
- **Status:** documented in `docs/cli/threat-model.md` since it was measured. **The README did
  not carry it until 15 Nov 2026, while showing only the synthetic 3.3%/1.7% results; that
  omission was itself a claim-integrity defect.** The fix is the first technical priority:
  measure it with a local harness, then move departure timing out of a userspace thread
  that competes for the CPU.
- **Reproduced locally (15 Nov 2026):** `throughput_bench.py --cpu-probe` loads the client's
  cores on a random schedule and finds it on the wire in 3 of 3 runs (count AUC 0.92–1.00,
  p = 0.0005). With `AVPN_CATCH_UP_MS=50` the packet count is restored, but the gaps between
  packets still give the load away: wider gaps in nearly every loaded window (gap-spread
  AUC 0.001–0.07, where 0.5 is chance), p = 0.0005 in each run. A fix must remove both. The probe scores
  both and is the fix's regression gate.
- **Fix in progress (15 Nov 2026):** the cloak's client-side wire clock (`AVPN_WIRE_CLOCK_PPS`,
  off by default) hands every slot of a fixed grid to the kernel 30 ms ahead, with WireGuard's
  datagram or a decoy, and the `fq` qdisc releases each on time.
  - **Result so far:** on the real carrier it turns perfect separation into a marginal signal,
    left at load transitions.
  - **Found on the way:** kernel pacing alone exposes a CPU power-state side channel (idle
    cores wake the release timer late), which awake cores remove and power QoS only reduces.
  - **Since `34004ba`** (quinn's congestion control off while the clock runs, and slots kept on
    failed sends), the probe finds **no leak in 3 of 3 runs** (count flat at 3,256–3,270 per
    window, loaded or idle). A consistent but not significant lean in the timing features
    remains, as the power-state effect would leave.
  - **Real websites (15–16 Nov 2026):** the client-side clock alone left 9.5% and then 10.4%
    (chance 5%, significant both times). Clocking the relay's downstream too brought k-FP to
    5.15%, equal to its shuffled-label mean (p = 0.58), in the same interleaved run. Cost:
    page loads succeed 93.0% instead of 96.5% and take about 0.8 s longer.
  - **Not yet a fix to claim:** one 20-site closed world on one machine and network; downstream
    packets alone still score 9.3% (p = 0.03 uncorrected); heavy sites time out more. The clock
    stays off by default, and `fast` is still not claimed while the device is busy.
- **Evidence:** `docs/evidence/WF_REAL_PILOT.json`, `docs/evidence/CPU_LEAK_PROBE.json`,
  `docs/evidence/KERNEL_PACING.json`, `docs/evidence/WF_REAL_RERUN.json`,
  `docs/evidence/WF_REAL_RERUN2.json`.

## Fixed

### The OCI exit kept its private keys as plain files (14–20 Nov 2026)
- **What:** a server whose systemd could not seal with systemd-creds fell back, by design and
  with a loud warning (Bug 9a), to plain root-only key files. The owner's exit (OCI Always
  Free, Ubuntu 22.04, systemd 249, no vTPM, a host shared with another workload) ran that
  way from 14 November: its TLS identity, KEM, paced-link, WireGuard and cloak keys were
  readable by root on that host and by anyone with its disk, a snapshot or a backup.
- **Not affected:** the relay (TPM2-sealed), the client (Nitrokey), and traffic secrecy
  against anyone without those keys. Someone holding them could impersonate the exit to a
  client that trusts it, or decrypt the link keys sent to it in a chain bundle.
- **How found:** the owner, reading the chain summary's `PLAINTEXT KEYS` on 20 November.
- **Fix:** keys of hosts without a usable TPM2 are now locked to the operator's Nitrokey
  (above, and docs/HARDWARE_BOUND_SESSIONS.md), and plain or host-key-only keys are replaced,
  never re-wrapped: deleting a file on a cloud disk does not erase earlier copies. Done live
  on 20 November (chain 20261120T092141Z): the exit made new keys, none of them in plain
  files; with its RAM-held data key removed it refused to start (`Locked`) until
  `avpn cloud unlock` (PIN + touch); the client enrolled the new chain, so the old keys
  open nothing.

### A hardware-protected client could not connect from a terminal (found 20 Nov 2026)
- **What:** phase 2 of hardware-bound sessions runs a short-lived signer for the PIN and
  touch. The supervisor gave it the request on stdin, so the signer saw no terminal and,
  outside a desktop session or the systemd service, refused: `sudo avpnctl connect` failed
  with "no terminal, desktop session or systemd password agent for the PIN". Its "touch the
  key" message also went to a captured pipe instead of the person.
- **Not affected:** the service (`systemctl start advanced-vpn`, PIN through `avpn unlock`)
  and the desktop dialog; no key or session was weakened: it failed closed.
- **How found:** the owner's first connect with a physical Nitrokey after phase 2. Every test
  supplied the PIN and touch through stubs or emulated firmware, never a terminal.
- **Fix:** the request goes on a pipe of its own (`--request-fd`); stdin and stderr stay the
  caller's; the reply and refusals come back on stdout. `tools/test_session_auth.py` runs the
  real launch path under a pseudo-terminal and fails on the old one.


### Mesh descriptor signatures could never be verified (found 20 Nov 2026)
- **What:** `tools/mesh.py` imported ML-DSA-65 from `cryptography...asymmetric.ml_dsa`, a
  module the pinned library (cryptography 49/50, `mldsa`) does not have. Every real
  `verify_descriptor` call raised `SystemExit` instead of returning; `keyguard mesh-sign`
  imported the same name, so signed publishing failed too. The claim that unverified
  descriptors never enter a directory held only because nothing could be verified.
- **Not affected:** the VPN's data plane, enrollment and the TLS layers (they use
  `cryptography`'s `mldsa` or Rust). Beacons refused malformed descriptors before
  reaching the signature check.
- **How found:** building gateway key consistency on descriptor signatures. Every mesh test
  replaced `verify_descriptor` with a stub, so no test had ever run it.
- **Fix:** the right module (`MLDSA65PublicKey`, a 32-byte seed or PKCS#8 for signing), and
  `tools/test_gateway_consistency.py`, which signs and verifies real descriptors with no
  stub and fails on the old import. The same audit found the mesh reading its identity from a
  file nothing wrote (`~/.config/advanced-vpn/operator.pub` as a raw key) and asking for a
  plaintext key to seal: it now uses the operator key `avpn init --vault` already keeps (the
  vault's `operator-mldsa65.pub`, or the bundles' JSON `operator.pub`) and its sealed
  envelope (`keyguard mesh-sign --role operator-mldsa65`); a test signs and verifies a
  descriptor through that whole path. The node key in a descriptor stays the operator's until
  enrollment returns the server's own.

### Pad tools could reuse a one-time pad; the information-theoretic claim overstated its proof (16 Nov 2026)
- **What:** an independent audit (16 Nov 2026) found four state bugs in the pad and identity
  tools, each reproduced by a counterexample on the pushed code:
  - two `Chain` handles opened before either took a round both returned that round's pad;
  - two concurrent `Book` consumers could both read a record before it was advanced and
    erased: one-time pad reuse;
  - a stale `zkid.Identity` handle could write an earlier epoch back over a later one,
    restoring an earlier membership secret at rest and undoing forward privacy;
  - a torn write of a deniable store's single header slot (power loss) lost the layer.
  The design doc and padbook also called a book "information-theoretic" when its sources'
  assumptions were only supported, not established: the extractor's seed is the Nitrokey's
  ChaCha8 output (pseudorandom, not uniform), drawing other sources first establishes order,
  not independence, and an SP 800-90B estimate is evidence, not a proof.
- **Not affected:** anything deployed. These tools are reachable from no command of the
  VPN; no cell has run outside the lab. Both e2e runs used one process at a time.
- **Fix:** every take, advance and epoch step locks, reloads its state from disk, checks
  against that and commits before returning a secret (`tools/state_transaction.py`); renames
  fsync their directory; the deniable store's v2 format keeps two header generations per
  layer and writes data copy-on-write (fresh stores only; v1 is not migrated). The claim is
  now `conditional-information-theoretic`, with the assumptions stated in
  `docs/DCNET_CONTROL_DESIGN.md` §2. The audit's counterexamples now fail on the code; its
  13 new tests catch the bugs when the fixes are removed (checked by mutation). Real
  Nitrokey: `docs/evidence/PADSTORE_E2E.json`.

### DC-net collisions could decode as an event nobody sent (16 Nov 2026, before use)
- **What:** an event's check was CRC-8 with a zero start and no final XOR, which is linear:
  the XOR of two valid events carries a valid CRC, and the zero padding stays zero. When
  two members sent in the same round with kinds 1 and 2, 1 and 3, or 2 and 3 (37.5% of
  two-sender collisions with random kinds), the round decoded as a third, plausible event
  instead of "garbled". For the same reason a disruptive member could XOR in a
  CRC-consistent difference and turn an honest member's event into another valid one,
  undetected. `docs/DCNET_CONTROL_DESIGN.md` §4 claimed collisions were detected.
- **Not affected:** anything deployed. DC-net is a library and a pad tool, reachable from no
  command (its status line), and no cell has run outside the lab. Sender anonymity does not
  depend on the check.
- **How found:** the first end-to-end cell run (`tools/dcnet_cell_lab.py`: four member
  processes, six pair books, frames over UDP) decoded 3 of 4 collisions as events; its
  Rust replay agreed, so both implementations shared the flaw. The unit test for collisions
  had used two events of the same kind, whose kinds XOR to 0, an invalid kind.
- **Fix:** the check is a 72-bit truncated SHA-256 of the event (`event_tag`, in the 9 bytes
  that held the CRC and the zero padding). Two events, or an event and a difference chosen
  without knowing it, now pass with probability 2^-72. New tests reproduce both failures on
  the old code; the cell lab now decodes every collision as garbled
  (`docs/evidence/DCNET_CELL_LAB.json`).

### Phase 0 patch: systemd-creds probe would abort host setup (15 Nov 2026, before release)
- **What:** the probe for systemd-creds sealing wrote a root-owned file in `/tmp` and removed
  it as the unprivileged user. `/tmp` is sticky, so on hosts where sealing *works*
  (systemd ≥250) the removal fails, and `set -e` aborts `avpn cloud host setup`.
- **Not affected:** any release; it was caught in review before merging.
- **Fix:** the probe pipes the credential through `systemd-creds encrypt - - | decrypt - -`
  and checks that it decrypts to what was sealed. Tests refuse any file argument.

### Kill-switch race in v0.10.0 (14 Nov 2026)
- **What:** the supervisor and an application launch could rebuild the namespace's kill-switch
  table at the same moment, each seeing it absent; nftables then appended a second copy.
  The drift watchdog remembered the doubled copy and kept "restoring" it, which can trip
  its tampering guard and stop the data plane on purpose.
- **Not affected:** no traffic left outside the tunnel. Every table load was one atomic
  transaction, and a doubled table blocks exactly like a single one; proven in a network
  namespace. The harm was availability (fail closed).
- **Fix (v0.10.1):** every table load resets the table inside the same transaction, at all
  five places that write one. The race went from 200/200 doubled to 0/200.
- **Also fixed:** v0.10.0 was published although its tag's verify run failed, because the
  release gate accepted any passing run on the commit. Since then every verify run on the
  commit must pass, and a public tag is never moved: a failed release is followed by the
  next patch. v0.10.0 carries a "superseded" banner and the disclosure is on v0.10.1.

### Tunnel stall on real-systemd KVM guests (8–14 Nov 2026)
- **What:** the cloak's QUIC NewReno congestion window collapsed after early losses, sends
  stalled, the client's carrier watchdog killed the carrier, and the relay's single
  session slot timed out: a self-sustaining loop.
- **Not affected:** confidentiality, and the kill switch (traffic was blocked, not leaked).
- **Fix (v0.10.0):** the cloak runs BBR. Since then every transfer passed in the valid KVM
  runs, with 65 of 66 soak reconnects. The one miss is still being investigated.

### Inter-relay cover claimed before it existed (v0.7.0 docs, corrected 12 Nov 2026)
- **What:** v0.7.0's documents said cover traffic ran on the links between servers. It ran
  only between the client and the first hop.
- **Found:** v0.8.0 measured the inner link before fixing it: 0.5 pps idle, up to 3,419 pps
  during a download (`RATE_CLASSES.json`, `inner_link.before_v0_7_0`).
- **Fix (v0.8.0):** paced, encrypted constant-rate cells on every server-to-server link
  (`src/link.rs`). Since then every figure names the version it was measured on.

### The provider's audit log kept the client's address (9 Nov 2026)
- **What:** CloudTrail (always on, 90 days) recorded the client's address as the caller of
  every API command, and inside every firewall rule that named it.
- **Fix (v0.4.0):** the first hop is open to any address (WireGuard answers only enrolled
  peers); later hops admit only servers; SSH from the operator closes after `avpn cloud
  chain`.
- **Remaining, by nature:** provider commands run while not connected still record the
  caller's address (`avpn help privacy`).

### Binaries a server could not run (9 Nov 2026, caught before damage)
- **What:** a Debian 13 build needs glibc 2.38+; the Ubuntu 22.04 exit has 2.35, so setup
  would have broken the exit.
- **Fix (v0.4.0):** `host setup` compares the server's glibc with the package before
  uploading.

### Privilege escalation through runtime files (8 Nov 2026, before the first public release)
- **What (High):** root published runtime files into a directory the unprivileged service
  could write, then called path-based `chmod`/`chown` after the rename. A compromised data
  plane could swap in a symlink and redirect root's `chown` (e.g. to `/etc/shadow`).
  Certificate rotation re-armed it every 6 hours.
- **Fix:** create with `O_EXCL|O_NOFOLLOW`, set mode and owner through the descriptor, then
  rename. `RootFileHandoffTests` simulates the race and failed before the fix.
  Details in [AUDIT_2026-11.md](AUDIT_2026-11.md).

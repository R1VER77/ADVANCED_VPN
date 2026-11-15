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
  - **Not yet a fix,** and `fast` is still not claimed while the device is busy.
- **Evidence:** `docs/evidence/WF_REAL_PILOT.json`, `docs/evidence/CPU_LEAK_PROBE.json`,
  `docs/evidence/KERNEL_PACING.json`.

## Fixed

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

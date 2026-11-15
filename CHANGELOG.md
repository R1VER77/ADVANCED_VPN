# Changelog

User-visible changes per release, newest first. Defects that affected security, privacy,
availability or a published claim are in [docs/INCIDENTS.md](docs/INCIDENTS.md). Every
measured figure in the docs names the version it was measured on.

## Unreleased
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

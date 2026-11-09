# Managed v0.2 validation — 2026-11-07

## Update — 2026-11-08 (post-quantum authentication, opt-in cap)

All suites were rerun on the unchanged v0.2 tree first (all passed; the
reproducibility rerun produced the same three binary hashes as below). Then:

- **Authentication is ML-DSA-65 only** in both QUIC layers. A Rust test performs
  real mutual handshakes: a matching ML-DSA-65 deployment authenticates, and a
  fully consistent, correctly pinned ECDSA deployment is refused. Removing the
  restriction makes the test fail (checked by mutation). The legacy routed test
  adds a `classical` identity issued by the genuine authority, which is rejected.
- **Enrollment bundles are hybrid-signed** (Ed25519 + ML-DSA-65; both required).
  Tests reject a forged or missing half; dropping the ML-DSA check fails them.
- **The daily cap is opt-in (default none).** `tools/budget_test.py` first
  reproduced three defects on the old code: near-idle carrier restarts consumed
  a 256 MiB cap in 4 restarts, an exhausted cap ended the supervisor, and a cap
  and kernel meter were applied by default. After the fix: 12 restarts reserve
  only the counted bytes, exhaustion blocks while the supervisor stays alive and
  resumes when the cap is raised, and the default installs no meter. CI runs it.
- Current counts: 6 Rust tests and 23 Python tests; legacy and managed namespace
  tests pass with ML-DSA identities. Lab supervisors now run with exactly the
  installed unit's capability bounding set (read from the unit file) and
  no_new_privs.

### Installed-service validation in Debian 13 VMs ([evidence](evidence/VM_VALIDATION.json))

`tools/vm_validation.py` installs the package with the real installer in three
KVM guests, enrolls signed bundles and drives them through the QEMU guest agent.

| Check | Result |
|---|---|
| Install / enroll | All three roles; units not enabled by install |
| Internet through owned exit | HTTPS 200 with DNS over TLS to the real Quad9 |
| Default cap | None: no kernel meter; 100 MiB transfer, carrier stayed up |
| MTU | Underlay 1419 refused (apps stay blocked); 1420 connects |
| Soak, 30 min | 55 disconnect/reconnect cycles: blocked while down 55/55, recovered 55/55 |
| Whole-device reboot | Guard finished (5.35 s) before systemd-networkd (6.03 s); zero client frames outside policy; tunnel up; DNS via resolved and HTTPS 200; direct egress blocked; blocked after disconnect; cleartext only after explicit reset |
| Throughput (iperf3, TCP) | Before fix: 8.8 Mbit/s clean, 1.77 at 50 ms/1% loss, 0.31 at 150 ms/1% loss. After fix: **71.8 Mbit/s** clean (2-vCPU guests), 1.87 at 50 ms/1%, 1.03 at 150 ms/1% |

The VMs found three defects that namespace tests could not, because a user
namespace grants its root every capability: (1) the runtime directory was
`chown`ed before `chmod` and the unit has no `CAP_FOWNER`, so the installed
service never started; (2) the unit lacked `CAP_KILL`, so the supervisor crashed
whenever it stopped its unprivileged children (rotation, disconnect, profile
change); (3) whole-device DNS failed closed under systemd-resolved. All three are
fixed; (1) and (2) are now caught by the managed namespace test (mutation-checked),
(3) by the VM run.

**Throughput cause, proven.** `tools/throughput_bench.py` (namespaces, 32 MiB,
SHA-checked) isolated each factor:

| Run | Throughput |
|---|---|
| Full tunnel, old per-session bound (2 MB/s, 2000 pkt/s) | 9.96 Mbit/s |
| WireGuard + DAITA `balanced` carrier only | 961 Mbit/s |
| Full tunnel, bound raised to the config maximum | 294 Mbit/s |
| Full tunnel, `strong` (Tamaraw constant-rate) | 0.34 Mbit/s |

The fixed one-second bound at every hop was the limit. It dropped whatever exceeded
the window, which forced TCP retransmissions. Generated profiles now use the
configuration maximum (100 MB/s, 100,000 pkt/s). CI fails below 50 Mbit/s; a mutant
with the old bound measured 9.91 Mbit/s and failed.

On lossy links, plain TCP without the VPN, under the same netem and the inner MTU,
gave medians of 2.95 Mbit/s at 50 ms/1% and 1.30 Mbit/s at 150 ms/1% (5 runs each,
wide spread). TCP's loss response dominates there. Links are local; `wan_tested`
stays false.

### Key custody: device-generated keys, hardware operator ([evidence](evidence/HARDWARE_MANAGED.json))

Every device runs `avpn request`; private keys are generated and protected there
and never transferred. Bundles carry only public data and the WireGuard PSK,
hybrid X25519 + ML-KEM-768 encrypted to each recipient. With the physical
Nitrokey, four PIN + touch operations covered the whole flow:

1. The client generated its keys and sealed them before anything was written. No plaintext key file existed at any point.
2. The operator signature: a FIDO2 assertion from the non-exportable Ed25519 credential, plus ML-DSA-65 from an operator key sealed under that credential.
3. Enrollment checked both halves, decrypted the PSK and resealed the WireGuard key, then deleted the one-time KEM key.
4. A cold start unsealed the keys into memory and carried private traffic. It ran under the unit's capabilities, with non-dumpable data-plane processes.

In the VMs ([evidence](evidence/VM_VALIDATION.json), `key_custody_run`), each
guest held only `systemd-creds` files (host key; no TPM2 in the guests), zero
plaintext key files, and the whole-device reboot passed with keys decrypted at boot.

Unit tests cover all of the following, using a synthetic authenticator for the FIDO2 checks:
- An assertion is rejected for a missing PIN (UV) flag, a missing touch (UP), the wrong relying party, the wrong origin, the wrong key or the wrong message.
- A forged or missing half of the hybrid operator signature is rejected.
- A bundle made for another device is rejected, including for the exit, which has no WireGuard key.
- The PSK can't be opened with another device's KEM key.
- The controller makes itself non-dumpable before anything else.

Removing the PIN check or the device-binding check makes these tests fail. Counts: 6 Rust tests and 34 Python tests.

**Service PIN prompt.** In an installed Debian 13 guest, a transient unit with the
real unit's sandbox and capability set called `keyguard.pinentry()`. An agent
following systemd's ask-password protocol, standing in for the boot console,
answered it, and the exact PIN arrived (hashes compared). Unit tests cover the
terminal, service, unanswered and no-source paths. Adding `--accept-cached` makes
them fail.

### Multi-hop chains and no retained data ([evidence](evidence/MULTIHOP.json))

`tools/throughput_bench.py --hops N [--switch-to M]` runs the real request → init →
enroll flow for 1, 2 and 3 hops, switches chains with `enroll --replace`, and audits
three things on every run:
1. Raw ingress observers: the random payload marker was never seen by any server,
   and the client's address was seen only by the first hop.
2. Device keys were unchanged across a switch, and traffic was blocked during it.
3. No server wrote any persistent file during the session, and none held the
   client's IP or the payload.

Measured: 1 hop 362 Mbit/s, 2 hops 258, 3 hops 166 (switch runs 3→2 and 1→3).
Moving the status file back to disk made the audit fail (mutation check).

The first 3-hop attempt failed. QUIC needs at least 1200 bytes of UDP payload,
and the original per-layer shrink broke that floor. The layer budget is now
built from the inside out (1312/1256/1200).

In installed Debian 13 VMs, after real traffic, the relay and exit wrote nothing
under `/etc/advanced-vpn` and had zero journal lines for the VPN units. Boot
ordering is now taken from systemd's in-memory timestamps, because the units no
longer log: the guard was active at 5.74 s, before systemd-networkd started at 6.32 s.

### First real-internet run ([evidence](evidence/WAN.json))

One hop, over the real internet: a local Debian 13 client VM on a home connection
(via a consumer VPN) to an OCI exit in `me-dubai-1`. The exit runs alongside other services
on an always-free E2 micro (Ubuntu 22.04). The operator signed with the Nitrokey.

| Check | Result |
|---|---|
| Exit IP | The internet saw the exit's IP (`203.0.113.80`), not the home IP |
| DNS and HTTPS | Resolved through the tunnel; HTTPS 200 |
| Speed | 12.3 Mbit/s download, about 340 ms TCP round trip |
| After disconnect | DNS and HTTPS both blocked |
| Exit after traffic | No persistent files written, zero journal lines, client IP in no state file; co-hosted services unaffected (free RAM 443 → 406 MB) |

This run found two real defects that the lab could not:
1. **DNS leak in app mode.** glibc's `nss-resolve` and the D-Bus system bus reach the
   host's systemd-resolved over Unix sockets, which a network namespace doesn't isolate.
   Apps' lookups therefore went outside the tunnel. Fixed by hiding those sockets in
   the app's mount namespace. The managed test now stands up fake resolver sockets and
   fails if an app can reach one (mutation-checked).
2. **Desktop PIN prompt.** Desktop apps run inside systemd scopes, so the new
   service-PIN path wrongly took over from the desktop dialog. Fixed, with a regression
   test that fails if the order is reversed.

**Two hops over the internet** ran after that: an AWS relay in `eu-north-1` (t3.micro,
Debian 13, NitroTPM AMI, keys sealed with `systemd-creds` `host+tpm2`) → the OCI exit.
The client and exit switched chains with `enroll --replace`.
- The internet saw the exit's IP; DNS and HTTPS went through the tunnel; about 400 ms
  round trip and 4.2 Mbit/s; both blocked after disconnect.
- **On the real internet, the exit's only inbound source was the relay.** Your IP
  never appeared there.
- Neither server wrote a persistent file or a journal line, and neither held the
  client's IP.

This run found two more defects, both fixed:
1. `systemd-creds --with-key=auto` used the host key without saying so when the TSS2
   libraries were missing. `request` now seals with `host+tpm2` explicitly when the TPM
   is usable, and records the choice.
2. Public-hop listeners bound the public IP, which NAT clouds don't put on the
   interface.

**Three hops over the internet** also pass: AWS relay → AWS middle (`t3.micro`,
NitroTPM, keys sealed with `host+tpm2`) → OCI exit. The relay, exit and client switched
chains with `enroll --replace`.
- The internet saw the exit's IP; DNS and HTTPS went through the tunnel; about
  397 ms round trip and 2.1 Mbit/s; both blocked after disconnect.
- **On the wire, the exit received only from the middle, and the middle only from the
  relay.** Your IP never reached either.
- No server wrote a persistent file or a journal line, or held your IP.

The 2026-11-07 results below were measured before these changes.

The local integration test passed with actual GotaTun 0.10.2 WireGuard/DAITA,
Maybenot 2.2.2 public machines and both original mandatory-hybrid QUIC layers.
This is a development release with measured namespace behavior, not a production
security certification. [Machine-readable result](evidence/MANAGED.json).

## Verified behavior

The test created isolated client, relay, owned-exit and destination namespaces.
Signed enrollment supplied the complete network configuration. An application
resolved a name through its mounted system resolver, the tunnel and a controlled
TLS-authenticated DNS upstream, then exchanged its private marker through exit
NAT. The marker was absent from physical carrier capture. No laptop network or
DNS settings changed.

| Check | Result |
|---|---|
| WireGuard carrier | Authenticated handshake with PSK; both QUIC layers retained |
| DAITA | Nonempty data packets had one UDP payload size, 1372 bytes; padding and decoys counted in both directions |
| Profiles | Balanced and strong both connected; disabling DAITA rejected |
| Network-facing service identity | UID 1 in subordinate-ID namespace mapping, zero effective capabilities |
| Private key handoff | Immutable descriptors; no raw private keys in service runtime directory |
| Controller/child crashes | Child restarted under guard; controller death killed data-plane children and retained isolation |
| Disconnect | Application traffic remained blocked |
| Whole-device leak test | Demonstrably working fallback route blocked after disconnect; explicit unlock restored it |
| DNS bypass / IPv6 | Blocked |
| Certificate rotation | Fresh leaf under enrolled SPKI accepted after rotation, without online authority key |
| Enrollment | Wrong operator, tampering, traversal and unsigned extras rejected |
| Budget persistence | Restart and clock rollback could not reset the allowance |

Empty keepalives and handshake messages remain identifiable. Padding/decoy
counters demonstrate engine activity, not statistical traffic-analysis resistance.
The exact counters and three release binary hashes are in the result file.

Four Rust tests and eighteen Python tests pass. Formatting and Clippy with
warnings denied pass. The legacy routed protocol test also passes on v0.2,
including classical-only/anonymous TLS rejection, peer rejection/revocation,
tampering/replay rejection and recovery after relay loss. See the
[legacy regression](evidence/LEGACY_REGRESSION_V02.json); its local RTT and stream
measurements do not measure DAITA performance or WAN performance.

## Dependency and hardware scope

The pinned dependency graph has zero known vulnerabilities in the recorded
[RustSec scan](evidence/MANAGED_RUSTSEC.json). RUSTSEC-2025-0141 reports that
`bincode 1.3.3`, a transitive Maybenot dependency, is unmaintained. It is retained
explicitly; no arbitrary remote defense-machine import or UAPI is exposed.
This warning and the zero-vulnerability result do not establish that the code
is free of exploitable bugs. The updated certificate-root bundle and rand pin
resolve the findings encountered during development. Current
[dependency/license inventory](evidence/MANAGED_DEPENDENCIES.json).

The pre-existing [physical Nitrokey proof](evidence/HARDWARE.json) covers the
FIDO2 envelope and sealed-memory handoff of v0.1 TLS keys. Managed v0.2 extends
that mechanism to WireGuard private key/PSK material; its envelope/descriptor
tests pass. A complete managed hardware-unlocked installed-service session has
not been demonstrated. Keys exist in endpoint memory after authorization; they
are not hardware-native non-exportable TLS or WireGuard keys.

## Remaining deployment validation

No cloud activation or change to the laptop's existing VPN was performed. Before
general use, validate real WAN MTU/throughput and a sustained disconnect/reconnect
soak, cold-boot guard ordering and recovery on the target distribution, installed
service hardware PIN UI, and application/desktop isolation. Initramfs networking
is outside the tested boot guard. IPv6 is deliberately blocked.

Public Maybenot machines need a separate classifier evaluation before making
claims about resistance to traffic analysis. This release does not implement
provider attestation, defend a trusted endpoint against its root/hypervisor, or
prove a cloud provider cannot log metadata. Consult [SECURITY.md](../SECURITY.md).

# IPv6 tunneling design — gap #6

Status: design approved 21 November 2026 (delegated authority, decision
D009 in [DECISIONS.md](DECISIONS.md)); implementation staged in §5.
Companion evidence: the dual-stack leak suite
(`tools/ipv6_leak_suite.py`, delivered 21 November 2026) already runs
its gates against the *current* fail-closed posture and passes.

## 1. Why IPv6 is blocked today (the honest posture)

The current data plane refuses IPv6 outside the tunnel — fail-closed —
for the same reason every commercial VPN's IPv6 story is a leak
catalog: if the tunnel carries only IPv4 and the local network offers
IPv6, dual-stack clients happily route AAAA traffic around the tunnel
(DNS leak → direct IPv6 → real address). Refusing is correct; shipping
IPv6 *half*-working would be worse than not shipping it.

The fail-closed posture is already tested from both sides: the leak
suite's gates assert (a) that a v6-capable network with the tunnel up
produces zero IPv6 egress from the namespace, and (b) that a v6-only
service inside the namespace fails loudly rather than falling back to
any direct path.

## 2. What shipping IPv6 actually requires

Not "support IPv6" as one item, but four independently-failable pieces:

1. **An IPv6 exit address.** The exit needs a v6 allocation from its
   provider. Oracle Cloud Always Free includes an IPv6 /64 per VCN;
   AWS bills per-IPv4 and provides v6 at no charge; small providers
   vary. A v4-only exit cannot serve a dual-stack client — the
   descriptor must say which, and chain planning must not build a
   dual-stack chain through a v4-only exit.
2. **The tunnel carrying v6 payloads.** The cloak and inner QUIC links
   are v4-transport tunnels carrying IP packets; v6 packets ride as
   inner payloads with no transport change. The MTU arithmetic changes
   (1280-byte v6 minimum vs the current 1380-byte padded cell
   payload — v6 fits inside the existing cell with room to spare, and
   v6-in-v4 fragmentation never appears because the cell is already
   the MTU unit).
3. **The namespace's dual-stack routing.** Inside the protected
   namespace: a v6 default route through the tunnel interface, v6 DNS
   through the in-tunnel DoT forwarder (AAAA resolution is where most
   commercial "IPv6 leak" bugs live), and the kill switch extended to
   drop v6 outside the tunnel — today it drops v4 outside the tunnel
   and v6 everywhere, which is exactly right for the v4-only tunnel
   and must become "drop v6 outside the tunnel" when the tunnel
   carries v6.
4. **Exit-side egress policy.** The exit's `exit_policy`
   ([PATH_SELECTION_DESIGN.md](PATH_SELECTION_DESIGN.md) §2) admits
   ports, not address families; it needs a family dimension (admit
   v4 only / v6 only / both) so a v6-hostile exit never receives
   v6-destined flows it would silently drop.

## 3. The design

**Client-side: dual-stack inside, single-stack outside.** The namespace
gets both a v4 and a v6 default route into the tunnel. The outer
transport (client↔entry) stays on whichever address family it uses
today — v4 in the common case, v6 when the entry is v6-reachable
(hotel networks that are v6-only exist; the entry descriptor records
both families and the client prefers what its local network offers,
which is itself a fingerprint-dimension the cloak's persona logic
already knows how to reason about).

**Exit-side: family-honest descriptors.** The exit descriptor gains
`v6: {prefix: 2001:db8:…/64, egress: both|v4|v6}` next to its v4
address. Chain planning (§3 of PATH_SELECTION) refuses a dual-stack
chain through an exit without v6 egress. The eligibility probe
(`avpn stream-check`) records which family the service saw — a service
that resolves AAAA but blocks the exit's v6 prefix is a real,
measurable case (mechanism 1 applies to v6 ranges too, and v6
allocations are *more* stable than v4, so a listed v6 prefix stays
listed longer).

**DNS: AAAA inside the tunnel only.** The in-tunnel DoT forwarder
answers AAAA; the namespace's resolv.conf points at it; no v6 DNS
reaches any direct path. This is the single highest-leverage gate: the
leak suite's `aaaa_inside_tunnel_only` gate is the one commercial
implementations keep failing.

**Kill switch: per-family symmetry.** The guard drops, per family:
v4 outside the tunnel (unchanged), v6 outside the tunnel (new — was:
v6 everywhere), nothing else. The leak suite's positive control
(protection off → v6 visible) and negative control (protection on →
v6 visible only through the exit) pin both directions.

**Rollout shape: v6-length-preserving cells.** The constant-rate
stream's cell size is a security parameter (fixed-size, padded); v6
inner packets are padded to the same 1380-byte payload the v4 path
uses. A v6 packet's 40-byte header vs v4's 20 means slightly less
payload per cell — the rate classes do not change, the effective goodput
per cell drops ~2.7% for v6-dominated flows, which the throughput
bench records per family rather than hiding.

## 4. What this design refuses

- **No 6in4/6to4/NAT64 translation at the client.** Translation
  either leaks (6to4 to a public relay is a direct egress) or lies
  (NAT64 makes v6-only sites appear as v4 from the exit). The tunnel
  carries native v6 payloads or the namespace stays v4-only.
- **No v6 split-tunnel by destination.** Same rule as v4: everything
  in the namespace rides the tunnel, no exceptions for "just this
  v6 site" — a per-family exception list is a deanonymization oracle.
- **No silent fallback.** If the exit has no v6 and a v6-only service
  is contacted, the connection fails loudly (current behavior, kept).

## 5. Implementation stages and gates

| Stage | Work | Gate |
|---|---|---|
| 0 (done) | Leak suite against the fail-closed posture | 19 gates green; v6 egress impossible with the tunnel up |
| 1 | Exit descriptors gain the `v6` field; chain planning honors it | descriptor-validation tests; a v4-only exit refuses dual-stack chains |
| 2 | Namespace dual-stack routing + v6-aware kill switch + AAAA inside DoT | leak suite re-run with a v6-capable lab exit; both controls hold |
| 3 | Rate-class per-family throughput recording | bench reports v4/v6 goodput separately; cell size unchanged |
| 4 | `avpn stream-check` records the family the service saw | eligibility rows carry `family` |

Stage 1–2 are sandbox-testable (a v6-capable lab exit is a local
quinn/UDP socket pair on ::1 — no real v6 network needed); stages 3–4
need the throughput bench and the live probe respectively. Estimated
scope: stage 1–2 are a focused week of Rust work in `src/netns.rs`,
`src/tun.rs` and the descriptor validator.

## 6. What stays owner-side

A real v6 allocation on a real exit (provider console), the throughput
bench on the owner's line, and the live AAAA-behavior of real services
— all outside this sandbox, all listed in the delivery manifest.

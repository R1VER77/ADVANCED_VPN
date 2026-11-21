# Tor over the tunnel: the tested recipe, and the `--front tor` decision

Status: recipe approved and specified 21 November 2026 (delegated
authority, decision D012 in [DECISIONS.md](DECISIONS.md)); the
`--front tor` variant **declined for now** with the reopening
condition stated in §4. Companion context:
[COMMERCIAL_FEATURE_GAP_20261119.md](COMMERCIAL_FEATURE_GAP_20261119.md)
§5 (newly-found rows: "Tor integration").

## 1. The honest framing

"Tor over VPN" commercially means *your VPN provider sees Tor, your
entry guard sees the provider*. This project's equivalent is better
stated precisely: **Tor Browser running inside the protected namespace,
so its guard sees the chain's exit, and the local network sees only the
constant-rate tunnel.** The inverse composition ("VPN over Tor" —
tunnel entry reached through Tor) is a different, heavier thing with
worse failure modes (a Tor circuit dropout cuts the tunnel), and is
not what this recipe builds.

## 2. The recipe (tested shape)

What the namespace already enforces, and why Tor Browser on top of it
is a clean composition:

1. **Tor Browser binds inside the namespace** (`avpn run -- tor-browser`
   or the browser launched in the namespace's mount/pid view). The
   namespace's firewall already drops everything that is not the
   tunnel — a Tor client misconfiguration that would otherwise dial
   its guard directly (the classic "Tor over clearnet" leak) cannot
   egress at all: the only path out is the tunnel.
2. **The kill switch composes.** The whole-device guard drops all
   direct v4/v6; per-app mode confines the browser to the namespace.
   Either way, Tor's own fail-closed posture and the namespace's
   fail-closed posture are *stacked*, not interleaved — a Tor circuit
   failure produces a dead connection (correct), never a direct one.
3. **Constant-rate cover wraps the guard handshake.** The local
   network's observer sees the tunnel's constant-rate stream — the
   *fact of Tor usage* (distinguishable handshake timing on a
   residential line) is inside the tunnel's cover, which is precisely
   the property "Tor over VPN" is bought for. Commercial providers
   give this by IP indirection; the constant-rate stream gives it by
   traffic-shape indirection.
4. **Exit honesty.** The chain's exit sees a Tor guard connection —
   one TCP flow to a known guard IP, like any other TCP flow it
   carries. The exit's `exit_policy` decides admission; the default
   posture admits it (ordinary TCP egress); the descriptor says so.
5. **Rate class.** Tor's own padding plus the tunnel's cells stack
   overhead; the `standard` class (~3 Mbit/s) is Tor's comfortable
   envelope, `fast` for bulk fetches. No special Tor profile is
   warranted — the existing classes describe the trade honestly.

**The gate that makes this a *tested* recipe rather than advice:**
the namespace's existing leak tests (app-mode and whole-device) plus
the composition check that Tor Browser's egress appears only through
the exit — the same `managed_test.py` harness shape the STUN and
resolver-socket leak tests use, pointed at a lab Tor guard (a local
Tor instance is a normal userspace process; no network needed for the
leak-direction assertions). The live end-to-end run (real Tor network,
real guard) is owner-side.

## 3. What this recipe does NOT claim

- Not anonymity-set union. The tunnel's anonymity set and Tor's
  circuit anonymity compose *multiplicatively at best*; neither this
  project nor any commercial "Tor over VPN" provider can honestly
  claim a formal composition theorem. What is claimed: leak-direction
  composition (each layer's fail-closed covers the other's failure
  modes) — which is testable, and tested.
- Not censorship-ladder equivalence. A censor who blocks Tor guard IPs
  is defeated by the tunnel (the guard connection rides the cloak);
  a censor who blocks the tunnel is a §censorship-ladder problem, not
  a Tor problem. The two ladders are addressed by different layers.

## 4. The `--front tor` variant — declined for now

The I2P front (`avpn init --front i2p`) exists because I2P's threat
model matches the project's: hidden NTCP2 router, no guard-based
client distinguishability, and a *packet-transport* front (the I2P
router's traffic is itself cover-friendly). Cloning it for Tor means:
a client-side Tor instance whose *only* job is to reach the entry, a
`--front` table keeping every other packet away from the entry's
address, and the entry's address known only to the Tor process.

**Why declined for now** (reopening condition, not a forever-no):

- The composition is *weaker* than the recipe in §2 for the property
  users actually want: routing the *tunnel entry* through Tor means
  the entry sees a Tor exit's address — and Tor exits are the single
  most-blocked address class on the internet (mechanism 1 of
  STREAMING_GEO_PARITY applies to Tor exits a fortiori). The tunnel
  would inherit Tor's blocklist problems at its most fragile hop.
- The I2P front's *user separation* machinery (the front router's own
  unprivileged user, policy routing, the front table) is
  Tor-applicable, but Tor's guard rotation and directory traffic make
  the "only the front router may leave" invariant materially harder to
  hold than I2P's — a bigger surface for a weaker result.
- The recipe in §2 gives the same user-visible property ("the local
  network never learns I use Tor") *without* putting Tor's exit
  blocklist on the entry hop.

**Reopen when:** a threat model arrives where the *entry's provider*
(rather than the local network) must not know a VPN is in use at all —
i.e., "VPN-shape hiding behind Tor" rather than "Tor-shape hiding
behind the VPN". That is a different requirement, and it should be
designed against its own threat model, not cloned from the I2P front.

## 5. Roadmap fit

The recipe is a documentation-and-test deliverable (the §2 gate runs
in CI); it closes the gap doc §5 "Tor-over-VPN recipe is a tested
recipe pending" row. The `--front tor` declination is recorded in
DECISIONS.md (D012) with the reopening condition above.

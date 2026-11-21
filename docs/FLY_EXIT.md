# An exit on a Fly.io Machine

Fly.io has no free tier, but waives a personal organization's monthly bill under $5. A
256 MB Machine with a 1 GB volume costs about $2.78 a month in Europe, leaving room for
about 55 GB of outbound traffic. That is enough for a metered exit connected six hours a
day (about 47 GB). [The fee guard](FEE_GUARD.md) holds every server to such a cap.

    avpn cloud fly server --apply --name avpn-flyexit --region fra
    avpn cloud host setup --name avpn-flyexit --role exit --out exit.req --vault DIR
    avpn cloud chain --apply ...      # signs the chain with --link-transport tcp

## What it is

- **One image, built from this tree** (`deploy/fly/`). It holds the package, the
  hash-locked environment and the release binaries, on a Debian base pinned by digest.
  A Machine's root resets on every restart, so it is patched by rebuilding the image:
  `health` calls an image older than 14 days overdue.
- **No systemd.** `deploy/fly/init.sh` is the service manager and prints nothing,
  because a Machine's output goes to Fly's log store and a server keeps no logs.
  `/run`, `/var/log` and `/tmp` are RAM. The no-logs checks pass, and there is no swap.
- **One encrypted volume** at `/data`, with snapshots off. It holds the enrolled state
  and the month's metering only. The keys are locked to the operator's Nitrokey (a
  Machine has no TPM), so after any restart the exit waits for `avpn cloud unlock`.
- **IPv6 only, over TCP.** UDP on Fly needs a dedicated IPv4 ($2 a month) and the Fly
  proxy carries no QUIC, so the exit listens on `[::]:4444` and the app's free anycast
  IPv6 forwards raw TCP to it. The relay reaches it over a TCP paced link
  (`--link-transport tcp`): the same fixed-size cells on a constant clock. The relay
  needs IPv6 itself.
- **Administered through the Machines API**, not SSH. Its exec call runs a command in the
  Machine. `tools/fly-ssh` and `tools/fly-scp` give it the shape of ssh and scp, so
  `host setup`, `unlock`, `health` and `chain` run unchanged. That path is out of band:
  the egress lock never shuts it.

## What Fly.io sees

Fly's proxy terminates the public TCP connection, so the exit sees Fly's proxy and never
the relay's address. Fly sees the relay's IPv6 and the volume of constant-rate cells,
which is the same as any exit host's provider sees. Fly can read the volume's contents
only if it also holds the Nitrokey's unlock.

## Limits

- **The deploy token** is a secret with control over the app. Keep it in
  `~/.config/advanced-vpn/fly-deploy-token` (mode 600; the tool refuses a file others can
  read) and revoke it in the Fly dashboard when the app is retired.
- **Only one Fly server per organization** fits under the waiver. The fee guard refuses a
  second one.
- **Fly offers no hard spending limit.** See the fee guard's limits.

# The fee guard: a free account stays free

Contributing a free-tier account to the network must never produce a bill (owner, 20 Nov
2026). Every server enforces this itself, whoever uses it and however many members it
serves.

## What can cost money, and what stops it

| Charge | Stopped by |
|---|---|
| Outbound traffic | a monthly cap per server, enforced by a kernel quota (below) |
| Traffic the VPN does not send (updates, agents, a stray process) | the egress lock: only VPN traffic may leave |
| Machine hours, disk, public IPv4 | the account type: free shapes only; Fly.io's are paid from its $5 waiver before any traffic |
| A paid or upgraded account | `avpn cloud health` names it a problem: the cap covers traffic only |
| Fly.io volume snapshots, dedicated IPv4 | never enabled: snapshots off, IPv6 only |

## The monthly cap

The cap is the provider's free allowance, which belongs to the account, not the server.
It is shared by every server in that account and less a 10% margin for SSH, updates and
counting granularity:

| Provider | Free per month, per account | Cap of one server alone |
|---|---|---|
| Oracle Cloud Always Free | 10 TB outbound, per tenancy | 9,000 GB |
| AWS | 100 GB out, aggregated across all services and Regions | 90 GB |
| Azure | first 100 GB of egress, per customer | 90 GB |
| Fly.io | none; a personal organization's bill under $5 is waived, and $5 or more is billed in full | $5 − $1 spare − machine − volume, at $/GB, less 10%: 55 GB in Europe and 75 GB in iad/ewr for a 256 MB machine; a 512 MB machine does not fit in Europe |
| Google Cloud | 1 GB | 0.9 GB (useless as a hop) |
| your own host, a paid VPS | not on record | set by its owner (`--gb N`, or `--unlimited`) |

Prices were read on 2026-11-20 from each provider's pricing page (`tools/fee_guard.py`
names them). On Fly.io two 256 MB machines already cost more than the waiver leaves, so
only one Fly server per organization can stay free, and the guard refuses a second one.
An unknown Fly region is priced at the dearest rate.

`avpn cloud chain --apply` plans every cap before it changes anything. It stops if a hop's
account has no allowance on record, and writes each cap before that server starts. A
production server without a cap refuses to start. Removing the cap file while a server
runs keeps the last cap.

## Enforcement on the server

- **The meter** counts what the host sends on every interface except loopback and its
  own tunnels, per UTC calendar month. A host with containers is overcounted, never under.
  It keeps one number, rounded up to 16 MiB, beside (not inside) the enrolled state, so a
  re-enrollment or a reboot never resets the month. It keeps no per-member,
  per-session, per-destination or time record. A clock set back never reopens an earlier
  month.
- **The kernel quota** (`advanced_vpn_quota`) covers everything sent or forwarded past
  the tunnels, set to what is left of the month. When it is spent the kernel drops, with
  no polling gap. It runs after the egress lock, so a packet the lock refuses never uses
  up allowance.
- **At the cap** the supervisor stops the data plane, and status reads `capped` with the
  day service resumes (the 1st, UTC). Every hop's member sees the chain stop answering,
  and the operator's `avpn cloud health` says why.
- **SSH replies** stay outside the quota, at up to 1 MB/s, so a capped server can still
  be reached to raise its cap.

## The egress lock

`advanced_vpn_egress` is a watched table: the supervisor restores it if anything alters
it. Its rules are `inet`, so they cover IPv4 and IPv6 alike.

**Inbound** is dropped unless it is:
- loopback or the tunnels;
- an established flow;
- the chain's own ports;
- SSH;
- DHCP or DHCPv6;
- ICMP errors, packet-too-big, or neighbour discovery (only with hop limit 255, so it
  cannot come from off-link).

There are no ping answers: a server is silent to scanners on every port it does not
serve.

**Outbound** is dropped unless it is:
- the data plane's own user;
- a reply on an established flow;
- DHCP or NTP;
- the provider's link-local metadata service, which EC2 Instance Connect reads keys from;
- the ICMP a network needs.

**Forwarding** carries only what comes out of the exit's tunnel and its replies: the
internet cannot open a flow into the tunnel.

**Updates.** Security updates come daily, security only. The update timers, snapd, news
and telemetry are disabled on dedicated hosts. Instead the supervisor runs
`unattended-upgrade` (on Debian and Ubuntu, the security origins only) once a day, in a
maintenance window that lets root reach the package mirrors while it runs. The window is
counted against the cap, and a capped server waits for the month to turn.
`avpn cloud host update` runs the same on demand. `health` calls updates overdue after 3
days. A Fly.io Machine's root resets on every restart, so it is patched by rebuilding its
image instead, and `health` calls an image older than 14 days overdue.

**A shared host** (other workloads on it) gets no egress lock, because their traffic is
not the VPN's to block. Its quota and meter count only the data plane's user and the
exit's forwarded traffic, so the other workloads neither use up the cap nor get cut off
by it. Their own traffic is billed to the same account, which the guard cannot see:
`health` says so.

## Evidence

- `tools/server_egress_test.py` runs real nftables in namespaces, over IPv4 and IPv6. It
  shows:
  - root is blocked and the data plane's user is not;
  - neighbour discovery works;
  - the kernel stops traffic at the cap (193,000 bytes delivered of a 200,000-byte cap,
    exactly the headers' share short of it);
  - SSH replies survive a spent quota;
  - unlisted ports and pings get no answer;
  - the exit forwards only from its tunnel;
  - a maintenance window opens and closes;
  - a shared host's quota counts only the VPN.

  Six mutants of the rules each fail it.
- `tools/managed_test.py` runs the whole chain with the lock on the relay and the exit.
  When the relay's cap is set 1 MiB above what it has sent:
  - the relay stops serving and says `capped`;
  - the client's traffic stops;
  - lifting the cap brings the chain back.

  With the supervisor's capped branch removed, it fails.
- `tools/test_fee_guard.py` and `tools/test_cloud_caps.py` cover the meter (restarts,
  reboots, the turn of the month, a clock set back, vanished interfaces), the per-account
  sharing, Fly.io's waiver arithmetic, and the health rows.

## Limits

- Prices change. The table records when each was read. A provider that starts charging
  for something free today is caught only by `health`'s account checks, not by the cap.
- Fly.io bills a card on file and offers no spending limit we know of. The guard keeps
  the computed bill $1 under the waiver, but a price rise between checks could still
  produce a small bill.
- The meter is the host's own count. A provider may measure slightly differently, and the
  10% margin is there for that.

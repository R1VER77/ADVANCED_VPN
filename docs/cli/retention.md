# No retained data

The servers are built so that there is nothing to hand over. Deleting a log is not
enough: deleting a file does not overwrite it, and until those disk blocks are reused,
anyone holding the volume (the cloud provider, or whoever is given a snapshot) can
recover it. So a server must never write a log line to disk in the first place.

## What a server keeps, and where

- **Runtime state** (status, PIDs, leaves, resolver files) lives only in RAM, under `/run/advanced-vpn`.
- **The VPN's own units** run with `LogLevelMax=emerg`, so they write no connection logs at all.
- **Byte counters:** none. The optional daily cap lives on the client only.
- **On disk:** only the enrollment, meaning public certificates and the server's own sealed keys.

## Every other log, kept in RAM from first boot

`sshd` records every login, with the address it came from, and the admin logging in is
you. Distributions also run loggers that copy those lines to disk: the systemd journal,
and on Ubuntu `rsyslog`, which writes `/var/log/auth.log`. So every server gets the same
hardening:

- the systemd journal is RAM-only (`Storage=volatile`), and `/var/log/journal` is removed;
- `rsyslog`, `syslog-ng`, `auditd` and journal upload are stopped and masked;
- `/var/log` is a RAM filesystem, now and on every boot, so `auth.log`, `wtmp`, `btmp`, `lastlog` and package logs never reach the disk;
- login databases kept outside `/var/log` (`lastlog2`, `wtmpdb`) are removed;
- swap is turned off, because RAM, keys and addresses included, could otherwise be written out to disk.

When it runs:
- **Servers created by `avpn cloud aws relay` or `avpn cloud oci server`:** at first boot, as cloud-init user data, before `sshd` accepts its first login. Not even the setup session reaches the disk.
- **Servers recorded with `avpn cloud host add`:** at the start of `avpn cloud host setup`. Anything written before that, including the login that runs setup, may still be on the disk. To be sure, use a server created fresh by `avpn cloud`.

## Enforced, not assumed

A server's VPN refuses to start while any of these fail, before it changes anything on
the host. `avpn doctor` shows each one:
- journal in RAM only;
- `/var/log` in RAM;
- no disk logger running;
- no login database on disk;
- no swap.

The one exception is a host recorded as **shared** (`host add --shared`): its logging
belongs to the other things it runs, so this tool leaves it alone. Such a host starts,
and `doctor` reports that its logging is outside this tool's control.

Tested on the official Debian 13 and Ubuntu 24.04 cloud images. On each, a fresh VM
received a failed login with a unique username and a successful login with a unique
key. It was then powered off, and every byte it had written was scanned, deleted
blocks included. Stock images kept both markers (Debian 6 and 1 copies, Ubuntu 15 and
2); hardened images kept none. The test is `tools/retention_proof.py`, and its results
are in `docs/evidence/RETENTION_PROOF.json`.

## What this cannot reach

The providers under the servers keep records of their own: who calls their API, and
what their network carries. No setting on the server changes those.
- `avpn cloud audit` checks the providers' opt-in logging, and lists the always-on logs it cannot turn off.
- `avpn help privacy` explains what each provider can still see.

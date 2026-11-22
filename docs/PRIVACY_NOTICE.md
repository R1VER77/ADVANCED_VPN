# Privacy notice

This notice covers the cypherpunk_vpn project and the software it publishes. The project is
free software under [AGPL-3.0-or-later](../LICENSE), with a commercial dual-licensing path.
It is not a service. There is no account, no payment, no support contract and no central
operator, so the project holds no data about the people who run it. That follows from how
the software is built, not from a promise. The parties who do see parts of your traffic
are listed in section 5.

## 1. Who "we" are

The project is maintained under the pseudonym **R1VER77**. There is no company, no paid
staff and no support desk. If a legal entity is ever formed, its jurisdiction will be named
here, and the reason recorded in [DECISIONS.md](DECISIONS.md). Today there is none.

If you run the software, you operate your own tunnel with the project's code. People who
use *your* deployment should read your notice, not this one.

## 2. What the project collects

**Nothing.** There is no account system, sign-up, email list, payment, telemetry, error
reporting or analytics. The project's website is its repository. GitHub's own privacy
policy covers issues, pull requests and their notifications.

The commit history is public and signed with hardware-backed SSH keys
([SIGNED_REPOSITORY.md](SIGNED_REPOSITORY.md)).

## 3. What the software does not keep

- **No record of your browsing on the servers.**
  - The relay and exit services send their output to nowhere (`StandardOutput=null`,
    `LogLevelMax=emerg` in `deploy/advanced-vpn*.service`).
  - Their working state lives in RAM.
  - The exit's DNS resolver runs with query logging off (`tools/exit_resolver.py`).
  - On a Fly.io exit, `deploy/fly/init.sh` prints nothing, because a Machine's output goes
    to Fly's log store.
  - The managed validation checks that a chain leaves no retained data behind
    ([MANAGED_VALIDATION.md](MANAGED_VALIDATION.md), multi-hop evidence).
- **One counter per server.** To keep a free-tier server under its monthly cap, each
  server stores how many bytes it has sent this month, rounded to 16 MiB
  ([FEE_GUARD.md](FEE_GUARD.md)). It is one total per server: no clients, no
  destinations, no times.
- **No connection records.** While you are connected, the servers hold their current
  peer's address in memory, as any tunnel must. They do not write it down. Cloud providers
  can still see addresses on their own network (section 5).
- **No device or advertising identifiers.** The build contains no analytics or telemetry
  SDK. [third_party/SOURCES.json](../third_party/SOURCES.json) lists every vendored
  upstream.
- **No DNS history.** The client's signed local blocklist answers blocked names inside the
  tunnel. The exit's recursive resolver keeps no per-client queries.
- **No payment data.** There is no payment system. [FUNDING.md](FUNDING.md) records any
  funding the project receives; at present there is none.

## 4. What the software handles on your own devices

- **Settings and enrollment.**
  - On the client, the signed chain profile you enrolled lives in
    `/etc/advanced-vpn/enrolled`.
  - On the operator's machine, the chains and the cloud server records live in
    `~/.config/advanced-vpn/`.
  - They name your servers and providers, not you.
- **Keys.**
  - Keys are made on the device that uses them, in a vault at `/etc/advanced-vpn/vault`.
  - The vault is sealed to a security key (FIDO2 hmac-secret) or a TPM where available
    ([HARDWARE_BOUND_SESSIONS.md](HARDWARE_BOUND_SESSIONS.md)).
  - Private keys stay on the device. The device request you hand to the operator carries
    only public keys.
- **Running state.** Status files and PIDs are kept in RAM (tmpfs) and disappear when the
  service stops or the machine restarts.
- **Diagnostics.** `avpn status`, `avpn doctor` and the desktop app show connection details
  to you. Running them sends nothing anywhere.

## 5. What other parties can see

The design limits what each party learns, but none of them learns nothing. See also the
[threat model](cli/threat-model.md).

| Party | Can see | Cannot see |
|---|---|---|
| Your ISP or local network | That you send encrypted traffic to one address (your first server, or your upstream VPN); its timing and volume | What is inside it. The carrier is designed to look like HTTP/3 or HTTPS; that disguise has not been independently evaluated |
| Your first server's provider (AWS, Oracle, Azure, …) | The address you connect from, the address of the next server, and the timing and volume of the traffic | The contents, which are encrypted with hybrid post-quantum key exchange |
| Each server along the chain | Only the server before it and the server after it | Your address (except the first server), the destination, and the contents |
| The exit (yours, or a mesh peer's) | The traffic leaving the tunnel and where it goes; DNS queries reach its resolver | Your address. It sees only the server before it |
| The exit's provider | The same as the exit. On Fly.io, the exit's outgoing address is shared with other Fly customers and can change ([FLY_EXIT.md](FLY_EXIT.md)) | Your address |
| Every cloud provider you use | Who holds the account and what calls are made to its API | What other providers see |
| Websites | The exit's address and what you send them | Your address |
| The I2P network (with `--front i2p`) | That you take part in I2P | Your address, and that the destination is a VPN server |
| Your security key's maker | Nothing about your VPN use | The sealed secrets |
| GitHub | Whatever you post in an issue or pull request | Anything about your deployment |

One operator who runs every server in a chain can link its ends. Adding hops under that
same operator does not change this.

## 6. Jurisdiction

There is no operating entity, so there is no entity jurisdiction. The law where your
servers run applies to the data on them. The project leaves that choice to you;
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) lists what works where.

## 7. Legal process

An order served on the maintainer personally is governed by the law that applies to the
maintainer, not by the project. The project's defence is structural: the logs, account
database and payment records such an order would ask for do not exist.

## 8. Your rights

The project holds no personal data about you, so there is nothing to access, correct,
delete or move under GDPR or CCPA. Under AGPL-3.0-or-later you can do more:
- read, audit and change the source ([CONTRIBUTING.md](../CONTRIBUTING.md));
- run it entirely on your own infrastructure;
- rerun the evidence yourself (the validation tools in `tools/` and the formal models in
  `formal/`);
- fork it. If you run a modified version as a network service, AGPL §13 requires you to
  offer that version's source.

## 9. Children

The software is not aimed at children and collects nothing from anyone of any age.

## 10. Changes

This notice changes only by signed commit, and material changes are noted in the
[CHANGELOG](../CHANGELOG.md). The file's git history is its version record.

## 11. Contact

Open an issue on the [repository](https://github.com/R1VER77/ADVANCED_VPN/issues). There is
no email address, support desk or chat channel. Report security problems privately, as
described in [SECURITY.md](../SECURITY.md).

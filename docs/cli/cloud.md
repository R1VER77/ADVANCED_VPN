# avpn cloud

Find, create, record and remove the servers a chain runs on, then join them into one
multi-hop chain. Run it as yourself, not with sudo: it uses your own signed-in `aws`
and `oci` command-line tools, and plain SSH for everything else.

## Usage

    avpn cloud suggest [--profile P]
    avpn cloud status [--live]
    avpn cloud audit [--profile P] [--oci-profile NAME]
    avpn cloud aws relay --apply [--name avpn-NAME] [--role relay|middle|exit] [--allow-from IP|any] [--profile P] ...
    avpn cloud aws relay --teardown [--name avpn-NAME] [--profile P]
    avpn cloud aws allow --apply [--name avpn-NAME] [--allow-from IP|any ...] [--admin-ip IP] [--profile P]
    avpn cloud oci server --apply [--name avpn-NAME] [--role relay|middle|exit] [--shape micro|arm] ...
    avpn cloud oci server --teardown [--name avpn-NAME]
    avpn cloud oci allow --apply --name avpn-NAME --security-list OCID --allow-from IP [--port N] [--protocol udp|tcp]
    avpn cloud oci allow --teardown --name avpn-NAME --security-list OCID
    avpn cloud host add --name avpn-NAME --ssh USER@HOST --key FILE [--provider P] [--shared]
    avpn cloud host setup --name avpn-NAME --out FILE [--role ROLE] [--replace]
    avpn cloud host forget --name avpn-NAME
    avpn cloud chain --apply --client-request FILE --vault DIR [--order A,B,C] [--allow-same-provider] \
        [--hours-per-day H] [--accept-cost]

Every `--apply` and `--teardown` first shows its plan and asks before changing
anything. `--dry-run` stops after the plan. `--yes` skips the question; scripts
using `--json` must pass it.

## Getting started

1. `avpn cloud suggest` ranks the free places to run servers (`avpn help endpoints`) and says which you are already signed in to.
2. Create servers (`aws relay`, `oci server`) or record ones you have (`host add`). Two servers on two providers give a 2-hop chain where no single provider sees both your address and your destinations.
3. `avpn cloud chain --apply` installs every server, signs the chain once with your Nitrokey, enrolls the servers and starts them.
4. On the client: `sudo avpn enroll ... --replace` and `sudo avpn connect`, as the chain's last lines say.

## Safety rules

- Everything it creates is tagged (`avpn:managed=true` and `avpn:name=NAME` on AWS, freeform `avpn-managed`/`avpn-name` on OCI), and names start with `avpn-`. A teardown deletes only resources carrying both tags, and checks each one before deleting it. Nothing else in the account is touched.
- One region per account: the AWS profile's Region, and OCI's home region (Always Free exists only there). Anything else is refused.
- The first hop's tunnel port is open to any address: it is WireGuard, which never answers a peer it was not enrolled with (proven by the lab test and a live probe), so the provider's firewall configuration never names you. Every later hop admits only the previous server's single address. Private, documentation, IPv6 and range addresses are refused.
- Plans show a `caller` row: the address the provider will record as the API caller (AWS CloudTrail keeps it 90 days, OCI Audit 365 days, whatever you configure). Run provider commands while connected through a chain, and it records the exit's address instead of yours.
- A local inventory, `~/.config/advanced-vpn/cloud.json` (mode 0600, no secrets), records what was created or added.

## avpn cloud suggest

The endpoint catalog, ranked by usable monthly outbound transfer, with each
provider's free terms, caveats, whether it is ready to use from this machine, and the
exact next command. It ends with a recommendation based on what is recorded.

- `--profile P`: the AWS CLI profile whose sign-in to check (default `$AWS_PROFILE`).

## avpn cloud audit

What the cloud providers log about you, checked against your own accounts. It only
reads; nothing is changed.

- `--profile P`: also audit this AWS CLI profile. Profiles of servers in the inventory are always audited.
- `--oci-profile NAME`: the OCI CLI profile to audit (default `DEFAULT`, used whenever an OCI server is recorded).

Opt-in logging it looks for, each reported as `FOUND` when present:
- **AWS:**
  - CloudTrail trails and CloudTrail Lake;
  - VPC flow logs and traffic mirroring;
  - AWS Config recording, which keeps the history of every firewall rule;
  - Route 53 DNS query logs;
  - CloudWatch log groups, in the Region and in us-east-1;
  - GuardDuty.
- **OCI:**
  - flow logs and other logs, in every compartment;
  - traffic mirroring (VTAPs).
- **Firewalls:** any rule, AWS security group, OCI security list or bastion allow-list that names an address that is not one of your recorded servers.

A service the account may not read is reported as "cannot check", never as clean.
It also states the logs that are always on and cannot be turned off: AWS CloudTrail's
90-day history, with how many caller addresses it holds now, and OCI Audit's 365 days.
Running the audit is itself recorded there, under the address you run it from.

What happens on the servers themselves is checked by `avpn doctor` on each server
(`avpn help retention`).

## avpn cloud status

The recorded resources, by name.

- `--live`: also ask AWS whether each instance still exists.

## avpn cloud aws relay

One chain server on EC2.

- `--apply`: create it. It refuses if an instance with this name already exists.
- `--teardown`: delete everything tagged with `--name`: instances first, then the firewall, key pair, image and snapshot.
- `--name avpn-NAME`: the resource name and tag (default `avpn-relay`).
- `--role relay|middle|exit`: what the server is in the chain. It sets the default port.
- `--profile P`: the AWS CLI profile (default `$AWS_PROFILE`, else `default`).
- `--region R`: must equal the profile's Region; omit it to use that Region.
- `--instance-type T`: an EC2 type with NitroTPM support (default `t3.micro`).
- `--disk-gib N`: root disk size (default 8).
- `--port N`: the tunnel port (default 443 for a relay, where the HTTP/3 camouflage listens; 4445 for a middle; 4444 for an exit).
- `--allow-from IP`: who may reach the tunnel port: `any` (a relay's default, and only allowed for a relay), a public IPv4, or `auto` for this machine. A middle or exit needs the previous server's address. It can be repeated.
- `--admin-ip IP`: the address allowed to SSH in (default `auto`, this machine).
- `--dry-run`: show the plan and stop.
- `--yes`: do not ask for confirmation.

What `--apply` creates:
1. A copy of the newest official Debian 13 amd64 image (encrypted), re-registered with UEFI boot, NitroTPM 2.0 and IMDSv2. The intermediate copy is deregistered.
2. A throwaway ed25519 SSH key, kept in `~/.config/advanced-vpn/ssh/NAME`, and its key pair.
3. A security group: UDP on the tunnel port from `--allow-from`, and TCP 22 from `--admin-ip`.
4. The instance:
   - IMDSv2 required, hop limit 1;
   - `standard` CPU credits, so no surplus charges;
   - an encrypted gp3 root disk, deleted with the instance;
   - no instance profile;
   - first-boot user data that keeps every log in RAM before `sshd` accepts the first login (`avpn help retention`).

The plan shows a rough monthly list price. On the free plan, credits pay for it; AWS
Billing shows the real cost. If your sign-in has expired, the error says to run
`aws login --profile P`.

## avpn cloud aws allow

Replace who may reach a server this tool created.

    avpn cloud aws allow --apply --name avpn-relay --allow-from any --admin-ip auto

- `--apply`: change the security group (required; the plan is shown first).
- `--name avpn-NAME`: the server (default `avpn-relay`). Its security group must carry both tags.
- `--allow-from IP`: the new tunnel sources: `any` (first hop only), a public IPv4, or `auto`. Repeat it to admit several. The tunnel rule then admits exactly these.
- `--admin-ip IP`: the new address allowed to SSH in, or `auto`.
- `--profile P`, `--region R`: as for `aws relay`.
- `--dry-run`, `--yes`: as above.

Give at least one of `--allow-from` and `--admin-ip`; the other rule is left as it
is. The tunnel rule is the group's one single-port UDP rule (it refuses if there is
more than one) and the admin rule is TCP 22. Every other rule is kept.

The new addresses are opened before the old ones are closed, so a working chain never
loses its path. Old addresses, and any IPv6 range, prefix list or group reference on
those two rules, are removed. If the group already admits exactly the addresses
given, nothing is changed.

A first hop open to `any` never needs updating when your address changes. Single
addresses do: `auto` asks `checkip.amazonaws.com`, which sees the address your
traffic leaves from, and behind a commercial VPN that can change at any reconnect.

## avpn cloud oci server

One Oracle Cloud Always Free server with its own network. It needs the `oci` CLI,
configured once with `oci setup config`.

- `--apply`: create it. It refuses if the name is already recorded.
- `--teardown`: delete everything recorded for `--name`: instance, subnet, security list, internet gateway, VCN. Each must carry this tool's tags.
- `--name avpn-NAME`: the resource name and tag (default `avpn-exit`).
- `--role relay|middle|exit`: what the server is in the chain (default `exit`).
- `--shape micro|arm`: `micro` is VM.Standard.E2.1.Micro (AMD, 1 GB, up to 2 per tenancy); `arm` is VM.Standard.A1.Flex.
- `--ocpus N`, `--memory-gib N`: A1 only (Always Free: 2 OCPU and 12 GB in total; defaults 1 and 6).
- `--compartment OCID`: where to create it (default: the tenancy's root compartment).
- `--vcn VCN`: put the server in an existing VCN instead of creating one (a free tenancy has only two). The server gets its own subnet (the next free /24 in the VCN), route table and security list, all tagged as its own; the VCN and its internet gateway are used and never changed, and a teardown removes only the server's own parts.
- `--oci-profile NAME`: the profile in `~/.oci/config` (default `DEFAULT`). Its region must be the tenancy's home region.
- `--port N`, `--allow-from IP`, `--admin-ip IP`: as for `aws relay`.
- `--dry-run`, `--yes`: as above.

What `--apply` creates, all tagged with the name:
1. A VCN (`10.77.100.0/24`), an internet gateway and a default route to it.
2. A security list of its own: UDP on the tunnel port from `--allow-from`, TCP 22 from `--admin-ip`, and all egress. The subnet uses only this list, not the VCN's default one (which allows SSH from anywhere).
3. A throwaway ed25519 SSH key in `~/.config/advanced-vpn/ssh/NAME`.
4. The instance: the newest full Canonical Ubuntu 24.04 image for the shape, a public address, and legacy (unauthenticated) metadata endpoints disabled. Its first-boot user data keeps every log in RAM before `sshd` accepts the first login (`avpn help retention`).

OCI reclaims Always Free instances that stay idle (CPU, network and memory all under
20% for 7 days); a hop carrying your traffic is normally busy enough.

## avpn cloud oci allow

One ingress rule on an existing OCI security list, from the previous hop only. Use it
for OCI servers this tool did not create.

- `--apply`: add the rule. Re-applying replaces it rather than duplicating it.
- `--teardown`: remove it. Rules not created by this command are never touched.
- `--name avpn-NAME`: the rule's name, stored in its description as `advanced-vpn:NAME`.
- `--security-list OCID`: the security list to change.
- `--allow-from IP`: the previous hop's public IPv4, or `auto`.
- `--port N`: the destination port (default 4444).
- `--protocol udp|tcp`: the transport (default `udp`).
- `--dry-run`, `--yes`: as above.

Every other ingress rule, and every egress rule, is kept exactly as it was.

## avpn cloud host add

Record a server you already have, on any provider (Azure, Google, a VPS) or your own
machine, so `host setup` and `chain` can use it. It checks that SSH works with
passwordless sudo.

- `--name avpn-NAME`: a name for it.
- `--ssh USER@HOST`: how to reach it, as a sudo user. With `--ssh-config`, HOST can be an alias from that file.
- `--key FILE`: its SSH private key (mode 600; SSH never asks for a password).
- `--ssh-config FILE`: an SSH config file, for bastions, jump hosts or other ports.
- `--address IP`: its public IPv4, if HOST is not it (for example behind a bastion).
- `--provider KEY`: where it runs (default `own`): `oci`, `aws`, `azure`, `gcp` or `own`, or a paid host listed by `avpn cloud suggest` and `avpn help endpoints` (`racknerd`, `ionos`, `ovh`, `netcup`, `hetzner`, `1984`, `infomaniak`, `exoscale`). It sets the allowance used to order a chain and the legal sphere shown in its plan.
- `--shared`: the host also runs other things: setup leaves its system journal alone.

This tool does not manage the firewall of an added server. The chain plan says which
port to open, and from where.

## avpn cloud host setup

Install or upgrade the package on a recorded server over SSH and fetch its public
request. `chain` does this for every hop; use it on its own to prepare one server.

- `--name avpn-NAME`: the recorded server.
- `--source DIR`: a built checkout or unpacked release to install from (default: this one). It must contain `target/release/` with every binary.
- `--source-arm DIR`: a built ARM (aarch64) checkout, for ARM servers such as OCI's Ampere A1. Each server reports its processor (`uname -m`); an ARM server gets this build, the others `--source`, and an ARM server without `--source-arm` is refused rather than given binaries it cannot run.
- `--out FILE`: where to save the public request. Give it to `avpn init`.
- `--role relay|middle|exit`: the role to make keys for (default: its recorded role).
- `--replace`: replace keys made for another role. Without it, a role change is refused.

What it does on the server:
1. Installs `nftables`, `python3-venv` and the TSS2 runtime libraries. Without TSS2, systemd-creds would silently fall back to the host key.
2. Unless the host is shared, first of all: keeps every log in RAM (`avpn help retention`). That covers the journal, syslog daemons, `/var/log`, login databases and swap. Otherwise `sshd` would keep a persistent record of the admin's address, which is your address. A shared host is only marked as shared, and `doctor` reports it.
3. On images that reject by default (OCI's Ubuntu), accepts the tunnel port in the host firewall, and saves it unless the host is shared (saving would also persist its other runtime rules).
4. Installs or upgrades the package (the service is not enabled).
5. Keeps the keys when they were made for the same role; otherwise runs `avpnctl request --role ROLE --protect systemd-creds`, sealing them to host + TPM2 when the TPM is usable.

Binaries are copied as built, so the server needs a C library at least as new as the
build machine's (release builds need glibc 2.34: Debian 12+, Ubuntu 22.04+).

## avpn cloud host forget

Drop a server from the inventory. Nothing on the server or in the provider changes.

- `--name avpn-NAME`: the recorded server.

## avpn cloud chain

Join the recorded servers into one chain and start it.

- `--apply`: build the chain, or rebuild it after adding or removing a server.
- `--client-request FILE`: the client device's public request (from its installer, or `sudo avpn request --role client`).
- `--vault DIR`: the operator's Nitrokey vault; the chain is signed once (PIN + touch).
- `--order A,B,C`: the hop order from the client side, overriding the automatic one.
- `--allow-same-provider`: allow the entry and the exit on one provider. Without it, `chain` refuses such a chain, because that provider would see your address and your destinations together. Other hops sharing a provider are allowed, and the plan names the provider and how many hops it holds.
- `--source DIR`: the package to install on the servers, as for `host setup`.
- `--hours-per-day H`: hours you are connected per day (default 8). The rate class is the fastest whose constant stream fits the smallest hop allowance at this many hours (`avpn help init`); a relay pays for two paced links.
- `--accept-cost`: sign the class even when it exceeds a hop's free allowance. Without it, a chain whose slowest class still does not fit is refused, with the numbers.
- `--dry-run`, `--yes`: as above.

How hops are chosen: one server is a 1-hop chain, two make 2 hops, three or more make
3 hops (the most a chain has; extra servers are listed as unused). The exit is the
server with the largest monthly outbound allowance, because it carries everything.
The entry relay prefers a different provider from the exit, so no single provider
sees both your address and your destinations. A chain can carry about as much per
month as its smallest hop allowance; the plan shows it. The plan also shows the legal
sphere of each end and warns when both answer to the same law: every free tier is a
US company, and the US CLOUD Act reaches US providers wherever their servers stand, so
put one end on a non-US host (`avpn cloud suggest` lists some) for ends in different
spheres.

What `--apply` does:
1. Firewalls of managed servers (`aws relay`, `oci server`): the first hop's UDP 443 (the HTTP/3 camouflage in front of WireGuard) open to any address, and any older WireGuard port rule removed; each later hop's port (4445 middle, 4444 exit) only from the previous server; SSH from here for setup.
2. Installs or upgrades every server and fetches its request for its role. A server whose role changes gets new keys.
3. Signs the whole chain once: `avpnctl init` with your client request and every server's.
4. Enrolls and restarts each server, exit first, and checks it is running.
5. Removes SSH from your address. From then on you administer the servers while connected: the other hops admit SSH from the exit's address (which is where your traffic now comes from), and the exit answers at `10.77.0.1`, its own address inside the tunnel, which needs no firewall rule. The exit's public address does not work from inside the tunnel, because cloud servers do not hold it locally. So no rule names you. Rerun `chain` (or `aws allow --admin-ip auto`) to get back in when you are not connected.

Every chain is padded to constant cells on every hop, every link between two servers
is a paced, encrypted constant-rate stream (per-hop shaping), and the client's link to
the first hop looks like HTTP/3 on UDP 443; there is no option to turn any of them off
(`avpn help threat-model`). On AWS the first hop presents its provider DNS name as
its server name, so name and address agree.

The bundles go to `~/.config/advanced-vpn/chains/TIMESTAMP/bundles`. The last lines
give the client's enroll and connect commands.

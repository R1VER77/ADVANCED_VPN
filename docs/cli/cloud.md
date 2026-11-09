# avpn cloud

Create, inspect and remove the cloud servers a chain runs on. Run it as yourself, not
with sudo: it uses your own signed-in `aws` and `oci` command-line tools.

## Usage

    avpn cloud status [--live]
    avpn cloud aws relay --apply --allow-from IP [--name avpn-NAME] [--role relay|middle|exit] [--profile P] ...
    avpn cloud aws relay --teardown [--name avpn-NAME] [--profile P]
    avpn cloud oci allow --apply --name avpn-NAME --security-list OCID --allow-from IP [--port N] [--protocol udp|tcp]
    avpn cloud oci allow --teardown --name avpn-NAME --security-list OCID

Every `--apply` and `--teardown` first shows its plan and asks before changing
anything. `--dry-run` stops after the plan. `--yes` skips the question; scripts
using `--json` must pass it.

## Safety rules

- Everything it creates is tagged `avpn:managed=true` and `avpn:name=NAME`, and names start with `avpn-`. A teardown deletes only resources with both tags, and it refuses an instance not named `avpn-*`. Nothing else in the account is touched.
- The project has one Region, the profile's configured Region. Asking for any other Region is refused.
- A firewall is opened only to the previous hop's single public IPv4 address (and SSH only to the admin address). Private, documentation, IPv6 and range addresses are refused.
- A local inventory, `~/.config/advanced-vpn/cloud.json` (mode 0600, no secrets), records what was created.

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
- `--port N`: the tunnel port (default 41194 for a relay, 4445 for a middle, 4444 for an exit).
- `--allow-from IP`: the previous hop's public IPv4, or `auto` for this machine. It is required with `--apply` and can be repeated.
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
   - no instance profile.

The plan shows a rough monthly list price. On the free plan, credits pay for it; AWS
Billing shows the real cost. If your sign-in has expired, the error says to run
`aws login --profile P`.

After creation, install the package on the server, run
`sudo avpn request --role ROLE --protect systemd-creds` there, and include its request
in `avpn init`.

## avpn cloud oci allow

One ingress rule on an OCI security list, from the previous hop only. Use it for
existing OCI servers, for example the exit.

- `--apply`: add the rule. Re-applying replaces it rather than duplicating it.
- `--teardown`: remove it. Rules not created by this command are never touched.
- `--name avpn-NAME`: the rule's name, stored in its description as `advanced-vpn:NAME`.
- `--security-list OCID`: the security list to change.
- `--allow-from IP`: the previous hop's public IPv4, or `auto`.
- `--port N`: the destination port (default 4444).
- `--protocol udp|tcp`: the transport (default `udp`).
- `--dry-run`, `--yes`: as above.

Every other ingress rule, and every egress rule, is kept exactly as it was.

## avpn cloud host setup

Install the package on a server this tool created, over SSH with its throwaway key,
and fetch the server's public request.

- `--name avpn-NAME`: the recorded server.
- `--source DIR`: a built checkout to install from (default: this checkout). It must contain `target/release/` with every binary.
- `--out FILE`: where to save the public request. Give it to `avpn init`.

What it does on the server:
1. Installs `nftables`, `python3-venv` and the TSS2 runtime libraries. Without TSS2, systemd-creds would silently fall back to the host key.
2. Keeps the server's system journal in RAM only (`Storage=volatile`), and removes what the boot wrote to disk. Otherwise `sshd` would keep a persistent record of the admin's address, which is your address.
3. Installs the package with the installer (the service is not enabled).
4. Runs `avpnctl request --role ROLE --protect systemd-creds`. The keys are sealed to host + TPM2 when the TPM is usable.

It refuses to regenerate keys on a server that is already enrolled. Binaries are
copied as built, so the server needs a C library at least as new as the build
machine's (Debian 13 to Debian 13 works).

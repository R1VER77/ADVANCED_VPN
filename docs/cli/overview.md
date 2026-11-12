# avpn

`avpn` is the command-line front end of ADVANCED_VPN, a self-hosted,
post-quantum VPN. Run `avpn` with no arguments in a terminal for the interactive
view, or give it a command.

## Usage

    avpn [--state DIR] [--json] [--no-color] [--reduced-motion] [COMMAND] [ARGS...]

## Global options

- `--state DIR`: the enrollment directory. Default `/etc/advanced-vpn/enrolled`.
- `--json`: print the controller's JSON object instead of the rendered view. Use it in scripts.
- `--no-color`: no colour. `NO_COLOR` in the environment, or output that is not a terminal, does the same.
- `--reduced-motion`: no spinner animation in the interactive view.

## Commands

Everyday:

- `status`: what the supervisor is doing now
- `info`: this device's role, chain, key protection and preferences
- `hops`: the chain, hop by hop
- `doctor`: self-checks; `--check-egress` shows the address your first hop sees
- `connect` / `disconnect`: start or stop the VPN service
- `run -- CMD`: run one program inside the protected namespace
- `preferences`: mode, daily cap, upstream entry
- `unlock`: answer the Nitrokey PIN prompt after boot

Setup:

- `request`: generate this device's keys and a public request
- `init`: operator only; sign a chain from the requests
- `enroll`: install this device's signed bundle
- `cloud`: find free servers, create or record them, and join them into one chain (`cloud suggest`, `cloud chain`)
- `mesh`: publish a node descriptor, verify the volunteer mesh directory, or select a multi-operator chain (`mesh descriptor`, `mesh directory`, `mesh select`)
- `mix`: the mix lane, a Katzenpost mixnet client inside the protected namespace for requests that can wait seconds (`mix setup`, `mix start`, `mix fetch`)

Maintenance:

- `rotate`: rotate session certificates now
- `guard`: re-apply the boot-time kill switch
- `reset --allow-cleartext`: remove the kill switch

## Help topics

`avpn help COMMAND` shows a command's page. These concept topics are also available:
`chains`, `endpoints`, `front`, `keys`, `privacy`, `threat-model`, `retention`, `interactive`.

## Privileges

Commands that change the network or read the root-owned enrollment need root:
`sudo avpn ...`. The `avpn` binary renders results only. All privileged work happens
in the controller, `/opt/advanced-vpn/bin/avpnctl`, which validates every option itself.

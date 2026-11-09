# avpn run

Run one program inside the protected network namespace. It can reach the internet
only through the tunnel, and it uses the tunnel's DNS. The host resolver sockets are
hidden from it.

## Usage

    sudo avpn run [--uid UID] [--gid GID] -- COMMAND [ARGS...]

## Options

- `--uid UID`, `--gid GID`: the identity to run as. The default is the user who ran `sudo`. Root is refused.
- `COMMAND`: everything after `--`.

## Example

    sudo avpn run -- curl https://example.com

## What it changes

Nothing persistent. The program runs in the VPN's namespace with its own mount
namespace (resolver isolation).

## Failure modes

- The VPN is not running: the namespace has no route, so the program cannot reach the network. That is the kill switch working.

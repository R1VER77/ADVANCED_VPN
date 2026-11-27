# cypherpunk run

Run one program inside the protected network namespace. It can reach the internet
only through the tunnel, and it uses the tunnel's DNS. The host resolver sockets are
hidden from it.

## Usage

    sudo cypherpunk run [--uid UID] [--gid GID] [--ephemeral-browser firefox|chromium] [--ephemeral-socks HOST:PORT] -- COMMAND [ARGS...]

## Options

- `--uid UID`, `--gid GID`: the identity to run as. The default is the user who ran `sudo`. Root is refused.
- `--ephemeral-browser firefox|chromium`: wrap the launched browser in a disposable `0700` anti-fingerprinting profile (`tools/tor_lab.py`) whose cookies, cache, and storage are overwritten and wiped on exit.
- `--ephemeral-socks HOST:PORT`: optional local SOCKS5 proxy (such as `127.0.0.1:9050` for Tor-over-the-tunnel) with remote DNS enforced when `--ephemeral-browser` is set.
- `COMMAND`: everything after `--`.

## Example

    sudo cypherpunk run -- curl https://example.com

## What it changes

Nothing persistent. The program runs in the VPN's namespace with its own mount
namespace (resolver isolation).

## Failure modes

- The VPN is not running: the namespace has no route, so the program cannot reach the network. That is the kill switch working.

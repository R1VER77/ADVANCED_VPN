# avpn rotate

Rotate the short-lived session certificates now, instead of waiting for the next
automatic rotation. Identities are unchanged; only session leaves change.

## Usage

    sudo avpn rotate

## What it changes

Sends SIGHUP to the supervisor.

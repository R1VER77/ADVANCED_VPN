# cypherpunk disconnect

Stop the VPN. With Lockdown off, an intentional disconnect restores ordinary
internet access. With Lockdown on, internet access stays blocked until the next connection.

## Usage

    sudo cypherpunk disconnect [--keep-guard]

## Options

- `--keep-guard`: retain the runtime kill switch during a planned restart.

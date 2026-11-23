# cypherpunk guard

Re-apply the boot-time kill switch. `cypherpunk-vpn-guard.service` runs this before the
network comes up, so a whole-device client never sends cleartext during boot.

## Usage

    sudo cypherpunk guard

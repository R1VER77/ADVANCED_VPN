# cypherpunk unlock

Answer a pending Nitrokey PIN request in the terminal. If sudo asks for your
Linux password, enter that first. At the Nitrokey prompt, type the FIDO2 PIN
and press Enter. The terminal hides the PIN. Touch the key when it flashes.

The command shows what it is waiting for. It reports success after the
supervisor confirms the unlock. Run `sudo cypherpunk status` to check
tunnel protection.

## Usage

    sudo cypherpunk unlock

"""Whether a server can seal its keys to its TPM2 (standard library only: the installer
uses it before the hash-locked environment exists).

The rule (docs/HARDWARE_BOUND_SESSIONS.md, servers without a TPM; owner, 20 Nov 2026): a
server's keys are sealed to its TPM2 when systemd-creds can really use one, otherwise
locked to the operator's Nitrokey (`--protect operator`). Never the host key alone: its
secret sits on the same disk as the keys. `cypherpunk cloud host setup` probes the same way."""

import subprocess

from sysexec import trusted_exe

SERVER_ROLES = ("relay", "middle", "exit")

NO_TPM = (
    "this server cannot seal keys to a TPM2 (systemd-creds could not seal and open a test credential with "
    "its host and TPM2 key: systemd older than 250, no TPM, or no TSS2 libraries). Sealing with the host key "
    "alone would leave the keys' secret on the same disk. Lock them to the operator's Nitrokey instead: "
    "--protect operator --unlock-key FILE, where FILE is the operator's unlock key (cypherpunk unlock-key); "
    "cypherpunk cloud host setup does this for you"
)


def tpm2_sealing_works():
    """Seal and open a throwaway credential with the host and TPM2 key, through pipes only
    (a file in the sticky /tmp could not be removed by an unprivileged caller)."""
    try:
        exe = trusted_exe("systemd-creds")
    except (FileNotFoundError, ValueError):
        return False
    try:
        sealed = subprocess.run(
            [exe, "encrypt", "--with-key=host+tpm2", "--name=cpvpn-probe", "-", "-"],
            input=b"cypherpunk",
            capture_output=True,
            timeout=30,
        )
        if sealed.returncode:
            return False
        opened = subprocess.run(
            [exe, "decrypt", "--name=cpvpn-probe", "-", "-"], input=sealed.stdout, capture_output=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return opened.returncode == 0 and opened.stdout == b"cypherpunk"


def check_server_protection(role, protect, unlock_key=None, probe=tpm2_sealing_works):
    """Refuse (ValueError) a server key protection weaker than the rule above."""
    if protect == "operator":
        if role not in SERVER_ROLES:
            raise ValueError("--protect operator is for servers; a client unlocks with its own key")
        if unlock_key is None:
            raise ValueError("--protect operator needs --unlock-key FILE (the operator's: cypherpunk unlock-key)")
    elif unlock_key is not None:
        raise ValueError("--unlock-key goes with --protect operator only")
    if role in SERVER_ROLES and protect == "systemd-creds" and not probe():
        raise ValueError(NO_TPM)

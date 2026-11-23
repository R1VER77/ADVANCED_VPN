# cypherpunk state-key

Operator only. Release the key that encrypts OpenTofu's state and saved plans, for the
cloud provisioner (`tools/tofu_run.py`). The key is 32 random bytes sealed in the
operator's Nitrokey vault, made on first use; each release needs the PIN and a touch. It
is printed as JSON to a pipe only; the command refuses to print it to a terminal.

## Usage

    cypherpunk --json state-key (--vault DIR | --software-operator DIR) | ...

## Options

- `--vault DIR`: the operator's Nitrokey vault (PIN + touch).
- `--software-operator DIR`: LAB ONLY. Plaintext operator keys.

## Security notes

- The provisioner passes the key to OpenTofu in its environment for one run
  (`TF_ENCRYPTION`); it is never written beside the state it protects.
- Without the vault's key, OpenTofu cannot read the state or a saved plan.

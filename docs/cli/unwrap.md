# cypherpunk unwrap

Operator only. Unwrap the data keys of servers that lock their keys to the operator
(PIN + touch), for `cypherpunk cloud unlock`. The data keys are printed as JSON to a pipe; the
command refuses to print them to a terminal.

## Usage

    cypherpunk --json unwrap (--vault DIR | --software-operator DIR) --request NAME=FILE ... \
        [--wrapped NAME=FILE ...] | ...

## Options

- `--vault DIR`: the operator's Nitrokey vault (PIN + touch).
- `--software-operator DIR`: LAB ONLY. Plaintext operator keys.
- `--request NAME=FILE`: your own copy of the server's request. Its role and identity certificates are what the wrapped data key must be bound to, so a server cannot get another server's data key unwrapped for it.
- `--wrapped NAME=FILE`: the server's current unlock record (its `protection.json`), when it is not the one in the request. Only this ciphertext comes from the server.

## Security notes

- A data key wrapped to another operator's unlock key, or bound to other certificates, is refused by name.
- The output is secret: send it straight to the server (`cypherpunk cloud unlock` does, over SSH, on stdin).

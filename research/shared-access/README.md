# Shared-access pilot lab

The lab exercises sponsored blind credits, signed shared-pool selection, wallet sealing, and role-specific admission. It generates fresh authentication and WireGuard keys for each admission. Admission TLS connections run on loopback. The optional carrier fixture installs the admitted keys into two nested Linux WireGuard devices and exercises DNS and HTTPS against an isolated exit. The shipped GotaTun VPN has a separate peer lifecycle.

The issuer fixture uses Cloudflare’s Privacy Pass TypeScript library. The Python verifier checks the RFC 9578 token with OpenSSL-backed RSA-PSS, a pinned issuer key, and a role- and epoch-specific challenge. ML-DSA binds the authentication key holder to the token, the expected hop, a TLS exporter, and the proposed carrier key. The carrier must still prove possession through its own handshake when peer installation is implemented. The pilot token’s unforgeability is classical. [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html) · [Privacy Pass TypeScript library](https://github.com/cloudflare/privacypass-ts)

The directory trusts an out-of-band ML-DSA key and checks member signatures. The pilot still needs a way for clients to verify that they were all offered the same issuer configuration. The replay ledger is authoritative across local processes. A multi-host deployment needs a shared authority with the same atomic semantics and separate role namespaces. SQLite files assume a private, service-owned directory and a local filesystem.

## Run the lab

From the repository root with the project Python environment and Node.js 24 on `PATH`:

```sh
lab_dir=$(mktemp -d)
cp research/shared-access/{package.json,package-lock.json,issue-lab-batch.mjs} "$lab_dir/"
npm --prefix "$lab_dir" ci --ignore-scripts --no-audit --no-fund
.venv/bin/python research/shared-access/verify-lab-batch.py "$lab_dir/issue-lab-batch.mjs"
PYTHONPATH=tools .venv/bin/python -m unittest test_shared_admission test_mix_holdout test_mesh_fail_closed
unshare --user --map-root-user --net sh -c 'ip link set lo up && .venv/bin/python research/shared-access/browser-lab.py'
```

To run the forwarding fixture, use fresh network and mount namespaces:

```sh
unshare --user --map-root-user --net --mount sh -c '
  ip link set lo up && exec .venv/bin/python research/shared-access/verify-lab-batch.py "$1" --wireguard
' shared-access "$lab_dir/issue-lab-batch.mjs"
```

The fixture checks that DNS and authenticated HTTPS fail before installation, succeed once both peers are installed, and fail again after simulating grant expiry. Its relay permits only the encrypted inner UDP carrier. A deliberately interrupted installation must leave all four peer slots empty. For a physical wallet test, run the original command with `--hardware` from the desktop. It requests a PIN and three touches for a disposable non-resident credential, sealing the batch, and opening a pair. A current dedicated test vault can be passed with `--hardware-vault` to skip creating the credential.

The lab reports counts and booleans only. The browser fixture uses separate temporary Chromium profiles, and captures only a test page on loopback. The local observer can see cookies and a small browser settings vector.

The offline checkout policy tests use synthetic, already-verified shielded note observations. They cover two-source agreement, the ten-confirmation threshold, reorg disagreement, mainnet and transparent payment refusal, replay protection, atomic retries, and retention of the paid transaction denylist after cleanup. It still needs the Tor service, real proof-validating watcher adapters, and a completed testnet purchase.

```sh
.venv/bin/python -m unittest discover -s research/shared-access -p 'test_*.py'
```

## Timing qualification

Rescore each run with `python tools/mix_holdout.py RUN --out REPORT --require-margin`. The report includes separate timing, sender-frequency, and combined estimates with the same held-out events. Use `python tools/mix_qualification.py MANIFEST --out RESULT` with a JSON array of entries such as `{"region":"us-central1","report":"trial-1.json"}`. The result keeps the timing claim closed unless the recorded captures cover the required distinct days, seeds, and regions and the observer thresholds pass. The upper estimate uses the more conservative of a one-sided Wilson estimate and a seeded whole-capture bootstrap. The estimate remains empirical and is conditional on the observer and workload.

## Pilot gates still open

- Wire admission into the shipped GotaTun peer lifecycle and the required upstream route. Repeat the fixture’s forwarding, rollback, and expiry checks on that path, with leak protection and physical Nitrokey operation.
- Review the protocol and the distributed replay authority, then run the planned independent GCP trials and independent-operator validation. The archived same-day mix runs provide a regression control.
- Implement and test shielded testnet checkout, including the independent confirmation paths. Keep paid and shared access disabled in the shipped VPN until the applicable gates pass.

# Shared-access pilot lab

The lab exercises sponsored blind credits, signed shared-pool selection, wallet sealing, and role-specific admission. It generates fresh TLS authentication and WireGuard public keys for each admission. The PIN and touch step uses a hardware-secret fixture. The TLS connections run on loopback, and the admission code is disconnected from the shipped VPN data plane.

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

The lab reports counts and booleans only. The browser fixture uses separate temporary Chromium profiles, and captures only a test page on loopback. The local observer can see cookies and a small browser settings vector.

## Timing qualification

Rescore each run with `python tools/mix_holdout.py RUN --out REPORT --require-margin`. The report includes separate timing, sender-frequency, and combined estimates with the same held-out events. Use `python tools/mix_qualification.py MANIFEST --out RESULT` with a JSON array of entries such as `{"region":"us-central1","report":"trial-1.json"}`. The result keeps the timing claim closed unless the recorded captures cover the required distinct days, seeds, and regions and the observer thresholds pass. The upper estimate uses the more conservative of a one-sided Wilson estimate and a seeded whole-capture bootstrap. The estimate remains empirical and is conditional on the observer and workload.

## Pilot gates still open

- Wire admission into the VPN peer lifecycle and the required upstream route. Verify protected DNS and HTTPS, IPv4 and IPv6 leak protection, partial-install rollback, expiry, and physical Nitrokey operation on the complete path.
- Review the protocol and the distributed replay authority, then run the planned independent GCP trials and independent-operator validation. The archived same-day mix runs provide a regression control.
- Implement and test shielded testnet checkout, including the independent confirmation paths. Keep paid and shared access disabled in the shipped VPN until the applicable gates pass.

# Contributing

Read the [principles](docs/PRINCIPLES.md), [conduct policy](CODE_OF_CONDUCT.md),
[security limits](SECURITY.md) and [roadmap](docs/ROADMAP.md). Pseudonymous contributions
are welcome. No employer affiliation, academic credential, donation or government ID
is required. Contributions retain the repository's Apache-2.0 licensing; preserve
third-party license notices.

For a change, explain the problem and resulting behavior, link the relevant roadmap
gate and report the checks performed and limitations. Keep unrelated changes separate.
Use signed commits. Describe boundary changes in [the decision log](docs/DECISIONS.md).
See [governance](docs/GOVERNANCE.md) for decisions and reconsideration.

The pinned Rust toolchain is in `rust-toolchain.toml`. Install Python dependencies
using `python -m pip install --require-hashes -r tools/hardware-requirements.txt` in an
isolated environment. The canonical checks and exact CI environments are in
[verify.yml](.github/workflows/verify.yml): formatting, Ruff, Clippy, Rust rejection
tests, Python unit tests, formal models and isolated network labs. Run the checks that
exercise your change; report optional dependencies and skipped tests. Root network and
installation labs belong in disposable VMs or documented isolated namespaces, never
against somebody's active VPN. Do not reset a physical key to make a test pass.

Never include private keys, credential handles, cloud tokens, real PINs, recovery
material, user traffic or raw production logs. Use the private reporting instructions
in SECURITY.md for exploitable findings. Independent reviewers can start with the
[review package](docs/INDEPENDENT_REVIEW.md); an unpaid review can be independent.

# zk-membership: anonymous membership + nullifier as a STARK (research prototype)

The design and the decision are in `docs/ZK_MEMBERSHIP_DESIGN.md`; the measured run is
`docs/evidence/ZK_MEMBERSHIP.json`. Not part of the shipping build or of CI.

- `methods/guest/src/main.rs`: the statement proved in the RISC Zero zkVM (Merkle
  membership of `SHA-256("avpn/member/v1" || s)` and the nullifier
  `SHA-256("avpn/nullifier/v1" || s || epoch || scope)`).
- `host/src/main.rs`: builds a tree of 2^DEPTH members, proves one membership with a
  succinct STARK receipt (never in dev mode), verifies it, checks the properties, prints
  JSON.

Run (needs the RISC Zero toolchain: `rzup install`, about 3 GB):

    cargo build --release && ./target/release/host 20

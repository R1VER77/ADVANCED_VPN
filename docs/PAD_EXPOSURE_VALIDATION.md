# Pad exposure containment and forward secrecy validation

17 November 2026. Assessment and engineering direction for cypherpunk_vpn, based on
source `43996ad`. Examples are test fixtures or proposed interfaces; this guide does
not implement a new pad source, storage format, recovery protocol or VPN integration.

## Findings

Independent, secret, one-time round pads can contain disclosure of one pad to its
own round. The existing round core implements one-time consumption, and the formal
pad model verifies non-reuse and secrecy of pads whose uses were not leaked. The
model assumes fresh independent values; it does not qualify the real generator.

| Property | Meaning | Current evidence |
|---|---|---|
| Pad exposure containment | Learning a round pad does not derive another independent round pad | Ideal symbolic pad model; normal-API consumption and wiping tests |
| Forward secrecy | Compromising current state does not recover erased earlier secrets | Computational hash-chain construction; three-round, one-capture symbolic model |
| Post-compromise recovery | After an intrusion ends, future secrets become protected again | No qualified recovery protocol for these pads; needs fresh secret input and a recovered endpoint |

Before use, ideal book pads must be jointly uniform and independent conditional on
Eve's generation/custody information `Z`. For a leaked entry `K_i`, in particular:

```text
I(K_other_entries ; K_i | Z) = 0
```

This concerns derivation of other pad entries. Round transcripts, event contents and
behavioural correlation need their own composition argument. Independent pads cannot
make an identity disclosed in one event unknown again. For extracted near-uniform
books, state a derived joint statistical-distance bound instead of exact zero.

## Exposure cases

| What the observer obtains | Expected boundary |
|---|---|
| One independent pad value | Other pad entries remain secret under the book's source and observation assumptions |
| One secret edge in a DC-net round | Remove that edge from the honest graph; the remaining connected components define candidate anonymity sets |
| Current network-chain state | Earlier protection is computational and requires erasure; current and future chain outputs are derivable |
| An unlocked book or its process memory | Accessible unused entries are exposed; one-entry containment does not apply |
| Encrypted envelopes or book snapshots | Protection is computational; custody and erasure assumptions must cover all copies |
| Persistent endpoint control | No promise that later randomness, event contents or pad use stays secret |

One edge leak need not destroy even that round's anonymity if other unknown edges
still connect the honest members. Enough exposed edges can reveal the sender's
component or identify a singleton. The reference core also permits a member who
knows an event to substitute another using an XOR difference; the public event hash
is not authorization. See the [paper review](INFORMATION_THEORETIC_REVIEW_20261117.md).

## Existing evidence

- [`PadBook::take`](../src/dcnet.rs) consumes one entry, wipes it and skipped entries,
  refuses reuse and stops at exhaustion. `Drop` wipes its tracked buffer.
- [`Book.take`](../tools/padbook.py) serializes cooperating consumers, persists the
  advanced state and zeroes consumed records before returning a pad.
- [`test_audit_state.py`](../tools/test_audit_state.py) exercises stale handles,
  threads/processes and durable state operations. These do not defeat full snapshots.
- [`dcnet_one_time_pads.spthy`](../formal/dcnet/dcnet_one_time_pads.spthy) verifies
  `pad_used_once`, `pad_known_only_if_leaked` and an executable use trace.
- [`dcnet_ratchet.spthy`](../formal/dcnet/dcnet_ratchet.spthy) verifies past-round
  secrecy in a model unrolled to three rounds with one state capture.
- [`TAMARIN.json`](evidence/TAMARIN.json) records proved lemmas, negative mutants and
  limits. Full authenticated multi-round sender equivalence has not been proved.

The 26 passing Rust DC-net cases reported in the paper review include an
exact-transcript sender-path coupling. Fixed synthetic bytes check code behaviour,
not physical entropy. The four-device setup trials validate those units' vault/access
behaviour, not hardware pad independence or forensic erasure.

The baseline [verification run](https://github.com/R1VER77/CYPHERPUNK_VPN/actions/runs/44098710860)
passed all three jobs. The open qualification gates below remain separate.

## Reproduce the current checks

Use an isolated checkout of a signed source revision. Obtain the signing public key
through a trusted channel and configure Git's allowed signers before interpreting
signature verification. Use synthetic data and temporary vaults.

```sh
cd /path/to/cypherpunk_vpn
git verify-commit HEAD
git rev-parse HEAD
git status --porcelain
rustc --version
cargo --version
tamarin-prover --version
maude --version
```

Use pinned Rust 1.95 and locked dependencies. Tamarin is 1.12.0 and Maude is 3.5.1;
their pinned downloads are in [`verify.yml`](../.github/workflows/verify.yml).
A fresh Python environment needs the hash-locked requirements. Network access is
required for uncached dependencies.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r tools/hardware-requirements.txt

cargo test --locked --lib dcnet::tests -- --nocapture
cargo fmt --all -- --check
cargo clippy --locked --lib --tests -- -D warnings

.venv/bin/python tools/dcnet_reference.py --check
.venv/bin/python -m unittest discover -s tools -p test_padbook.py -v
.venv/bin/python -m unittest discover -s tools -p test_padstore.py -v
.venv/bin/python -m unittest discover -s tools -p test_audit_state.py -v
```

These unit cases inject synthetic hardware responses. They must not require a real
PIN or change a connected key. The existing recorded-cell-run Rust case is ignored
by default; report that skip rather than counting it as a new physical pass.

Run selected models and their associated mutants, writing a fresh report outside
the committed full-model evidence file:

```sh
PAD_REPORT_DIR=$(mktemp -d)
.venv/bin/python tools/tamarin_check.py \
  --timeout 900 --json "$PAD_REPORT_DIR/tamarin-pad-exposure.json" \
  formal/dcnet/dcnet_one_time_pads.spthy \
  formal/dcnet/dcnet_ratchet.spthy \
  formal/dcnet/dcnet_collusion_4.spthy
```

Every named positive lemma must verify, and selected broken mutants must be
falsified. Missing lemmas, timeouts and incomplete analyses do not pass. Preserve
the report and tool versions; `mktemp` avoids replacing earlier evidence.

The [17 November focused validation](evidence/PAD_EXPOSURE_VALIDATION_20261117.json)
records nine verified lemmas and four rejected mutants, 26 passing Rust DC-net tests
with one existing ignored case, and 68 passing Python pad/storage/state tests. Both
examples below were extracted and executed in a temporary directory; the Rust
example compiled against an existing built library and passed its one test. Runtime
code, production vaults and connected-device configuration were unchanged.

## Exact example of pad independence

This exhaustive one-bit example demonstrates the mathematical requirement. It also
rejects a family whose entries are pairwise independent but not jointly independent.
It does not generate usable pads or certify a physical source.

```python
from collections import Counter
from fractions import Fraction
from itertools import product


def remaining_law(rows, exposed, value=None):
    # Each row is an equally likely source outcome in this finite toy model.
    selected = [r for r in rows if value is None or r[exposed] == value]
    counts = Counter(tuple(v for j, v in enumerate(r) if j != exposed)
                     for r in selected)
    return {outcome: Fraction(count, len(selected))
            for outcome, count in counts.items()}


independent = list(product((0, 1), repeat=3))
for exposed in range(3):
    before = remaining_law(independent, exposed)
    for leaked_value in (0, 1):
        assert remaining_law(independent, exposed, leaked_value) == before

# Each entry looks uniform, but K2 = K0 XOR K1 leaks a joint relation.
correlated = [(a, b, a ^ b) for a, b in product((0, 1), repeat=2)]
assert remaining_law(correlated, 0, 0) != remaining_law(correlated, 0)
print("Exact ideal containment holds; correlated counterexample rejected")
```

Frequency tests, a failed machine-learning prediction attempt, or checking that two
pads differ cannot replace this argument or establish real-source independence.

## Rust regression sketch

This proposed integration-test body uses the existing public API. If implementation
work is later authorized, place it in `tests/pad_exposure.rs` and run
`cargo test --locked --test pad_exposure`. Fixed arrays are test fixtures only.

```rust
use cypherpunk_vpn::dcnet::{BODY_LEN, DcError, PadBook};

#[test]
fn exposing_one_fixture_pad_does_not_change_other_entries() {
    let first = [0x11_u8; BODY_LEN];
    let leaked = [0x22_u8; BODY_LEN];
    let third = [0x33_u8; BODY_LEN];
    let mut book = PadBook::new(100, [first, leaked, third].concat()).unwrap();

    assert_eq!(book.take(100).unwrap(), first);
    let observed_by_attacker = book.take(101).unwrap();
    assert_eq!(observed_by_attacker, leaked);
    assert!(matches!(book.take(100), Err(DcError::PadUsed)));
    assert!(matches!(book.take(101), Err(DcError::PadUsed)));
    assert_eq!(book.take(102).unwrap(), third);
    assert!(matches!(book.take(103), Err(DcError::PadsExhausted)));
}
```

This checks consumption and isolation of API entries, not the source's independence.
Existing in-module tests inspect wiping. This public-API sketch cannot inspect the
private buffer or prove erasure of copies.

## Build and validation sequence

### 1 Define the exposure experiment

Specify pair/cell/round/epoch binding; when endpoints collude; when Eve learns an
output pad versus state; which storage/envelopes/backups she observes; and the erasure
and authenticated-channel assumptions. Include adaptive leaks and an honest trace.
Remove colluders and known-pad edges before identifying each anonymity set.

**Acceptance:** ideal transcript distributions agree for candidate senders within a
surviving component, using the actual codec and frames. Exposed cuts give the expected
smaller components. Approximate versions have a joint bound. Secrecy lemmas alone
do not establish equivalence, and event authorization remains a separate boundary.

### 2 Qualify generation

Trace physical sources, extractor seed, extraction and mixing. Establish conditional
entropy and cross-block/cross-edge dependencies. Resolve the current ChaCha-derived
seed and seed-reuse proof gaps. Budget error across book/cell/session and define source
failure/expiry criteria. Health tests support a source model but do not prove secrecy.

The existing `edge_claim()` interprets declared provenance. A future qualified profile
must reference reviewed source/seed/composition evidence and refuse unqualified inputs.
A positive JSON flag is insufficient. Exhaustion must never silently substitute a PRG
chain. The [paper review](INFORMATION_THEORETIC_REVIEW_20261117.md) lists detailed gaps.

**Acceptance:** an applicable finite-length extraction argument, reproducible source
assessment, joint error budget and explicit observation/custody boundary.

### 3 Validate durable consumption

Retain transaction locking, state reload and commit-before-release order. Inject faults
at reads, state writes, syncs, replacement, erasure and return. A failure may burn a
pad, but must not successfully release the same identified entry twice. Test separate
processes and stale pre-opened handles. The required contract is:

```text
lock stable state identity
reload and validate current generation and round
read selected pad into a bounded secret buffer
durably mark selected and skipped rounds consumed
erase and sync consumed records
release pad only after successful commit
on failure: release no pad and retain enough state to refuse reuse
```

**Acceptance:** no duplicate successful release in the stated crash/concurrency model.
Full snapshot resistance is separate. Copied old stores and keys can contain old pads
regardless of the latest counter. An external monotonic mechanism can detect protocol
rollback but cannot erase an adversary's already copied pad.

### 4 Test book and device compromise separately

Treat Rust book memory, Python immutable copies, decrypted records, wrapping keys and
future-chain state as separate adversary inputs. An unlocked host-resident book exposes
accessible entries. For stronger containment, design bounded batches or a device that
retains inaccessible book material and performs controlled round operations. Stock
FIDO2 sealing is not a token-resident DC-net. A custom applet needs its own API, reset,
side-channel, tamper and erasure review.

**Acceptance:** actual leakage matches the claim. Nitrokey/YubiKey/Trezor/Ledger PIN
and touch tests do not certify pad entropy or erasure. Use temporary credentials,
preserving wallet material, firmware and unrelated key applications.

### 5 Design recovery if required

Recover endpoint integrity and supply fresh shared secret information unknown to Eve.
Bind replacement books to a new epoch, pair and cell. Reject stale, mismatched,
duplicate and partially installed replacements. Stay blocked until both ends agree;
retries must not reuse consumed entries. Re-establish peer authentication independently
of stolen credentials and define revocation/re-verification of compromised identities.

Hashing exposed state again cannot heal it. Hybrid-KEM replenishment could provide
computational recovery under its assumptions. Information-theoretic recovery needs
an appropriate secret delivery or correlated-source model. An attacker remaining on
the endpoint can observe replacement secrets too.

**Acceptance:** prove and test the recovery point, lost updates, active interference,
delayed messages and an executable recovery trace. This is new work; the existing
three-round ratchet proof does not establish post-compromise recovery.

### 6 Validate integration and obtain independent review

Use disposable namespace/VM peers with synthetic events before VPN integration. Test
pad leaks, exposed cuts, churn, offline peers, duplicate frames, replay, jams, crashes
and exhaustion. A fallback must not silently reduce the displayed claim. Measure
fixed participation, timing/packet metadata and identity leakage across rounds.

**Acceptance:** record signed source, tool/dependency versions, hashes, commands,
positive/negative/ignored results, compromise inputs, reviewer scope and residual
limits. Keep pads, credentials, raw noise and identifying captures private. Independent
review must cover entropy, composition, storage/erasure and protocol boundaries.
Funding is not a prerequisite for review.

## Claim and novelty boundaries

Supported construction wording:

> Under the stated source, custody and observation assumptions, disclosure of one
> independent round pad does not reveal other pad entries. DC-net sender anonymity
> in that round depends on the remaining honest secret-edge graph. Current hash
> chains offer computational protection of erased earlier state, not recovery after
> current-state compromise.

Do not describe the deployed VPN as having validated perfect forward privacy.
The source, compromise, erasure and integration gates remain open.

The underlying ideas have prior art: [Chaum's DC-net paper](https://chaum.com/wp-content/uploads/2022/01/chaum-dc.pdf)
describes one-time-key anonymity; the
[Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
distinguishes forward security, message-key isolation and recovery; and
[proactive secret sharing](https://research.google/pubs/proactive-secret-sharing-or-how-to-cope-with-perpetual-leakage/)
addresses renewing distributed shares against compromise over time. Originality for
this project's combination needs a focused literature comparison, a precise additional
property and an argument establishing it. Composition alone is not a new theorem.

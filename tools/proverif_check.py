#!/usr/bin/env python3
"""Prove the project's ProVerif equivalence models and fail unless every one holds.

Each model lists the results ProVerif must print, in order, so a query that is dropped or
left unproved fails the check; and each listed broken variant (MUTANTS) must fail to prove,
so no equivalence passes by being vacuous. Mutants are edits applied to the model itself
(an edit that no longer applies fails too). Used by CI (verify.yml, job formal-models) with
ProVerif 2.05 built from the pinned source release; `--json` writes docs/evidence/PROVERIF.json.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
EQUIVALENT = "Observational equivalence is true."

MODELS = {
    "formal/ohttp/ohttp_unlinkability.pv": [EQUIVALENT],
    "formal/credits/credits_unlinkability.pv": [EQUIVALENT],
    "formal/voucher/voucher_unlinkability.pv": [EQUIVALENT],
}

# (model, [(old, new), ...], what the mutant breaks). Each must NOT prove.
MUTANTS = [
    (
        "formal/ohttp/ohttp_unlinkability.pv",
        [
            ("  new rsk: skey;\n", ""),
            ("pk(rsk)), gpk, r));", "pk(id)), gpk, r));"),
            ("adec(response, rsk)", "adec(response, id)"),
        ],
        "a member reuses one reply key for every request",
    ),
    (
        "formal/ohttp/ohttp_unlinkability.pv",
        [
            ("  new gsk: skey;\n  out(c, gsk);\n", ""),
            (
                "Member(pk(gsk), choice[id1, id2])",
                "out(c, choice[id1, id2]); Member(pk(choice[id1, id2]), choice[id1, id2])",
            ),
        ],
        "each member is given its own gateway key (no key consistency)",
    ),
    (
        "formal/credits/credits_unlinkability.pv",
        [
            ("out(c, blind(fdh(tokenA), rA));", "out(c, fdh(tokenA));"),
            ("out(c, blind(fdh(tokenB), rB));", "out(c, fdh(tokenB));"),
            ("let sigA = unblind(signedA, rA) in", "let sigA = signedA in"),
            ("let sigB = unblind(signedB, rB) in", "let sigB = signedB in"),
        ],
        "the member sends its token's hash unblinded",
    ),
    (
        "formal/credits/credits_unlinkability.pv",
        [
            (
                "  new sk: skey;\n  out(c, sk);\n  ! (\n",
                "  ! (\n    new skA: skey; new skB: skey;\n    out(c, (skA, skB));\n",
            ),
            ("checksign(sigA, pk(sk))", "checksign(sigA, pk(skA))"),
            ("checksign(sigB, pk(sk))", "checksign(sigB, pk(skB))"),
            (
                "out(c, choice[(tokenA, sigA), (tokenB, sigB)]);",
                "out(c, choice[(tokenA, sigA, pk(skA)), (tokenB, sigB, pk(skB))]);",
            ),
            (
                "out(c, choice[(tokenB, sigB), (tokenA, sigA)])",
                "out(c, choice[(tokenB, sigB, pk(skB)), (tokenA, sigA, pk(skA))])",
            ),
        ],
        "each member trusts its own issuer key, named in the spend",
    ),
    (
        "formal/voucher/voucher_unlinkability.pv",
        [
            ("out(c, (payA, tier, blind(fdh(secretA), rA)));", "out(c, (payA, tier, fdh(secretA)));"),
            ("out(c, (payB, tier, blind(fdh(secretB), rB)));", "out(c, (payB, tier, fdh(secretB)));"),
            # ...and keeps the signature as returned: otherwise `unblind` fails, both
            # buyers stop before phase 1 and the equivalence holds vacuously.
            ("let sigA = unblind(signedA, rA) in", "let sigA = signedA in"),
            ("let sigB = unblind(signedB, rB) in", "let sigB = signedB in"),
        ],
        "a buyer sends its voucher secret's hash unblinded at issuance",
    ),
    (
        "formal/voucher/voucher_unlinkability.pv",
        [
            (
                "  new sk: skey;\n  out(c, sk);\n  ! (\n",
                "  ! (\n    new skA: skey; new skB: skey;\n    out(c, (skA, skB));\n",
            ),
            ("checksign(sigA, pk(sk))", "checksign(sigA, pk(skA))"),
            ("checksign(sigB, pk(sk))", "checksign(sigB, pk(skB))"),
            (
                "out(c, choice[(secretA, sigA, tier), (secretB, sigB, tier)]);",
                "out(c, choice[(secretA, sigA, pk(skA)), (secretB, sigB, pk(skB))]);",
            ),
            (
                "out(c, choice[(secretB, sigB, tier), (secretA, sigA, tier)])",
                "out(c, choice[(secretB, sigB, pk(skB)), (secretA, sigA, pk(skA))])",
            ),
        ],
        "the two vouchers are minted under different epoch keys, named in the redemption",
    ),
    (
        "formal/voucher/voucher_unlinkability.pv",
        [
            ("out(c, (payB, tier, blind(fdh(secretB), rB)));", "out(c, (payB, payB, blind(fdh(secretB), rB)));"),
            (
                "out(c, choice[(secretA, sigA, tier), (secretB, sigB, tier)]);",
                "out(c, choice[(secretA, sigA, tier), (secretB, sigB, payB)]);",
            ),
            (
                "out(c, choice[(secretB, sigB, tier), (secretA, sigA, tier)])",
                "out(c, choice[(secretB, sigB, payB), (secretA, sigA, tier)])",
            ),
        ],
        "the two vouchers are for different tiers (cross-tier unlinkability is not claimed)",
    ),
]

RESULT = re.compile(r"^RESULT (.*)$", re.M)


def prove(path, timeout):
    """(RESULT lines, seconds, exit code or "timeout") of one ProVerif run."""
    start = time.monotonic()
    try:
        r = subprocess.run(["proverif", str(path)], capture_output=True, text=True, timeout=timeout, check=False)
        output, code = r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        output, code = "", "timeout"
    return RESULT.findall(output), round(time.monotonic() - start, 2), code


def main():
    """Prove every listed model and mutant; exit non-zero unless all pass."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--timeout", type=int, default=600, help="seconds per model")
    p.add_argument("--json", type=Path, help="write the results here")
    a = p.parse_args()
    version = subprocess.run(["proverif", "--help"], capture_output=True, text=True, check=False).stdout.splitlines()
    results, mutants, failed = {}, [], []
    for model, expected in MODELS.items():
        got, seconds, code = prove(ROOT / model, a.timeout)
        results[model] = dict(seconds=seconds, exit_code=code, results=got)
        print("%-50s %s" % (model, "; ".join(got) or "NO RESULT (%s)" % code))
        if code != 0 or got != expected:
            failed.append("%s: expected %s, got %s" % (model, expected, got or code))
    for model, edits, breaks in MUTANTS:
        text = (ROOT / model).read_text()
        for old, new in edits:
            if text.count(old) != 1:
                failed.append("%s: mutant edit no longer applies once: %r" % (model, old[:60]))
            text = text.replace(old, new)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / Path(model).name
            path.write_text(text)
            got, seconds, code = prove(path, a.timeout)
        refuted = code == 0 and bool(got) and EQUIVALENT not in got
        mutants.append(dict(model=model, breaks=breaks, results=got, seconds=seconds))
        print("%-50s %s (mutant, must not prove: %s)" % (model, "; ".join(got) or code, breaks))
        if not refuted:
            failed.append("%s: mutant (%s) was not refuted: %s" % (model, breaks, got or code))
    if a.json:
        a.json.write_text(
            json.dumps(
                dict(
                    tool=version[0] if version else "proverif",
                    models=results,
                    mutants=mutants,
                    failed=failed,
                ),
                indent=1,
            )
            + "\n"
        )
    for f in failed:
        print("FAILED:", f, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

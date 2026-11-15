#!/usr/bin/env python3
"""Prove the project's Tamarin models and fail unless every lemma is verified.

Each model's expected lemmas are listed here, so a lemma that is renamed, dropped or
left unproved fails the check as surely as a falsified one; and each listed broken
variant (MUTANTS) must be falsified, so no lemma passes by being vacuous. Used by CI (verify.yml)
with the pinned Tamarin 1.12.0 / Maude 3.5.1; `--json` writes docs/evidence/TAMARIN.json.
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

MODELS = {
    "formal/dcnet/dcnet.spthy": ["keys_secret", "frame_authenticity", "cancellation"],
    "formal/dcnet/dcnet_authenticity.spthy": ["keys_secret", "frame_authenticity", "executable_accept"],
    "formal/dcnet/dcnet_no_collusion.spthy": ["pad_secrecy_without_collusion"],
    "formal/dcnet/dcnet_collusion.spthy": [
        "honest_key_secret",
        "decodes_exactly",
        "executable",
        "collusion_reveals_pad",
    ],
    "crates/avpn-mix-lane/tamarin/pq_sphinx_reblind.spthy": [
        "element_hidden",
        "pad_hidden",
        "executable",
        "global_xor_reveals_pad",
    ],
}

# Broken variants the prover must falsify, so a lemma cannot pass by being vacuous or
# by not depending on what it is meant to protect: (model, [(text, replacement)], lemma).
MUTANTS = [
    (
        "formal/dcnet/dcnet_authenticity.spthy",
        [("In(<r, f, h(<'dc-mac', kc, r, f>)>)", "In(<r, f, mac>)")],
        "frame_authenticity",
    ),
    (
        "formal/dcnet/dcnet_authenticity.spthy",
        [
            ("In(<r, f, h(<'dc-mac', kc, r, f>)>)", "In(<r, f, h(<'dc-mac', kc, f>)>)"),
            ("h(<'dc-mac', kc, r, h(<k1, r>) XOR h(<k2, r>)>)", "h(<'dc-mac', kc, h(<k1, r>) XOR h(<k2, r>)>)"),
            (
                "h(<'dc-mac', kc, r, ~m XOR h(<k1, r>) XOR h(<k2, r>)>)",
                "h(<'dc-mac', kc, ~m XOR h(<k1, r>) XOR h(<k2, r>)>)",
            ),
        ],
        "frame_authenticity",
    ),
    (
        "formal/dcnet/dcnet.spthy",
        [
            (
                "  --[ Transmit(id, r, h(<k1, r>) XOR h(<k2, r>)) ]->\n"
                "  [ Out(<r, h(<k1, r>) XOR h(<k2, r>), h(<'dc-mac', kc, r, h(<k1, r>) XOR h(<k2, r>)>)>) ]",
                "  --[ Transmit(id, r, h(<k1, r>)) ]->\n  [ Out(<r, h(<k1, r>), h(<'dc-mac', kc, r, h(<k1, r>)>)>) ]",
            )
        ],
        "cancellation",
    ),
    ("formal/dcnet/dcnet_no_collusion.spthy", [("Out(~m) ]", "Out(~m), Out(~kac) ]")], "pad_secrecy_without_collusion"),
    (
        "formal/dcnet/dcnet_collusion.spthy",
        [("      fb = h(<~kab, ~r>) XOR h(<~kbc, ~r>)", "      fb = h(<~kbc, ~r>)")],
        "decodes_exactly",
    ),
    (
        "crates/avpn-mix-lane/tamarin/pq_sphinx_reblind.spthy",
        [("[ Out(<aenc(~k1, pk1), ~e2 XOR h(<~k1, 'pad2'>)>) ]", "[ Out(<aenc(~k1, pk1), ~e2>) ]")],
        "element_hidden",
    ),
]

LINE = re.compile(
    r"^\s+(\w+) \((all-traces|exists-trace)\): (verified|falsified - found trace|analysis incomplete)[^(]*\((\d+) steps\)"
)


def summary(output):
    """{lemma: (kind, result, steps)} from Tamarin's final summary."""
    tail = output.split("summary of summaries", 1)[-1]
    out = {}
    for line in tail.splitlines():
        m = LINE.match(line)
        if m:
            out[m.group(1)] = (m.group(2), m.group(3), int(m.group(4)))
    return out


def prove(model, timeout, lemma=None, path=None):
    """Run Tamarin on `model` (or a mutant copy at `path`), optionally one lemma:
    (summary, seconds, exit code or "timeout")."""
    start = time.monotonic()
    try:
        r = subprocess.run(
            ["tamarin-prover", "--prove" + ("=" + lemma if lemma else ""), str(path or ROOT / model)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output, code = r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        output, code = "", "timeout"
    return summary(output), round(time.monotonic() - start, 1), code


def main():
    """Prove every listed model and mutant; exit non-zero unless all pass."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--timeout", type=int, default=900, help="seconds per model")
    p.add_argument("--json", type=Path, help="write the results here")
    p.add_argument("models", nargs="*", help="only these models (default: all)")
    a = p.parse_args()
    version = subprocess.run(["tamarin-prover", "--version"], capture_output=True, text=True, check=False).stdout
    maude = subprocess.run(["maude", "--version"], capture_output=True, text=True, check=False).stdout.strip()
    results, failed = {}, []
    for model, expected in MODELS.items():
        if a.models and model not in a.models:
            continue
        lemmas, seconds, code = prove(model, a.timeout)
        results[model] = dict(
            seconds=seconds,
            lemmas={k: dict(kind=v[0], result=v[1], steps=v[2]) for k, v in lemmas.items()},
        )
        for lemma in expected:
            got = lemmas.get(lemma)
            ok = got is not None and got[1] == "verified"
            print("%-55s %-34s %s" % (model, lemma, got[1] if got else "MISSING (%s)" % code))
            if not ok:
                failed.append("%s: %s" % (model, lemma))
        for extra in sorted(set(lemmas) - set(expected)):
            failed.append("%s: unexpected lemma %s (list it here)" % (model, extra))
    mutants = []
    for model, edits, lemma in MUTANTS:
        if a.models and model not in a.models:
            continue
        text = (ROOT / model).read_text()
        for old, new in edits:
            if old not in text:
                failed.append("%s: mutant edit no longer applies: %r" % (model, old[:60]))
            text = text.replace(old, new)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / Path(model).name
            path.write_text(text)
            got, seconds, code = prove(model, a.timeout, lemma, path)
        result = got.get(lemma, (None, "MISSING (%s)" % code, 0))[1]
        mutants.append(dict(model=model, lemma=lemma, edits=len(edits), result=result, seconds=seconds))
        print("%-55s %-34s %s (mutant: must be falsified)" % (model, lemma, result))
        if not result.startswith("falsified"):
            failed.append("%s: mutant of %s was not falsified (%s)" % (model, lemma, result))
    if a.json:
        a.json.write_text(
            json.dumps(
                dict(
                    schema=1,
                    tool=version.splitlines()[0] if version else "tamarin-prover",
                    maude=maude,
                    date=time.strftime("%Y-%m-%d"),
                    models=results,
                    mutants=mutants,
                    not_proved=[
                        "DC-net sender anonymity as observational equivalence: --diff with XOR did not "
                        "terminate, even on the two-party core; the argument is the hand proof in "
                        "docs/DCNET_CONTROL_DESIGN.md section 6",
                        "DC-net per-round pad secrecy and an existence trace in the multi-round, "
                        "MAC-authenticated model: did not terminate (single-round versions are proved)",
                        "A colluder learning only XORs of honest pads in a 4-member cell: did not terminate",
                        "Re-blinding: secrecy of the KEM secret itself, and unlinkability across hop 1 "
                        "(an equivalence): did not terminate; the construction stays review-pending",
                    ],
                ),
                indent=2,
            )
            + "\n"
        )
    if failed:
        sys.exit("not proved: " + "; ".join(failed))


if __name__ == "__main__":
    main()

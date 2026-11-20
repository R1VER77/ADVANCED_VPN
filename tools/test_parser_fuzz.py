"""Mutation fuzzing of the Python parsers that take outside bytes (docs/VERIFICATION_PLAN.md:
"cargo-fuzz, proptest, Hypothesis for the parsers"). Standard library only: valid inputs are
flipped, truncated, extended and spliced by a seeded generator, and every parser must refuse
them with its own documented error, never another exception. The Rust parsers are fuzzed
coverage-guided in fuzz/."""

import json
from pathlib import Path
import random
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROUNDS = 1500


def mutations(valid: bytes, seed: int, rounds: int = ROUNDS):
    """Seeded mutants of `valid`: bit flips, byte sets, truncations, insertions, splices."""
    rng = random.Random(seed)  # noqa: S311 (reproducible test inputs, not secrets)
    for _ in range(rounds):
        b = bytearray(valid)
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(5)
            if op == 0 and b:
                i = rng.randrange(len(b))
                b[i] ^= 1 << rng.randrange(8)
            elif op == 1 and b:
                b[rng.randrange(len(b))] = rng.choice((0, 0xFF, 0x7F, 0x80, ord('"'), ord("{")))
            elif op == 2:
                del b[rng.randrange(len(b) + 1) :]
            elif op == 3:
                i = rng.randrange(len(b) + 1)
                b[i:i] = rng.randbytes(rng.randint(1, 16))
            elif op == 4 and len(b) > 2:
                i, j = sorted(rng.sample(range(len(b)), 2))
                b[i:j] = b[i:j][::-1]
        yield bytes(b)


class Parsers(unittest.TestCase):
    rounds = ROUNDS

    def survive(self, parse, valid, allowed, seed):
        """Every mutant either parses or raises one of `allowed`."""
        for i, data in enumerate(mutations(valid, seed, self.rounds)):
            try:
                parse(data)
            except allowed:
                pass
            except Exception as e:  # noqa: BLE001 - the point is to catch the unexpected
                self.fail("mutant %d raised %s: %r (input %s)" % (i, type(e).__name__, e, data[:80].hex()))

    def test_the_ohttp_gateway_refuses_every_mutant_with_refused(self):
        import ohttp

        private, public = ohttp.keypair()
        wire, _ = ohttp.encapsulate(public, 7, "POST", "/gossip", b"x", now=time.time())
        gateway = ohttp.Gateway(private, 7, started=time.time() - 120)
        self.survive(lambda d: gateway.open(d), wire, ohttp.Refused, 1)

    def test_the_ohttp_client_refuses_every_mutant_response_with_refused(self):
        import ohttp

        private, public = ohttp.keypair()
        wire, reply = ohttp.encapsulate(public, 7, "GET", "/health", now=time.time())
        _, _, _, reply_key = ohttp.Gateway(private, 7, started=time.time() - 120).open(wire)
        sealed = ohttp.Gateway.seal(reply_key, 200, b"{}")
        self.survive(lambda d: ohttp.decapsulate(d, reply), sealed, ohttp.Refused, 2)

    def test_a_hop_refuses_every_mutant_session_leaf_with_value_error(self):
        import session_auth

        vectors = json.loads((Path(__file__).resolve().parent / "testdata/session_auth.json").read_text())
        good = next(v for v in vectors["vectors"] if v["name"] == "accepted_es256")
        leaf = bytes.fromhex(good["leaf"])
        self.survive(lambda d: session_auth.verify_leaf(good["device"], d, vectors["now"]), leaf, ValueError, 3)

    def test_an_enrollment_request_is_refused_with_value_error(self):
        import keyguard
        import managed_profile as mp

        secret = bytes(range(32))
        meta = dict(salt=keyguard.b64(bytes(32)), credential=keyguard.b64(b"record"), counter=0)
        import tempfile

        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch.object(keyguard, "hardware_secret", lambda v: (secret, meta)),
        ):
            req = mp.request("exit", Path(d) / "exit", "none")
        raw = mp.canonical(req)
        self.survive(lambda d: mp.load_request(d, "exit"), raw, ValueError, 4)


class Fuzzer(unittest.TestCase):
    def test_the_mutator_actually_changes_its_input(self):
        valid = b'{"a": 1, "b": "xyz"}'
        changed = sum(m != valid for m in mutations(valid, 9, 200))
        self.assertGreater(changed, 190)


if __name__ == "__main__":
    unittest.main()

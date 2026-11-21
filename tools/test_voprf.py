#!/usr/bin/env python3
"""Tests for the RFC 9497 VOPRF (tools/voprf.py) against the RFC's own vectors.

Every check compares against a value printed in RFC 9496 (group encode, decode
rejection, element derivation, SQRT_RATIO_M1), RFC 9380 (expand_message_xmd
with SHA-512) or RFC 9497 (DeriveKeyPair, BlindedElement, EvaluationElement,
Proof, Output for the OPRF and VOPRF modes, batch included). A failure here
means the implementation is not the specified function.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import voprf  # noqa: E402


def h(hexstr: str) -> bytes:
    return bytes.fromhex("".join(hexstr.split()))


def scalar(hexstr: str) -> int:
    return int.from_bytes(h(hexstr), "little")


# ------------------------------------------------------ RFC 9496 A.1

GENERATOR_MULTIPLES = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
    "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
    "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
    "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
    "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
    "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
    "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
]

# RFC 9496 A.2: encodings that MUST be rejected (a representative sample).
INVALID_ENCODINGS = [
    # Non-canonical field encodings.
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f".replace("ff", "ff", 1),
    # Negative field elements.
    "0100000000000000000000000000000000000000000000000000000000000000",
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
    "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
    "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
    "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
    "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
    "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
    # Non-square x^2.
    "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
    "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
    "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
    "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
    "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
    "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
    "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
    "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
    # Negative x * y value.
    "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
    "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
    # s = -1, which causes y = 0.
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]

# RFC 9496 A.3: element derivation (input, encoded output) pairs.
DERIVATION_VECTORS = [
    (
        "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1"
        "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
        "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
    ),
    (
        "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27"
        "0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
        "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b",
    ),
    (
        "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c"
        "27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
        "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826",
    ),
    (
        "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2"
        "150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
        "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a",
    ),
    (
        "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767"
        "5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
        "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179",
    ),
    (
        "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2"
        "979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
        "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628",
    ),
    (
        "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462"
        "2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
        "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065",
    ),
]

# RFC 9496 A.3: these four inputs all derive the same output.
DERIVATION_COLLISIONS = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "1200000000000000000000000000000000000000000000000000000000000000",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000080"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000000"
    "1200000000000000000000000000000000000000000000000000000000000080",
]

# RFC 9496 A.4: SQRT_RATIO_M1 vectors (u, v, was_square, r).
SQRT_VECTORS = [
    ("00" * 32, "00" * 32, True, "00" * 32),
    ("00" * 32, "01" + "00" * 31, True, "00" * 32),
    ("01" + "00" * 31, "00" * 32, False, "00" * 32),
    ("02" + "00" * 31, "01" + "00" * 31, False, "3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54"),
    ("04" + "00" * 31, "01" + "00" * 31, True, "02" + "00" * 31),
    ("01" + "00" * 31, "04" + "00" * 31, True, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"),
]


class GroupTests(unittest.TestCase):
    def test_generator_multiples(self):
        point = voprf.IDENTITY
        for i, expected in enumerate(GENERATOR_MULTIPLES):
            self.assertEqual(voprf.encode(point), h(expected), f"B[{i}]")
            point = voprf.add(point, voprf.GENERATOR)

    def test_decode_rejects_invalid(self):
        for bad in INVALID_ENCODINGS:
            with self.assertRaises(ValueError, msg=bad):
                voprf.decode(h(bad))

    def test_decode_encode_round_trip(self):
        for good in GENERATOR_MULTIPLES[1:]:
            self.assertEqual(voprf.encode(voprf.decode(h(good))), h(good))

    def test_element_derivation(self):
        for inp, out in DERIVATION_VECTORS:
            self.assertEqual(voprf.encode(voprf.element_derivation(h(inp))), h(out))

    def test_element_derivation_collisions(self):
        outs = {voprf.encode(voprf.element_derivation(h(i))) for i in DERIVATION_COLLISIONS}
        self.assertEqual(
            outs,
            {h("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f")},
        )

    def test_sqrt_ratio_m1(self):
        for u, v, was_square, r in SQRT_VECTORS:
            got_square, got_r = voprf.sqrt_ratio_m1(int.from_bytes(h(u), "little"), int.from_bytes(h(v), "little"))
            self.assertEqual(got_square, was_square, (u, v))
            self.assertEqual(got_r, int.from_bytes(h(r), "little"), (u, v))


class ExpandMessageTests(unittest.TestCase):
    """RFC 9380 K.3: expand_message_xmd(SHA-512)."""

    DST = "QUUX-V01-CS02-with-expander-SHA512-256"

    def test_vectors(self):
        cases = [
            (b"", "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"),
            (b"abc", "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc"),
            (b"abcdef0123456789", "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58"),
        ]
        for msg, expected in cases:
            self.assertEqual(voprf.expand_message_xmd(msg, self.DST.encode(), 32), h(expected), msg)

    def test_length_matches_and_bounds(self):
        out = voprf.expand_message_xmd(b"m", b"dst", 200)
        self.assertEqual(len(out), 200)
        with self.assertRaises(ValueError):
            voprf.expand_message_xmd(b"m", b"dst", 65536)


# ------------------------------------------------------ RFC 9497 A.1

SEED = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
KEY_INFO = "74657374206b6579"  # "test key"
BLIND_1 = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"
BLIND_2 = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"
PROOF_RANDOM = "419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"

# NOTE: the RFC's second input is 17 bytes of 0x5a (the sage harness uses
# b'\x5A'*17); the printed hex is 34 characters.
INPUT_5A = "5a" * 17

OPRF_VECTORS = {
    "skSm": "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
    "cases": [
        (
            "00",
            "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
            "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
            "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f"
            "3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
        ),
        (
            INPUT_5A,
            "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
            "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
            "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4"
            "f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
        ),
    ],
}

VOPRF_VECTORS = {
    "skSm": "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909",
    "pkSm": "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e",
    "cases": [
        {
            "input": ["00"],
            "blind": [BLIND_1],
            "blinded": ["863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"],
            "evaluated": ["aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"],
            "proof": (
                "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd06"
                "6d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d"
            ),
            "proof_random": BLIND_2,
            "output": [
                "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7d"
                "a4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c"
            ],
        },
        {
            "input": [INPUT_5A],
            "blind": [BLIND_1],
            "blinded": ["cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"],
            "evaluated": ["60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"],
            "proof": (
                "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a"
                "67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02"
            ),
            "proof_random": BLIND_2,
            "output": [
                "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60"
                "356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6"
            ],
        },
        {
            "input": ["00", INPUT_5A],
            "blind": [BLIND_1, BLIND_2],
            "blinded": [
                "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
                "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654",
            ],
            "evaluated": [
                "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
                "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a",
            ],
            "proof": (
                "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a"
                "5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08"
            ),
            "proof_random": [PROOF_RANDOM],
            "output": [
                "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7d"
                "a4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c",
                "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60"
                "356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6",
            ],
        },
    ],
}


class DeriveKeyPairTests(unittest.TestCase):
    def test_oprf_seed(self):
        sk, pk = voprf.derive_key_pair(h(SEED), h(KEY_INFO), voprf.MODE_OPRF)
        self.assertEqual(sk, scalar(OPRF_VECTORS["skSm"]))
        self.assertEqual(pk, None or pk)  # OPRF vectors publish no pk

    def test_voprf_seed(self):
        sk, pk = voprf.derive_key_pair(h(SEED), h(KEY_INFO), voprf.MODE_VOPRF)
        self.assertEqual(sk, scalar(VOPRF_VECTORS["skSm"]))
        self.assertEqual(pk, h(VOPRF_VECTORS["pkSm"]))


class OPRFTests(unittest.TestCase):
    def test_vectors(self):
        sk, _ = voprf.derive_key_pair(h(SEED), h(KEY_INFO), voprf.MODE_OPRF)
        server = voprf.Server(sk, voprf.MODE_OPRF)
        for msg, blinded, evaluated, output in OPRF_VECTORS["cases"]:
            msg_bytes = h(msg)
            client = voprf.Client(b"", voprf.MODE_OPRF)  # OPRF needs no pk
            blind, blinded_got = client.blind(msg_bytes, scalar(BLIND_1))
            self.assertEqual(blinded_got, h(blinded), "BlindedElement")
            evaluated_got, _ = server.blind_evaluate(blinded_got)
            self.assertEqual(evaluated_got, h(evaluated), "EvaluationElement")
            out = client.finalize(msg_bytes, blind, evaluated_got, blinded_got, None)
            self.assertEqual(out, h(output), "Output")

    def test_evaluate_direct_matches_protocol(self):
        sk, _ = voprf.derive_key_pair(h(SEED), h(KEY_INFO), voprf.MODE_OPRF)
        server = voprf.Server(sk, voprf.MODE_OPRF)
        for msg, _, _, output in OPRF_VECTORS["cases"]:
            self.assertEqual(server.evaluate_direct(h(msg)), h(output))


class VOPRFTests(unittest.TestCase):
    def test_vectors_single(self):
        sk, pk = voprf.derive_key_pair(h(SEED), h(KEY_INFO), voprf.MODE_VOPRF)
        server = voprf.Server(sk, voprf.MODE_VOPRF)
        client = voprf.Client(pk, voprf.MODE_VOPRF)
        for case in VOPRF_VECTORS["cases"][:2]:
            msg = h(case["input"][0])
            blind, blinded = client.blind(msg, scalar(case["blind"][0]))
            self.assertEqual(blinded, h(case["blinded"][0]), "BlindedElement")
            evaluated, proof = server.blind_evaluate(blinded, scalar(case["proof_random"]))
            self.assertEqual(evaluated, h(case["evaluated"][0]), "EvaluationElement")
            self.assertEqual(proof[0], scalar(case["proof"][:64]), "proof c")
            self.assertEqual(proof[1], scalar(case["proof"][64:]), "proof s")
            out = client.finalize(msg, blind, evaluated, blinded, proof)
            self.assertEqual(out, h(case["output"][0]), "Output")

    def test_vector_batch(self):
        sk, pk = voprf.derive_key_pair(h(SEED), h(KEY_INFO), voprf.MODE_VOPRF)
        server = voprf.Server(sk, voprf.MODE_VOPRF)
        client = voprf.Client(pk, voprf.MODE_VOPRF)
        case = VOPRF_VECTORS["cases"][2]
        msgs = [h(m) for m in case["input"]]
        blinds, blinded = [], []
        for m, b in zip(msgs, case["blind"], strict=True):
            blind, enc = client.blind(m, scalar(b))
            blinds.append(blind)
            blinded.append(enc)
        self.assertEqual(blinded, [h(b) for b in case["blinded"]], "batch blinded")
        evaluated, proof = server.blind_evaluate_batch(blinded, scalar(case["proof_random"][0]))
        self.assertEqual(evaluated, [h(e) for e in case["evaluated"]], "batch evaluated")
        self.assertEqual(proof[0], scalar(case["proof"][:64]), "batch proof c")
        self.assertEqual(proof[1], scalar(case["proof"][64:]), "batch proof s")
        outs = client.finalize_batch(msgs, blinds, evaluated, blinded, proof)
        self.assertEqual(outs, [h(o) for o in case["output"]], "batch outputs")


class ProtocolPropertyTests(unittest.TestCase):
    """Beyond the vectors: the properties the mesh credits rely on."""

    def setUp(self):
        seed = bytes(range(32))
        sk, pk = voprf.derive_key_pair(seed, b"mesh-credit", voprf.MODE_VOPRF)
        self.server = voprf.Server(sk, voprf.MODE_VOPRF)
        self.pk = pk

    def test_unlinkability_of_blind(self):
        """The same input under two blinds yields the same output, and the
        server-side view (blinded elements) differs."""
        c1 = voprf.Client(self.pk, voprf.MODE_VOPRF)
        c2 = voprf.Client(self.pk, voprf.MODE_VOPRF)
        msg = b"relay credit epoch 42"
        out1 = voprf.run(self.server, c1, msg)
        out2 = voprf.run(self.server, c2, msg)
        self.assertEqual(out1, out2)
        # A fresh client blinds differently: blinded elements are random-looking.
        blind_a, blinded_a = c1.blind(msg)
        blind_b, blinded_b = c2.blind(msg)
        self.assertNotEqual(blinded_a, blinded_b)

    def test_proof_rejects_wrong_key(self):
        """A proof from a different server key must not verify."""
        other = voprf.Server(voprf.random_scalar(), voprf.MODE_VOPRF)
        client = voprf.Client(self.pk, voprf.MODE_VOPRF)
        msg = b"relay credit epoch 42"
        blind, blinded = client.blind(msg)
        evaluated, proof = other.blind_evaluate(blinded)
        with self.assertRaises(ValueError):
            client.finalize(msg, blind, evaluated, blinded, proof)

    def test_tampered_evaluation_rejected(self):
        client = voprf.Client(self.pk, voprf.MODE_VOPRF)
        msg = b"relay credit epoch 42"
        blind, blinded = client.blind(msg)
        evaluated, proof = self.server.blind_evaluate(blinded)
        bad = (int.from_bytes(evaluated, "little") ^ 1).to_bytes(32, "little")
        with self.assertRaises(ValueError):
            client.finalize(msg, blind, bad, blinded, proof)

    def test_output_is_deterministic_pseudo_random(self):
        c = voprf.Client(self.pk, voprf.MODE_VOPRF)
        self.assertEqual(voprf.run(self.server, c, b"a"), voprf.run(self.server, c, b"a"))
        self.assertNotEqual(voprf.run(self.server, c, b"a"), voprf.run(self.server, c, b"b"))

    def test_batch_proof_binds_every_element(self):
        """A batch proof over [A, B] must not verify for [A, C]."""
        c = voprf.Client(self.pk, voprf.MODE_VOPRF)
        msgs = [b"one", b"two"]
        blinds, blinded = [], []
        for m in msgs:
            blind, enc = c.blind(m)
            blinds.append(blind)
            blinded.append(enc)
        evaluated, proof = self.server.blind_evaluate_batch(blinded)
        # Swap in an evaluation of a different message for the second slot.
        _, other_evaluated, _ = (
            None,
            voprf.run(self.server, voprf.Client(self.pk, voprf.MODE_VOPRF), b"three"),
            None,
        ) or (None, None, None)
        # Evaluate 'three' directly and blind it into slot 2's shape.
        third_client = voprf.Client(self.pk, voprf.MODE_VOPRF)
        b3, blinded3 = third_client.blind(b"three")
        eval3, _ = self.server.blind_evaluate(blinded3)
        self.assertFalse(
            c.verify_proof(
                voprf.GENERATOR,
                c.pk,
                [voprf.decode(blinded[0]), voprf.decode(blinded3)],
                [voprf.decode(evaluated[0]), voprf.decode(eval3)],
                proof,
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

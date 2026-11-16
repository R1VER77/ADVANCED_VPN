"""elligator.py: RFC 9380 vectors, X25519 agreement with dirty keys, uniform representatives."""

import unittest

import elligator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

# RFC 9380 J.4.2 curve25519_XMD:SHA-512_ELL2_NU_: Q = map_to_curve(u[0]), P = 8 Q (x only).
VECTORS = [
    (
        "608d892b641f0328523802a6603427c26e55e6f27e71a91a478148d45b5093cd",
        "51125222da5e763d97f3c10fcc92ea6860b9ccbbd2eb1285728f566721c1e65b",
        "1bb913f0c9daefa0b3375378ffa534bda5526c97391952a7789eb976edfe4d08",
    ),
    (
        "46f5b22494bfeaa7f232cc8d054be68561af50230234d7d1d63d1d9abeca8da5",
        "7d56d1e08cb0ccb92baf069c18c49bb5a0dcd927eff8dcf75ca921ef7f3e6eeb",
        "7c22950b7d900fa866334262fcaea47a441a578df43b894b4625c9b450f9a026",
    ),
    (
        "235fe40c443766ce7e18111c33862d66c3b33267efa50d50f9e8e5d252a40aaa",
        "3fbe66b9c9883d79e8407150e7c2a1c8680bee496c62fabe4619a72b3cabe90f",
        "31ad08a8b0deeb2a4d8b0206ca25f567ab4e042746f792f4b7973f3ae2096c52",
    ),
    (
        "001e92a544463bda9bd04ddbe3d6eed248f82de32f522669efc5ddce95f46f5b",
        "227e0bb89de700385d19ec40e857db6e6a3e634b1c32962f370d26f84ff19683",
        "027877759d155b1997d0d84683a313eb78bdb493271d935b622900459d52ceaa",
    ),
    (
        "1a68a1af9f663592291af987203393f707305c7bac9c8d63d6a729bdc553dc19",
        "3bcd651ee54d5f7b6013898aab251ee8ecc0688166fce6e9548d38472f6bd196",
        "5fd892c0958d1a75f54c3182a18d286efab784e774d1e017ba2fb252998b5dc1",
    ),
]


def x_double(x):
    """x(2Q) on Curve25519 from x(Q): (x^2 - 1)^2 / (4x (x^2 + A x + 1))."""
    p, a = elligator.P, elligator.A
    return (x * x - 1) ** 2 * elligator.inv(4 * x * (x * x + a * x + 1)) % p


def pub_bytes(u):
    return u.to_bytes(32, "little")


class ElligatorTests(unittest.TestCase):
    def test_the_map_matches_rfc_9380(self):
        for u0, qx, px in VECTORS:
            q = elligator.map_to_curve(int(u0, 16))
            self.assertEqual(q, int(qx, 16))
            self.assertEqual(x_double(x_double(x_double(q))), int(px, 16))  # P = 8 Q

    def test_edwards_base_point_scalar_multiples_match_x25519(self):
        for _ in range(4):
            sk = x25519.X25519PrivateKey.generate()
            raw = sk.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
            ours = elligator.dirty_public(raw, 0)
            theirs = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(pub_bytes(ours), theirs)

    def test_the_low_order_point_has_order_8(self):
        lo = elligator.LOW_ORDER
        self.assertTrue(elligator._is_identity(elligator._mul(8, lo)))
        self.assertFalse(elligator._is_identity(elligator._mul(4, lo)))

    def test_a_dirty_ephemeral_agrees_on_the_same_shared_secret(self):
        recipient = x25519.X25519PrivateKey.generate()
        rpub = recipient.public_key()
        for _ in range(4):
            sk, u, rep = elligator.ephemeral()
            mine = x25519.X25519PrivateKey.from_private_bytes(sk).exchange(rpub)
            u_back = elligator.from_representative(rep)
            self.assertEqual(u_back, u)
            theirs = recipient.exchange(x25519.X25519PublicKey.from_public_bytes(pub_bytes(u_back)))
            self.assertEqual(mine, theirs)

    def test_representatives_look_uniform(self):
        reps = [elligator.ephemeral()[2] for _ in range(200)]
        top = sum(r[31] >> 7 for r in reps)
        self.assertTrue(60 < top < 140, top)  # the top bit is not stuck
        bits = sum(bin(b).count("1") for r in reps for b in r) / (200 * 256)
        self.assertAlmostEqual(bits, 0.5, delta=0.02)
        # The distinguisher dirty keys defeat: for a clean key, l * (decoded point) is
        # always the identity; for a dirty one, only when t = 0 (1 in 8).
        clean = 0
        for r in reps:
            u = elligator.from_representative(r)
            pt = elligator._from_y((u - 1) * elligator.inv(u + 1) % elligator.P)
            clean += elligator._is_identity(elligator._mul(elligator.L_ORDER, pt))
        self.assertTrue(10 < clean < 45, clean)  # about 200 / 8 = 25
        # About half of the curve's points have a representative.
        has = sum(
            elligator.representative(elligator.dirty_public(bytes([i]) * 32, i % 8)) is not None for i in range(200)
        )
        self.assertTrue(60 < has < 140, has)


if __name__ == "__main__":
    unittest.main()

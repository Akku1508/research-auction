"""Pedersen commitment: C_i = g^b_i * h^r_i (EC additive form C = bG + rH)."""

from .common import curve, random_scalar


class PedersenCommitment:
    def __init__(self):
        self.g = curve.G
        self.h = curve.scalar_mult(1337, self.g)

    def commit(self, bid_value: int, randomness: int = None):
        r_i = randomness if randomness is not None else random_scalar()
        c1 = curve.scalar_mult(bid_value, self.g)
        c2 = curve.scalar_mult(r_i, self.h)
        c_i = curve.point_add(c1, c2)
        return c_i, r_i

    def verify_opening(self, commitment, bid_value: int, randomness: int):
        expected, _ = self.commit(bid_value, randomness)
        return curve.points_equal(commitment, expected)

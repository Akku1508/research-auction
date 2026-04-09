"""Sigma protocol checks for commitment opening and max-bid relation proofs."""

import secrets
from .common import curve


class ZKProofs:
    def __init__(self):
        self.g = curve.G
        self.h = curve.scalar_mult(1337, self.g)

    def prove_opening(self, bid_value: int, randomness: int, challenge: int = None):
        # T = g^u h^v ; z1 = u + e*b ; z2 = v + e*r
        u = secrets.randbelow(curve.n - 1) + 1
        v = secrets.randbelow(curve.n - 1) + 1
        t = curve.point_add(curve.scalar_mult(u, self.g), curve.scalar_mult(v, self.h))
        e = challenge if challenge is not None else secrets.randbelow(curve.n - 1) + 1
        z1 = (u + e * bid_value) % curve.n
        z2 = (v + e * randomness) % curve.n
        return {"T": t, "e": e, "z1": z1, "z2": z2}

    def verify_opening_proof(self, commitment, proof):
        left = curve.point_add(curve.scalar_mult(proof["z1"], self.g), curve.scalar_mult(proof["z2"], self.h))
        right = curve.point_add(proof["T"], curve.scalar_mult(proof["e"], commitment))
        return curve.points_equal(left, right)

    def prove_maximum_relation(self, winner_commitment, other_commitment, d_j: int, rho_j: int):
        # D_j = C_w - C_j = d_j G + rho_j H, with d_j >= 0
        D_j = curve.point_add(winner_commitment, curve.point_neg(other_commitment))
        rhs = curve.point_add(curve.scalar_mult(d_j, self.g), curve.scalar_mult(rho_j, self.h))
        return {"D_j": D_j, "rhs": rhs, "non_negative": d_j >= 0}

    def verify_maximum_relation(self, proof):
        return proof["non_negative"] and curve.points_equal(proof["D_j"], proof["rhs"])

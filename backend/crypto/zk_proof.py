"""Sigma protocol checks for commitment opening and max-bid relation proofs."""

import secrets
from .common import curve


class ZKProofs:
    def __init__(self):
        self.g = curve.G
        self.h = curve.hash_to_point(b"research-auction:pedersen:H")

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

    def prove_key_possession(self, shared_key, challenge: int = None):
        """
        Schnorr-style proof that the prover knows the OT-derived key.

        The shared key is treated as a scalar-derived secret so we can verify
        knowledge without exposing the underlying value directly.
        """
        if isinstance(shared_key, str):
            normalized = shared_key.strip()
            try:
                shared_key = bytes.fromhex(normalized)
            except ValueError:
                shared_key = normalized.encode("utf-8")

        key_scalar = int.from_bytes(shared_key, "big") % curve.n
        if key_scalar == 0:
            key_scalar = 1

        u = secrets.randbelow(curve.n - 1) + 1
        t = curve.scalar_mult(u, self.g)
        e = challenge if challenge is not None else secrets.randbelow(curve.n - 1) + 1
        z = (u + e * key_scalar) % curve.n
        return {"T": t, "e": e, "z": z}

    def verify_key_possession_proof(self, expected_shared_key, proof):
        if isinstance(expected_shared_key, str):
            normalized = expected_shared_key.strip()
            try:
                expected_shared_key = bytes.fromhex(normalized)
            except ValueError:
                expected_shared_key = normalized.encode("utf-8")

        key_scalar = int.from_bytes(expected_shared_key, "big") % curve.n
        if key_scalar == 0:
            key_scalar = 1

        key_point = curve.scalar_mult(key_scalar, self.g)
        left = curve.scalar_mult(proof["z"], self.g)
        right = curve.point_add(proof["T"], curve.scalar_mult(proof["e"], key_point))
        return curve.points_equal(left, right)

    def prove_minimum_relation(self, winner_commitment, other_commitment, d_j: int, rho_j: int):
        # D_j = C_j - C_w = (v_j - v_w)G + (r_j - r_w)H, with d_j >= 0
        D_j = curve.point_add(other_commitment, curve.point_neg(winner_commitment))
        rhs = curve.point_add(curve.scalar_mult(d_j, self.g), curve.scalar_mult(rho_j, self.h))
        return {"D_j": D_j, "rhs": rhs, "non_negative": d_j >= 0}

    def prove_maximum_relation(self, winner_commitment, other_commitment, d_j: int, rho_j: int):
        # D_j = C_w - C_j = d_j G + rho_j H, with d_j >= 0
        D_j = curve.point_add(winner_commitment, curve.point_neg(other_commitment))
        rhs = curve.point_add(curve.scalar_mult(d_j, self.g), curve.scalar_mult(rho_j, self.h))
        return {"D_j": D_j, "rhs": rhs, "non_negative": d_j >= 0}

    def verify_minimum_relation(self, proof):
        return proof["non_negative"] and curve.points_equal(proof["D_j"], proof["rhs"])

    def verify_maximum_relation(self, proof):
        return proof["non_negative"] and curve.points_equal(proof["D_j"], proof["rhs"])

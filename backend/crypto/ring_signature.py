"""LSAG-style ring signature with key image linkability for bidder anonymity."""

import secrets
from .common import curve, point_to_bytes


class RingSignature:
    def __init__(self):
        self.G = curve.G

    def generate_keypair(self):
        sk = secrets.randbelow(curve.n - 1) + 1
        pk = curve.scalar_mult(sk, self.G)
        return sk, pk

    def H_p(self, p):
        return curve.scalar_mult(curve.hash_to_scalar(point_to_bytes(p)), self.G)

    def generate_key_image(self, sk, pk):
        return curve.scalar_mult(sk, self.H_p(pk))

    def _hash_challenge(self, msg: bytes, L, R):
        payload = msg + point_to_bytes(L) + point_to_bytes(R)
        return curve.hash_to_scalar(payload)

    def sign(self, message: bytes, signer_sk: int, signer_pk, ring, key_image):
        n = len(ring)
        j = ring.index(signer_pk)
        q = curve.n

        alpha = secrets.randbelow(q - 1) + 1
        s = [0] * n
        c = [0] * (n + 1)
        L = [None] * n
        R = [None] * n

        L[j] = curve.scalar_mult(alpha, self.G)
        R[j] = curve.scalar_mult(alpha, self.H_p(ring[j]))
        c[(j + 1) % n] = self._hash_challenge(message, L[j], R[j])

        i = (j + 1) % n
        while i != j:
            s[i] = secrets.randbelow(q - 1) + 1
            sG = curve.scalar_mult(s[i], self.G)
            cP = curve.scalar_mult(c[i], ring[i])
            L[i] = curve.point_add(sG, cP)

            sH = curve.scalar_mult(s[i], self.H_p(ring[i]))
            cI = curve.scalar_mult(c[i], key_image)
            R[i] = curve.point_add(sH, cI)

            c[(i + 1) % n] = self._hash_challenge(message, L[i], R[i])
            i = (i + 1) % n

        s[j] = (alpha - c[j] * signer_sk) % q

        return {
            "key_image": key_image,
            "c1": c[0],
            "s_values": s,
            "ring": ring,
            "message": message,
        }

    def verify(self, signature):
        ring = signature["ring"]
        n = len(ring)
        c = [signature["c1"]]
        s = signature["s_values"]
        I = signature["key_image"]
        msg = signature["message"]

        for i in range(n):
            sG = curve.scalar_mult(s[i], self.G)
            cP = curve.scalar_mult(c[i], ring[i])
            L = curve.point_add(sG, cP)

            sH = curve.scalar_mult(s[i], self.H_p(ring[i]))
            cI = curve.scalar_mult(c[i], I)
            R = curve.point_add(sH, cI)
            c.append(self._hash_challenge(msg, L, R))

        return c[n] == signature["c1"]

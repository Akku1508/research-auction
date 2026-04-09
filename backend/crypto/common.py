import hashlib
import secrets


class EllipticCurve:
    """secp256k1 arithmetic used by all primitives."""

    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.a = 0
        self.b = 7
        self.G = (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        )

    def mod_inverse(self, a, m):
        def egcd(x, y):
            if x == 0:
                return y, 0, 1
            g, x1, y1 = egcd(y % x, x)
            return g, y1 - (y // x) * x1, x1

        g, x, _ = egcd(a % m, m)
        if g != 1:
            raise ValueError("No modular inverse")
        return (x % m + m) % m

    def point_add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2:
            if y1 != y2:
                return None
            lmb = (3 * x1 * x1 + self.a) * self.mod_inverse(2 * y1, self.p) % self.p
        else:
            lmb = (y2 - y1) * self.mod_inverse(x2 - x1, self.p) % self.p

        x3 = (lmb * lmb - x1 - x2) % self.p
        y3 = (lmb * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_neg(self, p):
        if p is None:
            return None
        x, y = p
        return (x, (-y) % self.p)

    def scalar_mult(self, k, p):
        if p is None or k % self.n == 0:
            return None
        if k < 0:
            return self.scalar_mult(-k, self.point_neg(p))

        out = None
        addend = p
        while k:
            if k & 1:
                out = self.point_add(out, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return out

    def hash_to_scalar(self, data: bytes):
        return int.from_bytes(hashlib.sha256(data).digest(), "big") % self.n

    def points_equal(self, p1, p2):
        if p1 is None or p2 is None:
            return p1 is None and p2 is None
        return p1[0] == p2[0] and p1[1] == p2[1]


curve = EllipticCurve()


def random_scalar():
    return secrets.randbelow(curve.n - 1) + 1


def point_to_bytes(p):
    if p is None:
        return b"\x00"
    return p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")


def point_to_json(p):
    if p is None:
        return None
    return {"x": str(p[0]), "y": str(p[1])}


def point_from_json(d):
    if not d:
        return None
    return (int(d["x"]), int(d["y"]))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([a[i] ^ b[i % len(b)] for i in range(len(a))])

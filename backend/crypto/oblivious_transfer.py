"""Naor-Pinkas OT + tree extension for index-private retrieval."""

import hashlib
import math
import secrets
from .common import curve, point_to_bytes, xor_bytes


class NaorPinkasOT:
    def __init__(self):
        self.G = curve.G

    def sender_prepare_A(self):
        a = secrets.randbelow(curve.n - 1) + 1
        A = curve.scalar_mult(a, self.G)
        return a, A

    def receiver_compute_B(self, A, choice_bit):
        b = secrets.randbelow(curve.n - 1) + 1
        Gb = curve.scalar_mult(b, self.G)
        B = Gb if choice_bit == 0 else curve.point_add(A, Gb)
        return b, B

    def sender_mask(self, a, A, B, m0: bytes, m1: bytes):
        k0_point = curve.scalar_mult(a, B)
        B_minus_A = curve.point_add(B, curve.point_neg(A))
        k1_point = curve.scalar_mult(a, B_minus_A)
        k0 = hashlib.sha256(point_to_bytes(k0_point)).digest()
        k1 = hashlib.sha256(point_to_bytes(k1_point)).digest()
        e0 = xor_bytes(m0, hashlib.sha256(k0 + b"0").digest()[: len(m0)])
        e1 = xor_bytes(m1, hashlib.sha256(k1 + b"1").digest()[: len(m1)])
        return e0, e1

    def receiver_recover(self, b, A, e0, e1, choice_bit):
        kc_point = curve.scalar_mult(b, A)
        kc = hashlib.sha256(point_to_bytes(kc_point)).digest()
        if choice_bit == 0:
            return xor_bytes(e0, hashlib.sha256(kc + b"0").digest()[: len(e0)])
        return xor_bytes(e1, hashlib.sha256(kc + b"1").digest()[: len(e1)])


class NaorPinkasTreeOT:
    def __init__(self):
        self.base = NaorPinkasOT()

    def _prg(self, seed: bytes, bit: int):
        return hashlib.sha256(seed + bytes([bit])).digest()

    def sender_prepare_tree(self, messages):
        n0 = len(messages)
        k = math.ceil(math.log2(max(1, n0)))
        n_leaves = 2**k
        msgs = list(messages) + [b""] * (n_leaves - len(messages))

        seeds = [None] * (2 ** (k + 1))
        seeds[1] = secrets.token_bytes(32)
        for i in range(1, 2**k):
            seeds[2 * i] = self._prg(seeds[i], 0)
            seeds[2 * i + 1] = self._prg(seeds[i], 1)

        ciphertexts = []
        for leaf in range(2**k, 2 ** (k + 1)):
            path = []
            idx = leaf
            while idx >= 1:
                path.append(seeds[idx])
                idx //= 2
            L_j = hashlib.sha256(b"".join(reversed(path))).digest()
            m_j = msgs[leaf - 2**k]
            if not m_j:
                ciphertexts.append(b"")
            else:
                ks = hashlib.sha256(L_j).digest()
                ciphertexts.append(xor_bytes(m_j, ks[: len(m_j)]))

        level_pairs = []
        for level in range(1, k + 1):
            left = 2**level
            right = left + 1
            level_pairs.append((hashlib.sha256(seeds[left]).digest(), hashlib.sha256(seeds[right]).digest()))

        return {"original_n": n0, "n": n_leaves, "k": k, "ciphertexts": ciphertexts, "level_pairs": level_pairs}

    def receiver_obtain_leaf(self, sender_state, choice_index):
        k = sender_state["k"]
        bits = [(choice_index >> (k - 1 - i)) & 1 for i in range(k)]

        obtained = []
        for i in range(k):
            K0, K1 = sender_state["level_pairs"][i]
            a, A = self.base.sender_prepare_A()
            b, B = self.base.receiver_compute_B(A, bits[i])
            e0, e1 = self.base.sender_mask(a, A, B, K0, K1)
            obtained.append(self.base.receiver_recover(b, A, e0, e1, bits[i]))

        L_choice = hashlib.sha256(b"".join(obtained)).digest()
        c = sender_state["ciphertexts"][choice_index]
        ks = hashlib.sha256(L_choice).digest()
        return xor_bytes(c, ks[: len(c)])

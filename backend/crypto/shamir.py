"""Shamir Secret Sharing over large prime field for distributed auctioneer trust."""

import secrets

PRIME = 2**521 - 1


def _eval_poly(coeffs, x):
    acc = 0
    power = 1
    for c in coeffs:
        acc = (acc + c * power) % PRIME
        power = (power * x) % PRIME
    return acc


def split_secret(secret: int, threshold: int, total: int):
    if threshold > total:
        raise ValueError("threshold cannot exceed total")
    coeffs = [secret] + [secrets.randbelow(PRIME - 1) + 1 for _ in range(threshold - 1)]
    shares = []
    for x in range(1, total + 1):
        shares.append((x, _eval_poly(coeffs, x)))
    return shares


def reconstruct_secret(shares):
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm)) % PRIME
            den = (den * (xj - xm)) % PRIME
        lagrange = num * pow(den, -1, PRIME)
        secret = (PRIME + secret + yj * lagrange) % PRIME
    return secret

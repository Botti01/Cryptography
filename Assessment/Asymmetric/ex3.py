#!/usr/bin/env python3
from gmpy2 import isqrt, is_square
import sys

def fermat_factor(N, max_iters=None):
    """
    Attempt to factor N by Fermat's method:
    Find integers a, b such that N = a^2 - b^2 = (a-b)(a+b).
    """
    # Start at ceil(sqrt(N))
    a = isqrt(N)
    if a * a < N:
        a += 1

    iters = 0
    while True:
        if max_iters is not None and iters >= max_iters:
            raise RuntimeError(f"Stopped after {max_iters} iterations, no factor found.")
        
        b2 = a*a - N
        if b2 >= 0 and is_square(b2):
            b = isqrt(b2)
            # We have N = (a-b)*(a+b)
            p = a + b
            q = a - b
            return int(p), int(q)
        
        a += 1
        iters += 1

if __name__ == "__main__":
    # The target modulus
    N = int(
        "206196720022768247889246680066437598178020032305393119870540720920425094195"
        "833612984479548742345361302932645219639094867676869215417348824384613993692"
        "025679425131499811231629090893491386383721295645809244600935874119405837136"
        "9097581541094913"
    )

    try:
        p, q = fermat_factor(N, max_iters=10_000_000)
        print("Success!")
        print("p =", p)
        print("q =", q)
        print("Check:", p*q == N)
    except Exception as e:
        print("Fermat failed:", e)
        sys.exit(1)

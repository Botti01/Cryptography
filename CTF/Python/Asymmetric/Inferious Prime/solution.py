"""

Here is my super-strong RSA implementation, because it's 1600 bits strong it should be unbreakable... at least I think so!

"""

# ─── Attack ─────────────────────────────────────────────────────────────────────
# RSA modulus factorization via FactorDB 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Submit the public modulus `n` to FactorDB to retrieve its prime factors p and q.
#   2. Compute φ(n) = (p − 1)(q − 1).
#   3. Compute the private exponent d = e⁻¹ mod φ(n).
#   4. Decrypt the ciphertext: m = cᵈ mod n.
#   5. Convert the integer m back to bytes to recover the flag.

from Crypto.Util.number import inverse, long_to_bytes               # RSA utilities
from factordb.factordb import FactorDB                             # online factorization client

# ─── Public parameters and ciphertext ──────────────────────────────────────────
n = 770071954467068028952709005868206184906970777429465364126693  # RSA modulus
e = 3                                                              # small public exponent
ct = 388435672474892257936058543724812684332943095105091384265939  # ciphertext

# ─── Step 1: Factor n via FactorDB ─────────────────────────────────────────────
f = FactorDB(n)
f.connect()  # submit n and fetch factorization

# ─── Step 2: Retrieve prime factors p and q ────────────────────────────────────
factors = f.get_factor_list()
if len(factors) != 2:
    raise ValueError(f"Expected exactly two prime factors, got: {factors}")
p, q = factors
print(f"[*] Retrieved factors:\n    p = {p}\n    q = {q}")

# ─── Step 3: Compute φ(n) and private exponent d ───────────────────────────────
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
print(f"[*] Computed φ(n) = {phi}")
print(f"[*] Computed private exponent d = {d}")

# ─── Step 4: Decrypt ciphertext m = ct^d mod n ────────────────────────────────
m = pow(ct, d, n)
flag = long_to_bytes(m)  # convert integer plaintext to bytes
print(f"Flag: {flag.decode()}")



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{fh98df62nx1mc}

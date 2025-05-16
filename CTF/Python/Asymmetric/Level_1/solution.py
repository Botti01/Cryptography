"""

The attached file contains the code and the output. Use them to get the flag...

"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# Factorization of RSA modulus (Pollard’s Rho)

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Retrieve prime factors of n from FactorDB.
#   2. Compute the Euler's totient φ(n) = (p − 1)(q − 1).
#   3. Compute the private exponent d = e⁻¹ mod φ(n).
#   4. Decrypt the ciphertext using m = cᵈ mod n.
#   5. Convert the decrypted message (as a number) back to bytes and print it.

from Crypto.Util.number import inverse, long_to_bytes  # cryptographic utilities
from factordb.factordb import FactorDB                # online factorization database client

# ─── Public Key Parameters and Ciphertext ────────────────────────────────────────
n = 176278749487742942508568320862050211633  # RSA modulus (product of two primes)
e = 65537                                     # RSA public exponent (common choice)
c = 46228309104141229075992607107041922411   # Ciphertext (integer format)

# ─── Step 1: Factor n via FactorDB ───────────────────────────────────────────────
f = FactorDB(n)
f.connect()                                   # Submit `n` and retrieve factor info

# ─── Step 2: Retrieve factors p and q ────────────────────────────────────────────
factors = f.get_factor_list()
if len(factors) != 2:
    raise ValueError(f"Expected exactly two prime factors, got: {factors}")
p, q = factors
print(f"[*] Retrieved factors:\n    p = {p}\n    q = {q}")

# ─── Step 3: Compute φ(n) = (p − 1)(q − 1) ───────────────────────────────────────
phi = (p - 1) * (q - 1)
print(f"[*] Computed φ(n) = {phi}")

# ─── Step 4: Compute private key d = e⁻¹ mod φ(n) ───────────────────────────────
d = inverse(e, phi)
print(f"[*] Computed private exponent d = {d}")

# ─── Step 5: Decrypt ciphertext using RSA: m = c^d mod n ────────────────────────
m = pow(c, d, n)
flag = long_to_bytes(m)  # convert integer to bytes
print(f"[*] Decrypted flag: {flag.decode()}")



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{X5a.7}

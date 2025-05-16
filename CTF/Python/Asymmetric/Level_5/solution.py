"""

You have the code, access the server and get the flag!

nc 130.192.5.212 6645

"""

# ─── Attack ─────────────────────────────────────────────────────────────────────
# RSA multiplicative blinding with decryption oracle (CCA-style) 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the server and read the RSA modulus `n` and ciphertext `c`.
#   2. Choose a random blinding factor `r` ∈ [2, n−1].
#   3. Compute blinded ciphertext c' = c · rᵉ mod n.
#   4. Send “d<c'>” to the oracle, which returns Dec(c') = m·r mod n.
#   5. Unblind by computing m = (m·r) · r⁻¹ mod n.
#   6. Convert `m` to bytes to recover the flag.

from Crypto.Util.number import long_to_bytes, inverse  # RSA utilities
from pwn import remote                                # for remote connection
import random                                         # to pick random r

# ─── Step 1: Connect and read public parameters ────────────────────────────────
host, port = "130.192.5.212", 6645
conn = remote(host, port)

# Read modulus n (decimal) and ciphertext c (decimal)
n = int(conn.recvline().decode().strip())
c = int(conn.recvline().decode().strip())
e = 65537  # public exponent

# ─── Step 2: Choose random blinding factor ──────────────────────────────────────
# Pick r ≠ 1 so that c' ≠ c and the oracle accepts it.
r = random.randrange(2, n - 1)

# ─── Step 3: Compute blinded ciphertext c' = c · rᵉ mod n ──────────────────────
r_e = pow(r, e, n)
c_prime = (c * r_e) % n

# ─── Step 4: Ask the oracle to decrypt c' ──────────────────────────────────────
# Oracle expects input prefixed with 'd'
conn.sendline(f"d{c_prime}")
# It returns Dec(c') = m·r mod n
m_r = int(conn.recvline().decode().strip())

# ─── Step 5: Unblind to recover m ──────────────────────────────────────────────
r_inv = inverse(r, n)           # compute r⁻¹ mod n
m = (m_r * r_inv) % n           # m = (m·r)·r⁻¹

# ─── Step 6: Convert m to bytes and print flag ─────────────────────────────────
flag = long_to_bytes(m)
print("\n" + flag.decode())

# ─── Clean up ──────────────────────────────────────────────────────────────────
conn.close()



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{af37efa5-de5b-4de2-adcd-43324caca805}
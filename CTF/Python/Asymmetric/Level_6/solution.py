"""

access the server and get the flag

nc 130.192.5.212 6646

"""

# ─── Attack ──────────────────────────────────────────────────────────────────────
# RSA multiplicative blinding (simplified CCA-style)

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the server and read the flag ciphertext `c`.
#   2. Choose a small blinding factor `r` (e.g., 2).
#   3. Ask the server to encrypt `r` to obtain `rᵉ mod n`.
#   4. Forge `c' = c · rᵉ` and ask the server to decrypt it, yielding `m·r`.
#   5. Recover `m = (m·r) // r` (since m·r < n, integer division is exact).
#   6. Convert `m` to bytes to reveal the flag.

from pwn import remote
from Crypto.Util.number import long_to_bytes

# ─── Step 1: Connect and retrieve encrypted flag ───────────────────────────────
conn = remote('130.192.5.212', 6646)
c = int(conn.recvline().strip())   # ciphertext of the flag

# ─── Step 2: Choose blinding factor ──────────────────────────────────────────────
r = 2  # small random factor (must satisfy r ≠ 1 and m·r < n)

# ─── Step 3: Obtain rᵉ from the server ──────────────────────────────────────────
# Prefix with 'e' to indicate encryption request
conn.sendline(f"e{r}")
r_e = int(conn.recvline().strip())  # r^e mod n

# ─── Step 4: Forge blinded ciphertext and decrypt ──────────────────────────────
c_prime = c * r_e                   # blinded ciphertext = c·rᵉ
conn.sendline(f"d{c_prime}")       # prefix 'd' to request decryption
m_times_r = int(conn.recvline().strip())  # decrypted result = m·r

# ─── Step 5: Unblind to recover m ──────────────────────────────────────────────
# Since m·r < n, integer division yields exact m
m = m_times_r // r

# ─── Step 6: Convert to bytes and print flag ───────────────────────────────────
flag = long_to_bytes(m)
print("FLAG:", flag.decode())



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{4701ecda-eaf6-4a7a-9e43-29cdf914e9ff}

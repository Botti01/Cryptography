"""

nc 130.192.5.212 6647

"""

# ─── Attack ──────────────────────────────────────────────────────────────────────
# RSA Least Significant Bit Oracle (Bleichenbacher’s attack variant) 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the server and read the RSA modulus `n` and ciphertext `c`.
#   2. Precompute factor = 2ᵉ mod n to iteratively shift plaintext bits.
#   3. Maintain a rational interval [low, high] that bounds m.
#   4. For each bit position i:
#        a) Blind ciphertext: c ← c · (2ᵉ) mod n → corresponds to shifting plaintext by 2.
#        b) Query the oracle for the LSB (parity) of Dec(c).
#        c) Refine interval: if bit=0 → high=mid, else low=mid.
#   5. After n.bit_length() iterations, low≈high≈m.
#   6. Convert m to bytes to recover the flag.

from pwn import remote                     # for remote TCP interaction
from fractions import Fraction             # exact rational arithmetic
from Crypto.Util.number import long_to_bytes  # to convert integer → bytes

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = '130.192.5.212'
PORT = 6647
e = 65537  # public exponent

def get_parity(conn, c_val):

    # Send the decimal ciphertext to the oracle and return its LSB (0 or 1).
    # The server replies with the parity of the decrypted plaintext.

    conn.sendline(str(c_val).encode())
    return int(conn.recvline().strip())

def main():
    # ── Step 1: Connect and receive parameters ───────────────────────────────────
    conn = remote(HOST, PORT)
    n = int(conn.recvline().strip())
    c = int(conn.recvline().strip())

    # ── Step 2: Precompute multiplication factor for shifting plaintext ────────
    # Multiplying ciphertext by (2ᵉ mod n) causes plaintext to be multiplied by 2.
    two_e = pow(2, e, n)

    # ── Step 3: Initialize search interval for m: [0, n] ───────────────────────
    low = Fraction(0)
    high = Fraction(n)

    # ── Step 4: Iteratively recover each bit of m ──────────────────────────────
    bit_len = n.bit_length()
    for i in range(bit_len):
        # a) Blind ciphertext to shift plaintext left by one bit
        c = (c * two_e) % n

        # b) Query LSB of decrypted value
        bit = get_parity(conn, c)

        # c) Refine interval [low, high] based on bit
        mid = (low + high) / 2
        if bit == 0:
            # if shifted plaintext < n/2 → original bit was 0
            high = mid
        else:
            # if shifted plaintext ≥ n/2 → original bit was 1
            low = mid

        # Optional progress indicator
        print(f"Recovered bit {i+1}/{bit_len}: {bit}", end='\r')

    # ── Step 5: Conclude m ≈ high ≈ low after all bits ─────────────────────────
    m = int(high)

    # ── Step 6: Convert to bytes and print the flag ────────────────────────────
    flag = long_to_bytes(m)
    print("\n" + flag.decode())

    conn.close()

if __name__ == '__main__':
    main()
    
    

# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{b4b6d1f1-929c-4a41-9900-51091ea9b258}

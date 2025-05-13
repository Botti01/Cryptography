"""
    
you have the code, guess the flag

nc 130.192.5.212 6541
    
"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# Adaptive Chosen Plaintext Attack 

import string
from pwn import remote  

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"   
PORT = 6541              
BLOCK_SIZE = 16          # AES block size in bytes (for ECB oracle alignment)

def main():

    # Connects persistently to the AES-ECB encryption oracle,
    # then recovers the flag byte-by-byte by exploiting the
    # deterministic block cipher property in ECB mode.

    # ── Step 1: Open persistent connection ─────────────────────────────────────────
    # Keeping the same AES key across queries allows us to compare ciphertext blocks.
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")  # synchronize to the initial menu prompt

    # ── Precompute expected flag length ────────────────────────────────────────────
    # Known from challenge: flag = 10-byte prefix + 36-byte UUID = 46 bytes total.
    FLAG_LEN = 10 + 36
    recovered = b""       # buffer to accumulate recovered flag bytes

    # ── Define candidate characters ────────────────────────────────────────────────
    # Try letters, digits, and punctuation—typical CTF flag charset.
    charset = (string.ascii_letters + string.digits + string.punctuation).encode()

    # ── Step 2: Byte-at-a-time ECB decryption ──────────────────────────────────────
    for i in range(FLAG_LEN):
        # Calculate how many “A” bytes to prepend so that the unknown byte
        # lands at the end of a block. This aligns our target byte.
        prefix_len = (BLOCK_SIZE - ((i + 1) % BLOCK_SIZE)) % BLOCK_SIZE
        prefix = b"A" * prefix_len

        # --- A) Obtain the real ciphertext block for the unknown byte ---
        io.sendline(b"enc")           # select encryption from the menu
        io.recvuntil(b"> ")
        io.sendline(prefix.hex().encode())
        ct_hex = io.recvline().strip()  # full ciphertext in hex
        full_ct = bytes.fromhex(ct_hex.decode())
        io.recvuntil(b"> ")            # wait for menu again

        # Identify which block contains our target byte
        block_index = (prefix_len + i) // BLOCK_SIZE
        target_block = full_ct[block_index*BLOCK_SIZE : (block_index+1)*BLOCK_SIZE]

        # --- B) Build dictionary of guesses for the last byte in that block ---
        found = False
        for c in charset:
            # Construct guess: prefix + all recovered bytes + candidate byte
            guess = prefix + recovered + bytes([c])

            # Send the guess to encryption oracle
            io.sendline(b"enc")
            io.recvuntil(b"> ")
            io.sendline(guess.hex().encode())
            ct2 = bytes.fromhex(io.recvline().strip().decode())
            io.recvuntil(b"> ")

            # Extract the corresponding block from this ciphertext
            candidate_block = ct2[block_index*BLOCK_SIZE : (block_index+1)*BLOCK_SIZE]

            # If blocks match, we've found the correct byte
            if candidate_block == target_block:
                recovered += bytes([c])
                print(f"[+] Recovered byte {i+1}/{FLAG_LEN}: {bytes([c]).decode()!r}")
                found = True
                break

        if not found:
            # If no candidate matched, exit early to avoid infinite loop
            print(f"[-] Failed to recover byte #{i+1}")
            break

    # ── Step 3: Clean up and output ────────────────────────────────────────────────
    io.close()  # close the persistent connection
    print("\n[***] Flag:", recovered.decode(errors="ignore"))


if __name__ == "__main__":
    main()



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{96ce8a93-d548-4f88-bc6c-db6eb3c96382}

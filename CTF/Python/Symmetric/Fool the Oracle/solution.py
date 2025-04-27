"""
    
you have the code, guess the flag

nc 130.192.5.212 6541
    
"""

import string
from pwn import remote

HOST = "130.192.5.212"
PORT = 6541
# Block size for the cipher (likely AES)
BLOCK_SIZE = 16

def main():
    # 1) Open one persistent connection so that the same AES key survives all our queries.
    io = remote(HOST, PORT)
    # The server immediately prints the menu, ending with "> ".
    io.recvuntil(b"> ")

    # We know from the challenge that the flag length is 10 + 36 = 46 bytes.
    FLAG_LEN = 10 + 36

    recovered = b""  # will hold the bytes of the flag as we discover them

    # We'll only try ASCII letters, digits and punctuation as possible flag characters.
    charset = (string.ascii_letters + string.digits + string.punctuation).encode()

    # 2) Recover the flag one byte at a time:
    for i in range(FLAG_LEN):
        # How many “A”s to prepend so that the (i)th unknown flag byte
        # lands as the very last byte of some ECB block?
        prefix_len = (BLOCK_SIZE - ( (i + 1) % BLOCK_SIZE )) % BLOCK_SIZE
        prefix = b"A" * prefix_len

        # --- Step A: Get the real ciphertext block containing the unknown byte ---
        # Menu → "enc"
        io.sendline(b"enc")
        io.recvuntil(b"> ")

        # Oracle: data = bytes.fromhex(input), so send hex(prefix)
        io.sendline(prefix.hex().encode())

        # Read back the full ciphertext (hex) and convert to bytes
        ct_hex = io.recvline().strip()
        full_ct = bytes.fromhex(ct_hex.decode())

        # After printing ciphertext, oracle re‐prints the menu.  Sync up.
        io.recvuntil(b"> ")

        # Which block index holds our target byte?
        block_index = (prefix_len + i) // BLOCK_SIZE
        # Extract that 16‐byte block
        target_block = full_ct[block_index*BLOCK_SIZE : (block_index+1)*BLOCK_SIZE]

        # --- Step B: Build a dictionary of (last‐byte ⇒ ciphertext‐block) mappings ---
        found_byte = None
        for c in charset:
            guess = prefix + recovered + bytes([c])
            # Send enc + hex(guess)
            io.sendline(b"enc")
            io.recvuntil(b"> ")
            io.sendline(guess.hex().encode())

            # Read and parse the ciphertext
            ct2 = bytes.fromhex(io.recvline().strip().decode())
            io.recvuntil(b"> ")

            # Since len(guess) = prefix_len + (i+1) ≡ 0 mod BLOCK_SIZE,
            # the very last byte of guess sits at the end of block_index.
            candidate_block = ct2[block_index*BLOCK_SIZE : (block_index+1)*BLOCK_SIZE]

            if candidate_block == target_block:
                # Bingo!
                recovered += bytes([c])
                print(f"[+] Recovered byte {i+1}/{FLAG_LEN}: {bytes([c]).decode()!r}")
                found_byte = c
                break

        if found_byte is None:
            print(f"[-] Failed to recover byte #{i}")
            break

    io.close()

    print("\n[***] Flag:", recovered.decode())

if __name__ == "__main__":
    main()



# FLAG: CRYPTO25{96ce8a93-d548-4f88-bc6c-db6eb3c96382}
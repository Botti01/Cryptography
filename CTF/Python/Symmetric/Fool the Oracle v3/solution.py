"""

...even more complex now...

nc 130.192.5.212 6543

"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# Adaptive Chosen Plaintext Attack

import sys
from pwn import remote 

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"  # remote host for the encryption oracle
PORT = 6543             # remote port for the encryption oracle
BLOCK_SIZE = 16         # AES block size in bytes (ECB mode)
FLAG_LEN = 46           # length of the flag: len("CRYPTO25{}") + 36

# ─── Utility: Send payload and receive ciphertext ───────────────────────────────
def get_ciphertext(io, payload_hex: str) -> bytes:

    # Send the "enc" command with hex-encoded payload and return
    # the raw ciphertext bytes. We drive the menu once per call.

    io.recvuntil(b"> ")           # wait for menu prompt
    io.sendline(b"enc")           # select encryption option
    io.recvuntil(b"> ")           # wait for payload prompt
    io.sendline(payload_hex.encode())
    ct_hex = io.recvline().strip().decode()  # e.g. "5f3a..."
    return bytes.fromhex(ct_hex)  # convert hex string to raw bytes

# ─── Utility: Detect random-prefix alignment ────────────────────────────────────
def find_prefix_alignment(io):

    # Determine how many padding 'A's are needed so that sending
    # A*(pad + 2*BLOCK_SIZE) yields two identical consecutive blocks.
    # Returns:
    #   pad_len     — number of random prefix bytes mod BLOCK_SIZE
    #   start_block — index of the first of the identical blocks

    for pad in range(BLOCK_SIZE):
        test = b"A" * (pad + 2 * BLOCK_SIZE)
        ct = get_ciphertext(io, test.hex())
        # split into BLOCK_SIZE-byte chunks
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        # look for two adjacent identical blocks
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return pad, i
    raise RuntimeError("Could not detect prefix alignment")

def main():

    # 1) Open a persistent connection (ensures a single AES key).
    # 2) Detect alignment of the unknown random prefix.
    # 3) Recover the flag by byte-at-a-time ECB decryption.

    # ── Step 1: Establish connection ──────────────────────────────────────────────
    io = remote(HOST, PORT)

    # ── Step 2: Find pad length and start block for alignment ────────────────────
    pad_len, start_block = find_prefix_alignment(io)
    print(f"[+] Alignment detected: pad_len={pad_len}, start_block={start_block}")

    recovered = b""  # buffer for discovered flag bytes

    # ── Step 3: Byte-at-a-time decryption ────────────────────────────────────────
    for idx in range(FLAG_LEN):
        # Compute how many 'A's so that the unknown byte
        # lands at the end of block (start_block + block_idx).
        block_idx = idx // BLOCK_SIZE
        in_block = idx % BLOCK_SIZE
        pad_bytes = pad_len + (BLOCK_SIZE - 1 - in_block)
        prefix = b"A" * pad_bytes

        # 3a) Get the real ciphertext block for the target byte
        ct_real = get_ciphertext(io, prefix.hex())
        target = ct_real[(start_block + block_idx)*BLOCK_SIZE :
                         (start_block + block_idx + 1)*BLOCK_SIZE]

        # 3b) Brute-force by appending each possible byte (0–255)
        found = False
        for candidate in range(256):
            guess = prefix + recovered + bytes([candidate])
            ct_guess = get_ciphertext(io, guess.hex())
            block = ct_guess[(start_block + block_idx)*BLOCK_SIZE :
                             (start_block + block_idx + 1)*BLOCK_SIZE]
            if block == target:
                recovered += bytes([candidate])
                # print progress with the discovered character
                print(f"[+] Recovered byte #{idx:02d}: {chr(candidate)!r}")
                sys.stdout.flush()
                found = True
                break

        if not found:
            # abort if no match, to avoid infinite loop
            print(f"[!] Failed at byte #{idx}")
            break

    # ── Done: print recovered flag ────────────────────────────────────────────────
    print(f"\n[+] Recovered flag: {recovered.decode(errors='ignore')}")

if __name__ == "__main__":
    main()



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{e3ab2169-39d5-43aa-bde7-02286c2e2e56}

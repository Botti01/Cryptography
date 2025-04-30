"""

...even more complex now...

nc 130.192.5.212 6543

"""

import sys
from pwn import remote

HOST = "130.192.5.212"
PORT = 6543
BLOCK_SIZE = 16
FLAG_LEN = 46  # len("CRYPTO25{}")+36

def get_ciphertext(io, payload_hex: str) -> bytes:
    """
    Drive the “enc” menu once and return the raw ciphertext bytes.
    """
    io.recvuntil(b"> ")
    io.sendline(b"enc")
    io.recvuntil(b"> ")
    io.sendline(payload_hex.encode())
    # The service replies with one line of hex, e.g. "5f3a..."
    ct_hex = io.recvline().strip().decode()
    return bytes.fromhex(ct_hex)

def find_prefix_alignment(io):
    """
    We don’t know the length of the random padding (1–15 bytes).
    Send A*(pad + 2*BLOCK_SIZE) for pad=0..15 until we see two identical
    consecutive ciphertext blocks.  That tells us:
      pad_len      = pad
      start_block  = index of the first of those two identical blocks
    """
    for pad in range(BLOCK_SIZE):
        test = b"A" * (pad + 2 * BLOCK_SIZE)
        ct = get_ciphertext(io, test.hex())
        # Split into 16-byte blocks
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        # Look for two identical blocks
        for i in range(len(blocks)-1):
            if blocks[i] == blocks[i+1]:
                return pad, i
    raise RuntimeError("Could not detect prefix alignment")

def main():
    # 1) Open one connection (single key for all calls)
    io = remote(HOST, PORT)

    # 2) Detect how many A’s we need to align user bytes to a block boundary
    pad_len, start_block = find_prefix_alignment(io)
    print(f"[+] Alignment: pad_len={pad_len}, start_block={start_block}")

    recovered = b""

    # 3) Recover FLAG_LEN bytes one at a time
    for idx in range(FLAG_LEN):
        # 3a) Compute how many A’s to send so that the next unknown
        #      flag byte lands at the end of block (start_block + block_idx)
        block_idx = idx // BLOCK_SIZE
        in_block  = idx  % BLOCK_SIZE
        # user_data = A * (pad_len + (BLOCK_SIZE - 1 - in_block))
        pad_bytes = pad_len + (BLOCK_SIZE - 1 - in_block)
        prefix = b"A" * pad_bytes

        # 3b) Query the real ciphertext to grab the target block
        ct_real = get_ciphertext(io, prefix.hex())
        target = ct_real[(start_block+block_idx)*BLOCK_SIZE:
                         (start_block+block_idx+1)*BLOCK_SIZE]

        # 3c) Brute-force by appending each possible byte
        found = False
        for candidate in range(256):
            guess = prefix + recovered + bytes([candidate])
            ct_guess = get_ciphertext(io, guess.hex())
            block = ct_guess[(start_block+block_idx)*BLOCK_SIZE:
                             (start_block+block_idx+1)*BLOCK_SIZE]
            if block == target:
                recovered += bytes([candidate])
                # **Per-byte print**
                print(f"Recovered byte #{idx:02d}: {chr(candidate)!r}")
                sys.stdout.flush()
                found = True
                break

        if not found:
            print(f"[!] Failed at byte #{idx}")
            break

    # 4) Done!
    print(f"\n[+] Recovered flag: {recovered.decode(errors='ignore')}")

if __name__ == "__main__":
    main()



# FLAG:  CRYPTO25{e3ab2169-39d5-43aa-bde7-02286c2e2e56}
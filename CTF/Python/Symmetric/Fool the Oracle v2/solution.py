"""

fool this new one...

nc 130.192.5.212 6542

"""

import string, math
from pwn import remote 

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"           
PORT = 6542    
BS = 16                          # AES block size in bytes (ECB mode)
FLAG_LEN = 10 + 36               # total flag length: len("CRYPTO25{}") + 36 = 46
KNOWN_PREFIX = b"CRYPTO25{"     # known fixed prefix of the flag
# charset for the remaining UUID4 part: uppercase, lowercase, digits, dash, and closing brace
CHARSET = (string.ascii_uppercase +
           string.ascii_lowercase +
           string.digits +
           "-}").encode()

# ─── Helper Function: split_blocks ────────────────────────────────────────────────
def split_blocks(data: bytes):
    """
    Splits raw bytes into a list of BS-byte blocks.
    This makes it easy to isolate and compare individual cipher blocks.
    """
    return [data[i:i+BS] for i in range(0, len(data), BS)]

# ─── Helper Function: make_oracle ────────────────────────────────────────────────
def make_oracle():
    """
    Opens a persistent connection and consumes the initial menu prompt.
    Returns:
      - io: the connection object (to be closed by the caller)
      - oracle(user_bytes) → ciphertext_bytes: function that
        1) sends "enc" to select encryption
        2) sends user-supplied bytes (hex-encoded)
        3) reads and returns the raw ciphertext bytes
        4) leaves the prompt ready for the next call
    """
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")  # consume the initial menu prompt

    def oracle(user_bytes: bytes) -> bytes:
        io.sendline(b"enc")                     # choose encryption
        io.recvuntil(b"> ")                    # wait for input prompt
        io.sendline(user_bytes.hex().encode())  # send hex-encoded data
        line = io.recvline().strip()           # read hex cipher output
        io.recvuntil(b"> ")                    # consume next menu prompt
        return bytes.fromhex(line.decode())     # return raw ciphertext

    return io, oracle

# ─── Helper Function: detect_alignment ───────────────────────────────────────────
def detect_alignment(oracle):
    """
    Determines how many padding 'A's are needed so that
    our input b"A"*(pad_length + 2*BS) produces two identical
    adjacent blocks.  This reveals:
      - pad_length: number of bytes in the unknown random prefix mod BS
      - prefix_blocks: index of the first of the identical blocks
    """
    for pad_length in range(BS):
        probe = b"A" * (pad_length + 2*BS)
        ct = oracle(probe)
        blocks = split_blocks(ct)
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return pad_length, i
    raise RuntimeError("Alignment detection failed")

# ─── Attack Logic: recover_flag ─────────────────────────────────────────────────
def recover_flag():
    """
    1) Detect random-prefix alignment via ECB block repetition.
    2) Pre-fill known flag prefix.
    3) Byte-by-byte brute force of the remaining FLAG_LEN - len(KNOWN_PREFIX) bytes:
       - Align each unknown byte to the end of a block.
       - Compare oracle output against a dictionary of guesses.
    """
    io, oracle = make_oracle()

    # 1) Find alignment parameters
    pad_length, prefix_blocks = detect_alignment(oracle)
    print(f"[*] pad_length = {pad_length}, prefix_blocks = {prefix_blocks}")

    # 2) Start with the known prefix in our recovered buffer
    recovered = bytearray(KNOWN_PREFIX)
    print(f"[*] Prefilled known prefix: {recovered.decode()}")

    # 3) Brute-force each subsequent byte
    for global_i in range(len(KNOWN_PREFIX), FLAG_LEN):
        block_idx = global_i // BS        # which ciphertext block holds this byte
        byte_in_block = global_i % BS     # position within the block

        # Compute padding so that the target byte lands at block end
        nA = pad_length + (BS - 1 - byte_in_block)
        prefix = b"A" * nA

        # Get the real ciphertext block for the unknown byte
        ct = oracle(prefix)
        target_block = split_blocks(ct)[prefix_blocks + block_idx]

        # Known bytes up to (but not including) the target byte
        known_so_far = bytes(recovered[:block_idx * BS + byte_in_block])

        # Try every candidate character
        for c in CHARSET:
            guess = prefix + known_so_far + bytes([c])
            ct2 = oracle(guess)
            if split_blocks(ct2)[prefix_blocks + block_idx] == target_block:
                recovered.append(c)
                print(f"[+] Recovered byte {global_i:02d}: {chr(c)}")
                break
        else:
            raise RuntimeError(f"No match for byte {global_i}")

    # Clean up and return full flag
    io.close()
    return recovered

if __name__ == "__main__":
    flag = recover_flag().decode()
    print("\nRecovered flag:", flag)



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{ad3c6c1e-5cac-4c87-b5c3-a5dab511fee3}

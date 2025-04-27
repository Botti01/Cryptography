"""

fool this new one...

nc 130.192.5.212 6542

"""

import string, math
from pwn import remote

HOST = "130.192.5.212"
PORT = 6542
BS = 16
FLAG_LEN = 10 + 36       # Total flag length: len("CRYPTO25{}")+36 = 46
KNOWN_PREFIX = b"CRYPTO25{"  # We know the flag always starts with this

# Charset for the remainder (UUID4): uppercase, lowercase, digits, dash and brace
CHARSET = (string.ascii_uppercase +
           string.ascii_lowercase +
           string.digits +
           "-}")

def split_blocks(data: bytes):
    return [data[i:i+BS] for i in range(0, len(data), BS)]

def make_oracle():
    """
    Opens one connection, eats the initial menu, and returns:
      io, oracle(user_bytes) -> ciphertext_bytes
    The oracle also consumes the post-encrypt menu prompt, so it's ready
    for the next call.
    """
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")  # consume initial prompt

    def oracle(user_bytes: bytes) -> bytes:
        io.sendline(b"enc")
        io.recvuntil(b"> ")
        io.sendline(user_bytes.hex().encode())
        line = io.recvline().strip()   # the hex cipher
        io.recvuntil(b"> ")            # consume the menu prompt again
        return bytes.fromhex(line.decode())

    return io, oracle

def detect_alignment(oracle):
    """
    Find how many 'A's we need so that our input
      b"A"*(pad_length + 2*BS)
    will produce two identical adjacent blocks.  Returns:
      pad_length, prefix_blocks
    """
    for pad_length in range(BS):
        probe = b"A" * (pad_length + 2*BS)
        ct = oracle(probe)
        blocks = split_blocks(ct)
        for i in range(len(blocks)-1):
            if blocks[i] == blocks[i+1]:
                return pad_length, i
    raise RuntimeError("Alignment detection failed")

def recover_flag():
    io, oracle = make_oracle()

    # 1) Detect the random 5-byte prefix alignment
    pad_length, prefix_blocks = detect_alignment(oracle)
    print(f"[*] pad_length = {pad_length}, prefix_blocks = {prefix_blocks}")

    # 2) Start with the known prefix already in place
    recovered = bytearray(KNOWN_PREFIX)
    print(f"[*] Prefilled known prefix: {recovered.decode()}")

    # 3) Now brute-force only the remaining bytes (positions 9 .. 45)
    for global_i in range(len(KNOWN_PREFIX), FLAG_LEN):
        block_idx = global_i // BS
        byte_in_block = global_i % BS

        # Build padding so that the target flag byte is at the end of its AES block
        nA = pad_length + (BS - 1 - byte_in_block)
        prefix = b"A" * nA

        # Get the “real” ciphertext block containing flag[global_i]
        ct = oracle(prefix)
        target_block = split_blocks(ct)[prefix_blocks + block_idx]

        # Build the known‐so‐far portion up to this byte
        known_so_far = bytes(recovered[:block_idx*BS + byte_in_block])

        # Brute‐force this one byte
        for c in CHARSET:
            guess = prefix + known_so_far + c.encode()
            ct2 = oracle(guess)
            if split_blocks(ct2)[prefix_blocks + block_idx] == target_block:
                recovered.append(ord(c))
                print(f"Recovered byte {global_i:02d}: {c}")
                break
        else:
            raise RuntimeError(f"No match for byte {global_i}")

    io.close()
    return recovered

if __name__ == "__main__":
    flag = recover_flag().decode()
    print("\nRecovered flag:", flag)



# FLAG: CRYPTO25{ad3c6c1e-5cac-4c87-b5c3-a5dab511fee3}
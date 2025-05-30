"""

...even harder with this one...

nc 130.192.5.212 6544

"""

# ─── Attack ─────────────────────────────────────────────────────────────────────
# Byte-at-a-time ECB decryption with unknown random prefix 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Detect the length of the unknown random prefix by sending repeated blocks
#      until two identical ciphertext blocks appear (prefix alignment).
#   2. Compute pad_len = number of bytes needed so that controlled input
#      aligns the next unknown plaintext byte at the end of an AES block.
#   3. For each flag byte:
#        a) Send prefix + known_bytes + guess_byte and compare the target block
#        b) When a guess produces the same block as the real encryption, record it
#   4. Continue until the closing “}” is recovered.
#   5. Strip any garbage before “CRYPTO25” and print the flag.

from pwn import remote
from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size  # 16 bytes

def get_block(ct: bytes, idx: int) -> bytes:
    
    # Extract the idx-th 16-byte block from ciphertext.
    return ct[idx*BLOCK_SIZE:(idx+1)*BLOCK_SIZE]

def connect():
    
    # Open connection and consume initial menu prompt.
    io = remote("130.192.5.212", 6544)
    io.recvuntil(b"> ")
    return io

def send_enc(io, data_bytes: bytes) -> bytes:

    # Send 'enc' command with hex-encoded data_bytes, then
    # return the raw ciphertext bytes.

    io.sendline(b"enc")
    io.recvuntil(b"> ")
    io.sendline(data_bytes.hex().encode())
    ct_line = io.recvline().strip()
    io.recvuntil(b"> ")
    return bytes.fromhex(ct_line.decode())

def find_padding_len(io) -> int:

    # Find minimal pad_len such that sending b'A'*pad_len + b'B'*32
    # produces two identical consecutive blocks in the ciphertext.

    for pad_len in range(32):
        ct = send_enc(io, b"A"*pad_len + b"B"*32)
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        for j in range(len(blocks)-1):
            if blocks[j] == blocks[j+1]:
                print(f"[+] alignment found at pad_len = {pad_len}")
                return pad_len
    raise Exception("padding alignment not found")

def recover_flag(io, pad_len: int) -> bytes:

    # Perform byte-at-a-time ECB decryption:
    #   - Compute prefix to align unknown byte at block end.
    #   - Encrypt reference to get target block.
    #   - Try all 256 byte values to match the target block.

    known = b""
    while True:
        # Compute prefix so that next unknown byte is last in its block
        prefix_len = (BLOCK_SIZE - 1 - (len(known) % BLOCK_SIZE)) + pad_len
        prefix = b"A" * prefix_len

        # Get reference ciphertext and target block index
        ct_ref = send_enc(io, prefix)
        block_idx = (prefix_len + len(known)) // BLOCK_SIZE
        target_block = get_block(ct_ref, block_idx)

        # Brute-force next byte
        for b in range(256):
            guess = prefix + known + bytes([b])
            ct_guess = send_enc(io, guess)
            if get_block(ct_guess, block_idx) == target_block:
                known += bytes([b])
                print(f"[+] recovered: {known!r}")
                break
        else:
            raise Exception("Byte recovery failed")

        # Stop when the flag closing brace is found
        if known.endswith(b"}"):
            return known

def main():
    io = connect()

    # Step 1: detect prefix alignment offset
    pad_len = find_padding_len(io)
    print(f"[*] pad_len = {pad_len}")

    # Step 2: recover the flag bytes
    recovered = recover_flag(io, pad_len)

    # Step 3: strip off any garbage before "CRYPTO25" and print
    idx = recovered.find(b"CRYPTO25")
    if idx == -1:
        raise ValueError("Couldn't find CRYPTO25 in recovered bytes!")
    flag = recovered[idx:]
    print(f"[+] FLAG: {flag.decode()}")

if __name__ == "__main__":
    main()



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{df0b0f03-0bd4-4dc8-9043-bcdac301684c}
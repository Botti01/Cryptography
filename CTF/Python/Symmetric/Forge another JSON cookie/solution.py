"""

...it's more or less the same but with more errors to manage!

nc 130.192.5.212 6551

"""

# ─── Attack  ────────────────────────────────────────────────────────────────────
# JSON‐Block Splicing via ECB Token Forgery 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the service and request a token for a carefully crafted username
#      such that, when serialized as JSON, the plaintext “{"username": <name>, "admin": false}”
#      aligns into 16‐byte blocks in a controlled manner.
#   2. Decode the Base64‐encoded token to obtain its raw AES‐ECB ciphertext blocks.
#   3. Identify and reorder specific ciphertext blocks to forge a new token where
#      “"admin": true” appears in place of “"admin": false” without invalidating padding.
#   4. Base64‐encode the forged ciphertext and submit it to the “flag” endpoint to retrieve the flag.

from pwn import * 
from base64 import b64decode, b64encode
import json                     # for JSON serialization

context.log_level = 'info'      # show info‐level logs from pwntools

HOST = '130.192.5.212'
PORT = 6551
BLOCK_SIZE = 16                 # AES block size (ECB mode)

def get_token(name: bytes, r: remote) -> bytes:

    # Send the name to the server and return the raw AES‐ECB token.
    # 1) Wait for the 'name!' prompt.
    # 2) Send the username bytes.
    # 3) Read until 'token: ' and decode the Base64 token.

    r.sendlineafter(b'name!\n> ', name)
    r.recvuntil(b'token: ')
    token_b64 = r.recvline().strip().decode()
    return b64decode(token_b64)

def get_flag(forged_token: bytes, r: remote) -> bytes:

    # Submit the forged token to the 'flag' command and return the server response.
    # 1) Wait for the menu prompt.
    # 2) Send 'flag'.
    # 3) When prompted for 'token?', send the Base64‐encoded forged token.
    # 4) Receive all remaining data (which should include the flag).

    r.recvuntil(b'> ')            # wait for menu
    r.sendline(b'flag')
    r.sendlineafter(b'token?\n> ', b64encode(forged_token))
    return r.recvall()

def main():
    # Step 1: Connect to the remote service
    r = remote(HOST, PORT)

    # Craft a username that will align the JSON fields into 16‐byte blocks.
    # We want JSON of the form:
    #   {"username": "<name>", "admin": false}
    # so that the '"admin": false' field falls into specific blocks we can swap.
    #
    # Explanation of name1:
    #   b'ab' + b' ' *15           → fills up to 2 + 15 = 17 bytes after "username":
    #                                  i.e. '"username": "ab               '
    #   b'"surname' + b' ' *8      → continues into the next block:
    #                                  '"surname        '
    #   b' ' *15 + b'":' + b' ' *14 → pad so that '"admin": ' aligns at block boundary
    #   b'true,' + b' ' *11 + b'1234'
    #   → This tail ends up shaping the JSON so that '"admin": true,' can replace '"admin": false,'.
    name1 = (
        b'ab' + b' ' * 15 +
        b'"surname' + b' ' * 8 +
        b' ' * 15 + b'":' + b' ' * 14 +
        b'true,' + b' ' * 11 + b'1234'
    )

    # Log the crafted name for debugging
    log.info("Crafted name: " + name1.decode())

    # To understand block alignment, serialize the JSON and print 16‐byte chunks:
    json_str = json.dumps({
        "username": name1.decode(),
        "admin": False
    })
    for i in range(0, len(json_str), BLOCK_SIZE):
        print(json_str[i:i + BLOCK_SIZE])

    # Step 2: Request a token for the crafted username
    token1 = get_token(name1, r)
    # Split the raw token ciphertext into 16‐byte blocks
    blocks1 = [token1[i:i + BLOCK_SIZE] for i in range(0, len(token1), BLOCK_SIZE)]

    # Debug: print each block's hex for inspection
    log.info("Token1 blocks:")
    for idx, blk in enumerate(blocks1):
        log.info(f"Block {idx}: {blk.hex()}")

    # Step 3: Forge a new token by reordering blocks
    # Observing the printed blocks, identify which block indices correspond to:
    #   - Block 0: '{"username": "ab ... }'
    #   - Block 5: Block containing '"admin": false' (the 'false' literal)
    #   - Block 6: Block containing '"true,' after our inserted 'true'
    #   - etc.  
    # The exact reordering below swaps blocks so that '"admin": true' appears
    # in place of '"admin": false':
    forged = (
        blocks1[0] +  # '{"username": "...'
        blocks1[6] +  # '"true,' block
        blocks1[5] +  # block originally containing '"admin": '
        blocks1[2] +  # filler block (preserves JSON structure)
        blocks1[4] +  # filler block
        blocks1[7]    # trailing block (padding or closing brace)
    )
    log.success("Forged token (Base64): " + b64encode(forged).decode())

    # Step 4: Submit the forged token to retrieve the flag
    response = get_flag(forged, r)
    print(response.decode())

if __name__ == "__main__":
    main()



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{d153d414-d83d-45f2-9f90-f6628c479331}
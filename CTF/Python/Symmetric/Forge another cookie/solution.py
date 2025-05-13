"""

Needless to say, you need the proper authorization cookie to get the flag

nc 130.192.5.212 6552

"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# Copy and Paste Attack ECB.

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

import os
os.environ['PWNLIB_NOTERM'] = 'True' 
os.environ['PWNLIB_SILENT'] = 'True'  

from pwn import * 

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"  
PORT = 6552  
BLOCK_SIZE = 16         # AES block size in bytes (ECB mode)

def main():

    # 1) Connect to the server to get an encrypted user cookie (as an integer).
    # 2) Craft a username so that one ciphertext block corresponds to "true" with PKCS#7 pad.
    # 3) Splice blocks to create a cookie where &admin=true appears.
    # 4) Submit the forged cookie to retrieve the flag.

    # ── Step 1: Open connection ──────────────────────────────────────────────────
    io = remote(HOST, PORT)

    # ── Step 2: Craft username for block alignment ──────────────────────────────
    # Server constructs:
    #   pad("username=" + username + "&admin=false", 16)
    # We choose username so that:
    #   ‣ Block0 = AES("username=" + 7×"A")
    #   ‣ Block1 = AES(pad("true"))    ← contains "true" + 12×0x0c
    #   ‣ Block2 = AES(remaining "&admin=false"...)
    username = (
        b"A" * (BLOCK_SIZE - len("username="))  # fill first block after "username="
        + pad(b"true", AES.block_size)          # full block with "true"+PKCS#7
        + b"A" * (BLOCK_SIZE - len("&admin="))  # pad so "&admin=false" starts at block2
    )

    # ── Step 3: Send username and receive encrypted cookie ───────────────────────
    io.sendlineafter("Username: ", username)
    cookie_int = int(io.recvline().strip())     # cookie as big integer
    cookie = long_to_bytes(cookie_int)           # convert to raw ciphertext bytes

    # ── Step 4: Reorder blocks to inject admin=true ─────────────────────────────
    # Original cookie blocks: [block0, block1, block2]
    # We want:               [block0, block2, block1]
    forged_cookie_bytes = (
        cookie[:16]      # block0 unchanged
        + cookie[32:48]  # move original block2 into position1
        + cookie[16:32]  # place "true" block into position2
    )

    # ── Step 5: Convert forged cookie back to integer ────────────────────────────
    forged_cookie = str(bytes_to_long(forged_cookie_bytes)).encode()
    print(f"\n[*] Forged cookie (decimal): {forged_cookie.decode()}")

    # ── Step 6: Request flag using forged cookie ────────────────────────────────
    io.recvuntil(b'What do you want to do?\n')
    io.sendline(b'flag')
    io.recvuntil(b'Cookie: ')
    io.sendline(forged_cookie)

    # ── Step 7: Print server response (should include the flag) ────────────────
    print(io.recv(1024).decode())

    # ── Step 8: Clean up ────────────────────────────────────────────────────────
    io.close()

if __name__ == "__main__":
    main()



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{598ea8bb-28ba-42ba-9557-5cea53b7fdae}

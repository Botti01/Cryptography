"""

Needless to say, you need the proper authorization cookie to get the flag

nc 130.192.5.212 6552

"""

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Disable pwntools terminal control (for IDEs)
os.environ['PWNLIB_SILENT'] = 'True'  # Suppress pwntools banner

from pwn import *

HOST = "130.192.5.212"
PORT = 6552
BLOCK_SIZE = 16  # AES block size in bytes

def main():
    # 1) Open a new connection to the challenge server
    io = remote(HOST, PORT)

    # 2) Craft a username whose encryption will give us an isolated “admin=true” block.
    #
    #    The server does:
    #      cookie_plain = pad("username=" + username + "&admin=false", 16)
    #    then AES-ECB-encrypts and returns it.
    #
    #    We want one of the 16-byte ciphertext blocks to equal encrypt(pad("&admin=true")).
    #
    #    To do that, we choose:
    #      username = b"A"*(16 - len("username="))        # 7 bytes of 'A'
    #              + pad(b"true", 16)                    # pad("true") => b"true"+0x0c×12
    #              + b"A"*(16 - len("&admin="))          # 9 more 'A's
    #
    #    Breakdown:
    #      - len("username=") == 9, so 16−9 = 7 → first block ends just before our pad(true)
    #      - pad(b"true") is exactly 16 bytes (“true” + 12×b"\x0c”), so that lives in block #1
    #      - we tack on 9 more 'A's so that the suffix “&admin=false” starts at block #2
    #
    username = (
        b"A" * (BLOCK_SIZE - len("username="))  # fill up to block boundary
        + pad(b"true", AES.block_size)          # a full block containing "true"+PKCS#7
        + b"A" * (BLOCK_SIZE - len("&admin="))  # pad so "&admin=false" lands in next block
    )

    # 3) Send the crafted username and receive back the encrypted cookie as a big integer.
    io.sendlineafter("Username: ", username)
    cookie_int = int(io.recvline().strip())
    # Convert the integer to the raw bytes of the AES-ECB ciphertext
    cookie = long_to_bytes(cookie_int)

    # 4) Now cookie consists of at least 3 blocks:
    #      block0: AES("username=" + 7×"A")
    #      block1: AES(pad("true"))             ← this is our “admin=true” block
    #      block2: AES("AAAAA..." + "&admin=false" + padding)
    #
    #    We can splice block1 into a normal user‐cookie to flip admin to true.
    #
    #    Here we simply reorder the blocks from:
    #      [block0, block1, block2]
    #    to:
    #      [block0, block2, block1]
    #
    #    After decryption and parsing, the server sees “...&admin=true” in the second slot.
    forged_cookie_bytes = (
        cookie[:16]      # block0 stays the same
        + cookie[32:48]  # we move original block2 into position 1
        + cookie[16:32]  # and put our “true” block into position 2
    )

    # 5) Convert the forged byte‐string back to a big integer for submission
    forged_cookie = str(bytes_to_long(forged_cookie_bytes)).encode()
    print(f"\n[*] Forged cookie (decimal): {forged_cookie.decode()}")

    # 6) Invoke the “flag” command and supply our forged cookie
    io.recvuntil(b'What do you want to do?\n')
    io.sendline(b'flag')
    io.recvuntil(b'Cookie: ')
    io.sendline(forged_cookie)

    # 7) Read and print the server’s response (hopefully the flag)
    flag = io.recv(1024)
    print(flag.decode())

    # 8) Clean up
    io.close()

if __name__ == "__main__":
    main()

    
        
# FLAG: CRYPTO25{598ea8bb-28ba-42ba-9557-5cea53b7fdae}
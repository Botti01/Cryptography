"""
    
To get your flag, forge a payload that decrypts to a fixed value...

nc 130.192.5.212 6523    
    
"""

import sys
from pwn import *

HOST = "130.192.5.212"
PORT = 6523

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bytewise XOR of two equal-length byte-strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def leak_block(r, C_hex: str, IV_hex: str) -> bytes:
    """
    On the given open connection `r`, run the decrypt oracle
    on one block C under IV, and return the 16-byte plaintext.
    """
    # (1) choose "dec"
    r.recvuntil(b"> ")
    r.sendline(b"dec")

    # (2) send ciphertext
    r.recvuntil(b"> ")
    r.sendline(C_hex.encode())

    # (3) send IV
    r.recvuntil(b"> ")
    r.sendline(IV_hex.encode())

    # (4) skip the "Mh, a normal day." (or "Nice try...") line
    r.recvline()
    # (5) read the "Decrypted: <hex>\n" line
    line = r.recvline().strip()

    if not line.startswith(b"Decrypted: "):
        print("[!] Unexpected oracle response:", line, file=sys.stderr)
        sys.exit(1)

    hexpart = line.split(b": ", 1)[1]
    return bytes.fromhex(hexpart.decode())

if __name__ == "__main__":
    # (A) open one persistent connection
    r = remote(HOST, PORT)

    # (B) leak D_k(C0) by decrypting the all-zero block under IV=0
    C0 = b"\x00" * 16
    C0_hex = C0.hex()
    IV0 = b"\x00" * 16
    IV0_hex = IV0.hex()

    print("[*] Leaking D_k(C0) under IV=0…")
    DkC0 = leak_block(r, C0_hex, IV0_hex)
    print(f"    → D_k(C0) = {DkC0.hex()}")

    # (C) compute the forged IV* = D_k(C0) ⊕ leak
    leak = b"mynamesuperadmin"
    assert len(leak) == 16

    IV_star = xor_bytes(DkC0, leak)
    print(f"[*] Forged IV* = {IV_star.hex()}")

    if IV_star == leak:
        print("[!] Whoops, IV* == leak; unlucky.", file=sys.stderr)
        sys.exit(1)

    # (D) now run decrypt again, on the same connection, with (C0, IV_star)
    print("[*] Sending forged IV to pop the flag…")
    # we’re already at the menu, so just do the same leak_block steps,
    # except now we expect “Good job. Your flag: …”
    r.sendline(b"dec")           # menu → "dec"
    r.recvuntil(b"> ")
    r.sendline(C0_hex.encode())  # send C0
    r.recvuntil(b"> ")
    r.sendline(IV_star.hex().encode())  # send IV*

    # read the next two lines
    line1 = r.recvline().decode().strip()
    line2 = r.recvline().decode().strip()
    r.close()

    if line1.startswith("Good job"):
        # line1 = "Good job. Your flag: FLAG…"
        print(line1)
    else:
        print("[!] Exploit failed, got:")
        print(line1)
        print(line2)



# FLAG: CRYPTO25{096496ba-c281-42d9-84f4-af05b39cb006}
"""
    
To get your flag, forge a payload that decrypts to a fixed value...

nc 130.192.5.212 6523    
    
"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# Bit Flipping Attack CBC.

import sys
from pwn import *  

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"   
PORT = 6523             

# ─── Utility: XOR two byte-strings ───────────────────────────────────────────────
def xor_bytes(a: bytes, b: bytes) -> bytes:

    # Perform bytewise XOR of two equal-length byte strings.
    # Used to craft forged IV values in CBC mode.

    return bytes(x ^ y for x, y in zip(a, b))

# ─── Utility: Leak one decrypted block ──────────────────────────────────────────
def leak_block(r, C_hex: str, IV_hex: str) -> bytes:

    # Use the oracle to decrypt a single 16-byte block C under IV:
    #   1) send "dec" to select decryption
    #   2) send the ciphertext hex
    #   3) send the IV hex
    #   4) read and return the 16-byte plaintext as raw bytes

    r.recvuntil(b"> ")
    r.sendline(b"dec")            # choose decryption option
    r.recvuntil(b"> ")
    r.sendline(C_hex.encode())    # send ciphertext block (hex)
    r.recvuntil(b"> ")
    r.sendline(IV_hex.encode())   # send IV (hex)
    r.recvline()                  # skip intermediate response
    line = r.recvline().strip()   # read "Decrypted: <hex>" line

    if not line.startswith(b"Decrypted: "):
        # Unexpected response: abort
        print("[!] Unexpected oracle response:", line, file=sys.stderr)
        sys.exit(1)

    # Extract and return raw plaintext bytes
    hexpart = line.split(b": ", 1)[1]
    return bytes.fromhex(hexpart.decode())

if __name__ == "__main__":
    # ── Step 1: Open persistent connection ───────────────────────────────────────
    # Persisting the connection ensures reuse of the same AES key.
    r = remote(HOST, PORT)

    # ── Step 2: Leak D_k(C0) under IV=0 ──────────────────────────────────────────
    # We decrypt a zero-block under zero IV to learn the block cipher output.
    C0 = b"\x00" * 16
    C0_hex = C0.hex()
    IV0 = b"\x00" * 16
    IV0_hex = IV0.hex()

    print("[*] Leaking D_k(C0) under IV=0…")
    DkC0 = leak_block(r, C0_hex, IV0_hex)
    print(f"    → D_k(C0) = {DkC0.hex()}")

    # ── Step 3: Forge IV* to decrypt C0 to our chosen plaintext ────────────────
    # We want the decrypted block to equal our desired plaintext:
    leak = b"mynamesuperadmin"      # chosen 16-byte plaintext
    assert len(leak) == 16

    # Compute IV* = D_k(C0) ⊕ desired_plaintext
    IV_star = xor_bytes(DkC0, leak)
    print(f"[*] Forged IV* = {IV_star.hex()}")

    # Ensure IV* differs from leak to avoid trivial case
    if IV_star == leak:
        print("[!] Whoops, IV* == leak; unlucky.", file=sys.stderr)
        sys.exit(1)

    # ── Step 4: Send forged IV to pop the flag ─────────────────────────────────
    print("[*] Sending forged IV to pop the flag…")
    # Reuse the same menu-driven oracle for decryption
    r.sendline(b"dec")
    r.recvuntil(b"> ")
    r.sendline(C0_hex.encode())
    r.recvuntil(b"> ")
    r.sendline(IV_star.hex().encode())

    # Read and display the response lines
    line1 = r.recvline().decode().strip()
    line2 = r.recvline().decode().strip()
    r.close()

    if line1.startswith("Good job"):
        # Successful exploit prints the flag in line1
        print(line1)
    else:
        # Exploit failed: show returned messages for debugging
        print("[!] Exploit failed, got:")
        print(line1)
        print(line2)



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{096496ba-c281-42d9-84f4-af05b39cb006}

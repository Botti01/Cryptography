"""

Here at HA-SHop, we accept only coupons as payment. Do you have one to get the flag?

nc 130.192.5.212 6630

"""

# ─── Attack: SHA-256 Length Extension via HashPump ─────────────────────────────
# ─── Context ───────────────────────────────────────────────────────────────────
# The coupon is a MAC of a string like: "name=alice" signed as MAC = SHA256(key || message)
# Since SHA-256 is vulnerable to length extension (for known key length), we can:
#   1. Request a MAC for "name=alice"
#   2. Use hashpumpy to forge a valid MAC for "name=alice&value=101"
#   3. Send the forged coupon and MAC to the server and get the flag

from pwn import *
from binascii import unhexlify, hexlify
import hashpumpy

HOST = "130.192.5.212"
PORT = 6630

def main():
    # Step 1: Connect to the challenge server
    conn = remote(HOST, PORT)

    # Step 2: Request a coupon for "alice"
    conn.recvuntil(b"Choose an option (1-3): ")
    conn.sendline(b"1")
    conn.recvuntil(b"Enter your name: ")
    conn.sendline(b"alice")

    # Step 3: Read the original coupon and MAC
    conn.recvuntil(b"Coupon: ")
    hex_orig = conn.recvline().strip()
    log.info(f"Original coupon hex: {hex_orig.decode()}")

    conn.recvuntil(b"MAC: ")
    mac_orig = conn.recvline().strip().decode()
    log.info(f"Original MAC:        {mac_orig}")

    # Step 4: Perform SHA-256 length extension attack using hashpumpy
    orig_msg = unhexlify(hex_orig)       # original message (e.g., b"name=alice")
    append   = b"&value=101"             # what we want to append
    key_len  = 16                        # assumption on key length (often 16–32 bytes)

    # hashpump returns (new_mac, new_message)
    new_mac, new_msg = hashpumpy.hashpump(
        mac_orig,    # original digest
        orig_msg,    # original message bytes
        append,      # data to append
        key_len      # secret key length
    )

    forged_hex = hexlify(new_msg)
    log.info(f"Forged coupon hex: {forged_hex.decode()}")
    log.info(f"Forged MAC:        {new_mac}")

    # Step 5: Redeem the forged coupon
    conn.recvuntil(b"Choose an option (1-3): ")
    conn.sendline(b"2")
    conn.recvuntil(b"Enter your coupon: ")
    conn.sendline(forged_hex)
    conn.recvuntil(b"Enter your MAC: ")
    conn.sendline(new_mac.encode())

    # Step 6: Receive the result (flag or failure message)
    result = conn.recvall(timeout=2)
    print(result.decode())

if __name__ == "__main__":
    main()
    
    

# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{26caf08d-b0d2-43fd-be41-57c7f445b01f}

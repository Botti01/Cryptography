"""

Here at HA-SHop, we accept only coupons as payment. Do you have one to get the flag?

nc 130.192.5.212 6630

"""

# ─── Attack ─────────────────────────────────────────────────────────────────────
# SHA-256 length‐extension in pure Python + pwntools 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Use /login (option 1) to obtain a coupon and its SHA-256 MAC: MAC = SHA256(secret‖coupon).
#   2. Perform a length‐extension attack:
#      a) Compute the glue padding for (secret‖coupon).
#      b) Initialize SHA256 state with the original MAC and adjusted message length.
#      c) Update with “&value=1000” to forge MAC for (secret‖coupon‖pad‖&value=1000).
#   3. Send the forged coupon+MAC via the redeem option (2) to get the flag.

import struct
import re
from pwn import remote, log

HOST = "130.192.5.212"
PORT = 6630

# ----------------------------------------------------------------------
# Pure‐Python SHA-256 (compress + padding), extended with:
#  - ability to set initial h0..h7
#  - ability to specify a starting total length in bytes
# ----------------------------------------------------------------------

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def _right(x, n):
    return (x >> n) | ((x & 0xFFFFFFFF) << (32 - n)) & 0xFFFFFFFF

def _ch(x, y, z):
    return (x & y) ^ (~x & z)

def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def _Sigma0(x):
    return _right(x, 2) ^ _right(x, 13) ^ _right(x, 22)

def _Sigma1(x):
    return _right(x, 6) ^ _right(x, 11) ^ _right(x, 25)

def _sigma0(x):
    return _right(x, 7) ^ _right(x, 18) ^ (x >> 3)

def _sigma1(x):
    return _right(x, 17) ^ _right(x, 19) ^ (x >> 10)

def sha256_compress(block, H):

    # Process one 64-byte block, updating H in place.
    # Implements the SHA-256 compression function.

    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        w.append(( _sigma1(w[i-2]) + w[i-7] + _sigma0(w[i-15]) + w[i-16] ) & 0xFFFFFFFF)

    a, b, c, d, e, f, g, h = H
    for i in range(64):
        T1 = (h + _Sigma1(e) + _ch(e,f,g) + _K[i] + w[i]) & 0xFFFFFFFF
        T2 = (_Sigma0(a) + _maj(a,b,c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF

    for i, v in enumerate((a,b,c,d,e,f,g,h)):
        H[i] = (H[i] + v) & 0xFFFFFFFF

def sha256_pad(msg_len):

    # Return the SHA-256 padding for a message of length msg_len bytes.
    
    # 1. append 0x80
    pad = b"\x80"
    # 2. append 0x00 until length ≡ 56 mod 64
    pad += b"\x00" * ((56 - (msg_len + 1)) % 64)
    # 3. append 64-bit big-endian length (bits)
    pad += struct.pack(">Q", msg_len * 8)
    return pad

class SHA256:
    def __init__(self, h=None, msg_len=0):

        # If h is None → fresh; else h is a 8‐tuple of initial state words.
        # msg_len is total bytes already “consumed” before any new update().

        if h is None:
            # initial IV
            self.H = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            ]
        else:
            self.H = list(h)
        self.buffer = b""
        self.msg_len = msg_len

    def update(self, data):
        self.buffer += data
        self.msg_len += len(data)
        # process each 64-byte chunk
        while len(self.buffer) >= 64:
            block = self.buffer[:64]
            sha256_compress(block, self.H)
            self.buffer = self.buffer[64:]

    def digest(self):
        # make a copy so we don’t disturb self
        H_copy = list(self.H)
        buf_copy = self.buffer
        total_len = self.msg_len

        # append padding
        buf_copy += sha256_pad(total_len)
        # compress remaining blocks
        while len(buf_copy) >= 64:
            sha256_compress(buf_copy[:64], H_copy)
            buf_copy = buf_copy[64:]

        return b"".join(struct.pack(">I", h) for h in H_copy)

    def hexdigest(self):
        return self.digest().hex()

# ----------------------------------------------------------------------
# Length-extension helper
# ----------------------------------------------------------------------

def forge_sha256_mac(orig_mac_hex, orig_msg, key_len, to_append):
    
    # Perform length extension:
    #   - Parse orig_mac_hex as initial state.
    #   - Compute glue padding for secret||orig_msg.
    #   - Initialize SHA256 with state and total length.
    #   - Update with to_append, return new_mac_hex and forged message.
    #
    # Given:
    #   orig_mac_hex : hex string of SHA256(secret || orig_msg)
    #   orig_msg     : bytes
    #   key_len      : int, length of secret in bytes
    #   to_append    : bytes we want to append
    # Returns:
    #   (new_mac_hex, forged_msg)
    # where:
    #   new_mac_hex is hex(SHA256(secret||orig_msg||pad||to_append))
    #   forged_msg is orig_msg || pad || to_append

    # 1) decode original MAC → 8 words
    h = struct.unpack(">8I", bytes.fromhex(orig_mac_hex))

    # 2) compute glue padding for SECRET||orig_msg
    total = key_len + len(orig_msg)
    pad = sha256_pad(total)

    # 3) initialize SHA256 with h, and msg_len = total + len(pad)
    sha = SHA256(h=h, msg_len=total + len(pad))
    sha.update(to_append)
    new_mac = sha.hexdigest()

    # 4) forged_msg to send
    forged = orig_msg + pad + to_append
    return new_mac, forged

# ----------------------------------------------------------------------
# MAIN SCRIPT
# ----------------------------------------------------------------------

def main():
    io = remote(HOST, PORT, timeout=5)

    # Step 1: Obtain original coupon and MAC
    io.recvuntil(b"Choose an option (1-3):")
    io.sendline(b"1")
    io.recvuntil(b"Enter your name:")
    io.sendline(b"attacker123")

    data = io.recvuntil(b"Choose an option (1-3):")
    text = data.decode()
    c = re.search(r"Coupon:\s*([0-9a-f]+)", text)
    m = re.search(r"MAC:\s*([0-9a-f]+)", text)
    if not c or not m:
        log.error("Failed to parse server reply:\n" + text)
    orig_coupon_hex = c.group(1)
    orig_mac        = m.group(1)
    orig_coupon     = bytes.fromhex(orig_coupon_hex)

    log.info(f"orig_coupon = {orig_coupon!r}")
    log.info(f"orig_mac    = {orig_mac}")

    # Step 2: Forge coupon for &value=1000 via length extension
    new_mac, forged = forge_sha256_mac(
        orig_mac_hex      = orig_mac,
        orig_msg          = orig_coupon,
        key_len           = 16,                # SECRET is 16 bytes
        to_append         = b"&value=1000"
    )
    new_coupon_hex = forged.hex()

    log.success(f"forged_coupon = {new_coupon_hex}")
    log.success(f"forged_mac    = {new_mac}")

    # Step 3: Redeem the forged coupon
    io.sendline(b"2")
    io.recvuntil(b"Enter your coupon:")
    io.sendline(new_coupon_hex.encode())
    io.recvuntil(b"Enter your MAC:")
    io.sendline(new_mac.encode())

    # Step 4: Retrieve the flag
    io.recvuntil(b"Result: ")
    result_line = io.recvline(timeout=2).decode().strip()
    print("\nResult:", result_line)
    io.close()

if __name__ == "__main__":
    main()
    


# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{26caf08d-b0d2-43fd-be41-57c7f445b01f}

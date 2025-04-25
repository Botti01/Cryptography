"""

Read and understand the code. You'll easily find a way to forge the target cookie.

nc 130.192.5.212 6521

"""

import base64
import json
from pwn import remote

# Remote service address and port
HOST = '130.192.5.212'
PORT = 6521

# Connect to the challenge service
io = remote(HOST, PORT)

# 1) Receive the greeting and send a dummy username (empty string)
io.recvuntil(b'> ')
io.sendline(b'')  # name = ""

# 2) The service prints the plaintext JSON token, then the base64(nonce).base64(ciphertext)
#    Read until we see the token line
line = io.recvline()
# This line contains the JSON, e.g. {"username": ""}
orig_json = line.strip().decode()
print(f"Original plaintext: {orig_json}")

# Next line: 'This is your token: <nonce>.<ciphertext>'
tok_line = io.recvline().strip().decode()
# Extract the part after the colon
_, tok = tok_line.split(': ', 1)
print(f"Received token: {tok}")

# Split into nonce and ciphertext, base64-decode both
nonce_b64, ct_b64 = tok.split('.')
nonce = base64.b64decode(nonce_b64)
ct = base64.b64decode(ct_b64)

# 3) Recover the keystream by XORing ciphertext with known plaintext
orig_bytes = orig_json.encode()
keystream = bytes(c ^ p for c, p in zip(ct, orig_bytes))

# 4) Build a new plaintext that sets admin to true:
#    We choose a JSON payload of form '{"admin":true}' plus trailing spaces to match length
admin_payload_core = '{"admin":true}'
# Pad with spaces so that len(new_plain) == len(orig_bytes)
pad_len = len(orig_bytes) - len(admin_payload_core)
if pad_len < 0:
    raise ValueError("Original token too short to embed admin payload")
new_plain = (admin_payload_core + ' ' * pad_len).encode()
print(f"Forged plaintext: {new_plain.decode()!r}")

# 5) XOR the new plaintext with the same keystream to get the forged ciphertext
ct_forged = bytes(p ^ k for p, k in zip(new_plain, keystream))

# 6) Construct the new token: same nonce + new ciphertext
forged_token = base64.b64encode(nonce).decode() + '.' + base64.b64encode(ct_forged).decode()
print(f"Forged token: {forged_token}")

# 7) Trigger the flag retrieval
io.sendline(b'flag')
io.recvuntil(b'What is your token?')
io.sendline(forged_token.encode())

# 8) Print out the service response (should include the flag)
print(io.recvuntil(b"}").decode())
io.close()



#FLAG: CRYPTO25{7d3060b2-518e-4f58-a277-7c5f5d6e11ec}
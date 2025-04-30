"""

Read and understand the code. You'll easily find a way to forge the target cookie.

nc 130.192.5.212 6521

"""

import base64
import json
from pwn import remote 

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = '130.192.5.212'  
PORT = 6521          

# ─── Step 1: Establish connection and get original token ────────────────────────
# Connect to the challenge server and send a dummy username to obtain a token.
io = remote(HOST, PORT)
io.recvuntil(b'> ')      # wait for ">" prompt asking for username
io.sendline(b'')         # send empty username to receive a token

# ─── Step 2: Read the plaintext JSON and Base64 token ───────────────────────────
# The service first prints the JSON it will encrypt, e.g. {"username": ""}.
line = io.recvline()
orig_json = line.strip().decode()
print(f"Original plaintext: {orig_json!r}")

# Next, it prints "This is your token: <nonce>.<ciphertext>"
tok_line = io.recvline().decode().strip()
_, tok = tok_line.split(': ', 1)  # extract the part after colon
print(f"Received token: {tok}")

# ─── Step 3: Decode nonce and ciphertext ────────────────────────────────────────
# Split the token into nonce and ciphertext, both Base64-encoded.
nonce_b64, ct_b64 = tok.split('.')
nonce = base64.b64decode(nonce_b64)  # raw 16-byte nonce
ct = base64.b64decode(ct_b64)        # raw ciphertext bytes

# ─── Step 4: Recover keystream via known-plaintext attack ───────────────────────
# Since the service did AES-CTR (or similar stream cipher),
# ciphertext = plaintext ⊕ keystream. With known orig_json, we can compute:
orig_bytes = orig_json.encode()
keystream = bytes(c ^ p for c, p in zip(ct, orig_bytes))
# Now keystream[i] = ct[i] ⊕ orig_bytes[i] for each byte

# ─── Step 5: Craft new plaintext with admin privileges ─────────────────────────
# We want '{"admin":true}' as the JSON payload to elevate privileges.
admin_payload_core = '{"admin":true}'
# Pad with spaces so the new plaintext matches the original length
pad_len = len(orig_bytes) - len(admin_payload_core)
if pad_len < 0:
    raise ValueError("Original token too short to embed admin payload")
new_plain = (admin_payload_core + ' ' * pad_len).encode()
print(f"Forged plaintext: {new_plain.decode()!r}")

# ─── Step 6: Compute forged ciphertext using recovered keystream ────────────────
# ciphertext_forged = new_plain ⊕ keystream
ct_forged = bytes(p ^ k for p, k in zip(new_plain, keystream))

# ─── Step 7: Build the forged token ─────────────────────────────────────────────
# Reuse the original nonce + our new ciphertext, both Base64-encoded.
forged_token = (
    base64.b64encode(nonce).decode()
    + '.'
    + base64.b64encode(ct_forged).decode()
)
print(f"Forged token: {forged_token}")

# ─── Step 8: Submit forged token to retrieve flag ──────────────────────────────
io.sendline(b'flag')                      # select "flag" command
io.recvuntil(b'What is your token?')      # wait for prompt
io.sendline(forged_token.encode())        # send our forged token
# Read and print response, expecting the flag in a JSON or text response
print(io.recvuntil(b"}").decode())
io.close()



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{7d3060b2-518e-4f58-a277-7c5f5d6e11ec}```

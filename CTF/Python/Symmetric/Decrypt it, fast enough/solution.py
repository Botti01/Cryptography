"""

I'm reusing the already reused message... ......read the challenge code and find the flag!

nc 130.192.5.212 6562

"""

# ─── Attack ─────────────────────────────────────────────────────────────────────
# ChaCha20 nonce-reuse stream cipher keystream recovery 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Connect to the service and request encryption of a known plaintext.
#   2. Receive both the ciphertext of the known plaintext and the flag ciphertext
#      under the same (unknown) key and reused nonce.
#   3. Derive the keystream: keystream = ct_known ⊕ pt_known.
#   4. Recover the flag: pt_flag = ct_flag ⊕ keystream.
#   5. If flag not found, repeat with a fresh connection (nonce may rotate each run).

from pwn import remote
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
import time
import random

HOST = "130.192.5.212"
PORT = 6562

def get_ciphertexts(io, known_plain):

    # Interact with the menu:
    #   - Send 'y' to encrypt known_plain → get ct_known.
    #   - Send 'f' to fetch the flag ciphertext → get ct_flag.

    io.sendlineafter(b"Want to encrypt? (y/n/f)", b"y")
    io.sendlineafter(b"> ", known_plain)
    ct_known = bytes.fromhex(io.recvline().strip().decode())

    io.sendlineafter(b"Want to encrypt something else? (y/n/f)", b"f")
    ct_flag = bytes.fromhex(io.recvline().strip().decode())
    return ct_known, ct_flag

def recover_flag_from_stream(ct_known, pt_known, ct_flag):

    # Given two ciphertexts under the same keystream:
    #   keystream = ct_known ⊕ pt_known
    #   pt_flag   = ct_flag  ⊕ keystream

    # Derive stream keystream from known plaintext
    keystream = bytes(a ^ b for a, b in zip(ct_known, pt_known))
    # Decrypt flag
    pt_flag = bytes(a ^ b for a, b in zip(ct_flag, keystream))
    try:
        flag_str = pt_flag.decode()
    except UnicodeDecodeError:
        flag_str = pt_flag.decode(errors="ignore")
    return flag_str

def main():
    # Known plaintext long enough to cover flag length
    known_plain = b"A" * 48

    for attempt in range(30):
        io = remote(HOST, PORT)
        ct_known, ct_flag = get_ciphertexts(io, known_plain)
        io.close()

        flag_candidate = recover_flag_from_stream(ct_known, known_plain, ct_flag)
        if "CRYPTO25{" in flag_candidate:
            print("Flag:", flag_candidate)
            break
        else:
            print(f"Attempt {attempt+1}: No valid flag found, retrying...")
            time.sleep(0.2)
    else:
        print("Failed to recover flag after multiple attempts.")

if __name__ == "__main__":
    main()
    
    

# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{23ae15cf-c924-416c-b44d-fde94f18cc0c}

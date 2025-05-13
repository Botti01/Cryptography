"""

As I don't have enough fantasy, I'm just reusing the same text as other challenges... 
...read the challenge code and find the flag!

nc 130.192.5.212 6561

"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# Key Stream Reuse

from pwn import *  

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"  
PORT = 6561             

# ─── Utility: Flag Recovery Exploit Function ─────────────────────────────────────
def get_flag(seed):

    # Connects to the remote service, seeds its PRNG (predictable nonce),
    # retrieves the encrypted flag, then recovers the ChaCha20 keystream by
    # encrypting a known plaintext of the same length, and finally XORs
    # everything together to recover the plaintext flag.

    # ── Step 1: Establish connection ──────────────────────────────────────────────
    # Using pwntools' remote() to open a TCP socket to the challenge server.
    io = remote(HOST, PORT)

    # ── Step 2: Seed the server PRNG ──────────────────────────────────────────────
    # We wait for the prompt "> " and then send our chosen seed.
    # Seeding forces the same key/nonce in ChaCha20, enabling nonce reuse attack.
    io.recvuntil(b"> ")
    io.sendline(str(seed).encode())

    # ── Step 3: Receive the encrypted flag ────────────────────────────────────────
    # The service prints a message ending in "secret!\n" followed by hex ciphertext.
    # We strip and decode to get raw bytes for decryption logic.
    io.recvuntil(b"secret!\n")
    flag_ctxt_hex = io.recvline().strip().decode()  # e.g. "deadbeef..."
    flag_ctxt = bytes.fromhex(flag_ctxt_hex)         # convert hex to bytes

    # ── Step 4: Trigger second encryption ─────────────────────────────────────────
    # Ask the server to encrypt our controlled plaintext under the same nonce.
    # This step leaks the keystream because P_known is known.
    io.recvuntil(b"(y/n)")
    io.sendline(b"y")

    # ── Step 5: Send known plaintext ──────────────────────────────────────────────
    # Prepare a plaintext of identical length to flag ciphertext, here all "A"s.
    # Because ChaCha20 is a stream cipher, C_known = P_known ⊕ KS.
    io.recvuntil(b"message? ")
    known = b"A" * len(flag_ctxt)
    io.sendline(known)

    # ── Step 6: Read back encrypted known plaintext ───────────────────────────────
    # We now receive the hex-encoded ciphertext of our known plaintext.
    known_ctxt_hex = io.recvline().strip().decode()
    known_ctxt = bytes.fromhex(known_ctxt_hex)

    # ── Step 7: Close connection ─────────────────────────────────────────────────
    # No further interaction needed; close socket to free resources.
    io.close()

    # ── Step 8: Recover the flag via XOR math ────────────────────────────────────
    # Let:
    #   C_flag   = P_flag   ⊕ KS
    #   C_known  = P_known  ⊕ KS
    # ⇒ KS       = C_known  ⊕ P_known
    # ⇒ P_flag   = C_flag   ⊕ KS
    # Substitute KS to get: P_flag = C_flag ⊕ C_known ⊕ P_known
    flag = bytes(cf ^ ck ^ pk for cf, ck, pk in zip(flag_ctxt, known_ctxt, known))
    return flag

# ─── Main Entrypoint ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # We choose seed=0 here (any value works since the real issue is nonce reuse).
    recovered = get_flag(0)
    # Decode bytes to string, ignoring any non-UTF8 residues, and print result.
    print(f"Recovered flag: {recovered.decode(errors='ignore')}")



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{5a60b310-f194-4661-941b-eab7e18dc073}
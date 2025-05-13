"""

Guess the mode. Now you need to reason about how modes work. Ask a second encryption to confirm your hypothesis...

nc 130.192.5.212 6532

"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# ECB vs CBC mode detection

from pwn import remote  

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212" 
PORT = 6532       
NUM_ROUNDS = 128        # number of challenges before flag is revealed

# ─── Utility: Detect encryption mode ────────────────────────────────────────────
def detect_mode(ct1: bytes, ct2: bytes) -> str:
    
    # Compare two ciphertexts of identical plaintext under the same key:
    #   - If they match exactly, the mode is ECB (deterministic per block).
    #   - Otherwise, it's CBC (IV randomizes the output).
    
    return "ECB" if ct1 == ct2 else "CBC"

def main():
    
    # 1) Connect to the remote mode-detection challenge.
    # 2) For each round:
    #    a) Send 32 zero-bytes to be encrypted twice.
    #    b) Compare the two outputs to guess ECB vs CBC.
    #    c) Send the guess and verify correctness.
    # 3) After 128 correct guesses, read and print the flag.

    # ── Step 1: Establish connection ─────────────────────────────────────────────
    io = remote(HOST, PORT)

    # ── Step 2: Iterate through all challenge rounds ─────────────────────────────
    for round_i in range(NUM_ROUNDS):
        print(f"Challenge #{round_i}")  # show progress

        # 2a) Prepare and send the probe: 32 zero bytes in hex
        io.recvuntil(b"Input: ")
        probe = b"00" * 32  # "00" hex × 32 = 32 raw zero bytes
        io.sendline(probe)

        # Read first ciphertext output (hex), convert to raw bytes
        line1 = io.recvline().strip()
        ct1_hex = line1.split(b"Output: ")[1]
        ct1 = bytes.fromhex(ct1_hex.decode())

        # 2b) Send the same probe again for a second encryption
        io.sendline(probe)
        line2 = io.recvline().strip()
        ct2_hex = line2.split(b"Output: ")[1]
        ct2 = bytes.fromhex(ct2_hex.decode())

        # Display both ciphertexts for debugging/verification
        print(f"  Output1: {ct1_hex.decode()}")
        print(f"  Output2: {ct2_hex.decode()}")

        # 2c) Guess mode based on ciphertext equality
        prompt = io.recvuntil(b")\n")       # reads "What mode did I use? (ECB, CBC)"
        print(prompt.decode(), end="")
        guess = detect_mode(ct1, ct2)       # ECB if identical, else CBC
        io.sendline(guess.encode())

        # Read and print the server's response
        resp = io.recvline().strip().decode()
        print(" ", resp)
        if not resp.startswith("OK"):
            # Abort on wrong guess to prevent infinite loop
            print(f"[!] Failed at round {round_i}")
            return

    # ── Step 3: All rounds passed → retrieve and print flag ──────────────────────
    final = io.recvall(timeout=2).decode()
    print(final)

if __name__ == "__main__":
    main()



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{c15fa569-562d-4531-b58b-75fe687c4b0a}

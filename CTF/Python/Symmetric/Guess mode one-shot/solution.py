"""
    
Read the code. If you really understood it, you can correctly guess the mode. 
If you do it with a probability higher than 2^128 you'll get the flag.

nc 130.192.5.212 6531
    
"""

# ─── Attack ────────────────────────────────────────────────────────────────────
# ECB vs CBC mode detection

from pwn import remote  
import sys             

# ─── Configuration ───────────────────────────────────────────────────────────────
HOST = "130.192.5.212"      
PORT = 6531        
NUM_ROUNDS = 128            # total number of mode-guessing rounds

# ─── Helper: receive until a given prompt ────────────────────────────────────────
def recv_until_prompt(conn, prompt):

    # Read from connection until the given prompt is encountered.
    # Returns the full received string (including the prompt).

    return conn.recvuntil(prompt.encode()).decode()

def main():

    # 1) Connect to the remote mode-guessing service.
    # 2) For each of NUM_ROUNDS:
    #    a) Read the OTP value (used as plaintext) and send it back to get ciphertext.
    #    b) Split ciphertext into two 16-byte blocks.
    #    c) If blocks match → ECB; else → CBC.
    #    d) Send the guess and verify the response.
    # 3) After 128 correct guesses, print the flag.

    # ── Step 1: Establish connection ─────────────────────────────────────────────
    conn = remote(HOST, PORT)

    try:
        # ── Step 2: Iterate through each challenge round ─────────────────────────
        for i in range(NUM_ROUNDS):
            # a) Wait for challenge header
            header = recv_until_prompt(conn, "Challenge")
            print(f"Challenge {i}: {header.strip()}")

            # b) Read the OTP prompt and the OTP value in hex
            otp_prompt = recv_until_prompt(conn, "The otp I'm using: ")
            print(otp_prompt.strip())
            otp_hex = conn.recvline().decode().strip()
            print("OTP:", otp_hex)

            # c) Send OTP back as hex plaintext (so plaintext = 0 bytes)
            recv_until_prompt(conn, "Input: ")
            conn.sendline(otp_hex.encode())

            # d) Receive and parse ciphertext hex
            recv_until_prompt(conn, "Output: ")
            ct_line = conn.recvline().decode().strip()
            ciphertext_hex = ct_line.split()[0]
            print("Ciphertext:", ciphertext_hex)

            # e) Split into two 16-byte blocks (32 hex chars each)
            block1 = ciphertext_hex[:32]
            block2 = ciphertext_hex[32:64]

            # f) Guess mode: identical blocks imply ECB, else CBC
            mode_guess = "ECB" if block1 == block2 else "CBC"
            print("Guessed mode:", mode_guess)

            # g) Send guess and read feedback
            recv_until_prompt(conn, "What mode did I use? (ECB, CBC)")
            conn.sendline(mode_guess.encode())
            feedback = conn.recvline().decode().strip()
            print("Feedback:", feedback)

            # h) Abort on wrong guess
            if "Wrong" in feedback:
                print(f"[!] Failed at round {i}")
                sys.exit(1)

        # ── Step 3: All guesses correct → receive flag ───────────────────────────
        remaining = conn.recvall(timeout=3).decode()
        print(remaining)

    finally:
        conn.close()

if __name__ == "__main__":
    main()



# ─── Flag ────────────────────────────────────────────────────────────────────
# CRYPTO25{3709585c-5eda-4f6a-b1e5-a93e0cf99f93}```

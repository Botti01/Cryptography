"""

Guess the mode. Now you need to reason about how modes work. Ask a second encryption to confirm your hypothesis...

nc 130.192.5.212 6532

"""

from pwn import remote

HOST = "130.192.5.212"
PORT = 6532
NUM_ROUNDS = 128

def detect_mode(ct1: bytes, ct2: bytes) -> str:
    return "ECB" if ct1 == ct2 else "CBC"

def main():
    io = remote(HOST, PORT)

    for round_i in range(NUM_ROUNDS):
        # ----- Show which challenge we’re on -----
        print(f"Challenge #{round_i}")

        # Wait for the prompt, then send 32 zero‐bytes (hex)
        io.recvuntil(b"Input: ")
        probe = b"00" * 32
        io.sendline(probe)

        # Read back the first ciphertext
        line1 = io.recvline().strip()
        ct1_hex = line1.split(b"Output: ")[1]
        ct1 = bytes.fromhex(ct1_hex.decode())

        # Send the same probe again
        io.sendline(probe)
        line2 = io.recvline().strip()
        ct2_hex = line2.split(b"Output: ")[1]
        ct2 = bytes.fromhex(ct2_hex.decode())

        # ----- Print the two ciphertexts so you can see them -----
        print(f"  Output1: {ct1_hex.decode()}")
        print(f"  Output2: {ct2_hex.decode()}")

        # Now the server asks us to guess
        prompt = io.recvuntil(b")\n")
        print(prompt.decode(), end="")   # prints: What mode did I use? (ECB, CBC)

        guess = detect_mode(ct1, ct2)
        io.sendline(guess.encode())

        # Read their response and show it
        resp = io.recvline().strip().decode()
        print(" ", resp)   # prints either "OK, next" or "Wrong, sorry"
        if not resp.startswith("OK"):
            print(f"[!] Failed at round {round_i}")
            return

    # After 128 correct guesses, we get the flag
    final = io.recvall(timeout=2).decode()
    print(final)

if __name__ == "__main__":
    main()



# FLAG: CRYPTO25{c15fa569-562d-4531-b58b-75fe687c4b0a}
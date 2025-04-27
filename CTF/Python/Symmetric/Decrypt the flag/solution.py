"""
    
As I don't have enough fantasy, I'm just reusing the same text as other challenges... 
...read the challenge code and find the flag!

nc 130.192.5.212 6561
    
"""

from pwn import *

HOST = "130.192.5.212"
PORT = 6561

def get_flag(seed):
    """
    Connects to the remote service, seeds its PRNG, retrieves the encrypted flag,
    then recovers the ChaCha20 keystream by encrypting a known plaintext of the
    same length, and finally XORs everything together to recover the flag.
    """

    # 1) Open a TCP connection to the challenge server
    io = remote(HOST, PORT)

    # 2) Wait for the “> ” prompt, then send our chosen seed (as ASCII)
    io.recvuntil(b"> ")
    io.sendline(str(seed).encode())

    # 3) The service now prints:
    #      “OK! I can now give you the encrypted secret!\n<hex-ciphertext>\n”
    #    We skip until “secret!\n” and then read the next line as the flag ciphertext.
    io.recvuntil(b"secret!\n")
    flag_ctxt_hex = io.recvline().strip().decode()   # e.g. "deadbeef…"
    flag_ctxt     = bytes.fromhex(flag_ctxt_hex)     # convert hex → raw bytes

    # 4) Next the service asks: “Do you want to encrypt something else? (y/n)”
    #    We choose “y” to ask it to encrypt a chosen plaintext under the same key+nonce.
    io.recvuntil(b"(y/n)")
    io.sendline(b"y")

    # 5) It then prompts “What is the message? ”
    #    We prepare a known plaintext of the **same length** as the flag ciphertext,
    #    here all ASCII “A”s.  That way, ciphertext = known_plaintext ⊕ keystream.
    io.recvuntil(b"message? ")
    known = b"A" * len(flag_ctxt)
    io.sendline(known)

    # 6) Read back the hex-encoded ciphertext of our known plaintext.
    known_ctxt_hex = io.recvline().strip().decode()
    known_ctxt     = bytes.fromhex(known_ctxt_hex)

    # 7) We’re done with the connection, so close it.
    io.close()

    # 8) ChaCha20 (like any stream cipher) gives:
    #       C_flag   = P_flag   ⊕ KS
    #       C_known  = P_known  ⊕ KS
    #    ⇒ KS       = C_known  ⊕ P_known
    #    ⇒ P_flag   = C_flag   ⊕ KS
    #
    #  So: flag = C_flag ⊕ (C_known ⊕ P_known)
    flag = bytes(a ^ b ^ c for a, b, c in zip(flag_ctxt, known_ctxt, known))
    return flag

if __name__ == "__main__":
    # Here we call get_flag(0).  The exact seed doesn’t matter for the exploit,
    # since the vulnerability is nonce reuse rather than the PRNG itself.
    recovered = get_flag(0)
    print("Recovered flag:", recovered.decode(errors="ignore"))



# FLAG: CRYPTO25{5a60b310-f194-4661-941b-eab7e18dc073}
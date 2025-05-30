import os
import random
from time import time
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
from secret import flag

# Generate a random 32-byte key for ChaCha20 encryption (fixed for the session)
key = os.urandom(32)


def encrypt(msg):
    # Seed the random number generator with the current time (seconds since epoch)
    random.seed(int(time()))
    # Generate a 12-byte nonce using random bits (reseeding every call)
    cipher = ChaCha20.new(
        key=key, nonce=long_to_bytes(random.getrandbits(12*8)))
    # Encrypt the message (as bytes) and return the ciphertext
    return cipher.encrypt(msg.encode())


def main():
    # Interactive loop for encrypting user input or the secret flag
    confirm = input("Want to encrypt? (y/n/f)")
    while confirm.lower() != 'n':
        if confirm.lower() == 'y':
            # Encrypt user-provided message
            msg = input("> ")
            print(encrypt(msg).hex())
        elif confirm.lower() == 'f':
            # Encrypt the secret flag (imported from secret.py)
            print(encrypt(flag).hex())
        # Ask if the user wants to encrypt again or exit
        confirm = input("Want to encrypt something else? (y/n/f)")


if __name__ == '__main__':
    # Entry point: start the interactive encryption loop
    main()

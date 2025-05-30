import os
import random
from time import time
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
from secret import flag

key = os.urandom(32)


def encrypt(msg):
    random.seed(int(time()))
    cipher = ChaCha20.new(
        key=key, nonce=long_to_bytes(random.getrandbits(12*8)))
    return cipher.encrypt(msg.encode())


def main():

    confirm = input("Want to encrypt? (y/n/f)")
    while confirm.lower() != 'n':
        if confirm.lower() == 'y':
            msg = input("> ")
            print(encrypt(msg).hex())
        elif confirm.lower() == 'f':
            print(encrypt(flag).hex())
        confirm = input("Want to encrypt something else? (y/n/f)")


if __name__ == '__main__':
    main()

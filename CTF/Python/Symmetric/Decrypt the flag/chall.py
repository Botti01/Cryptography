import random
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
from secret import flag, randkey

nonce = -1  # Global variable to store the nonce (initially set to -1)


def encrypt_and_update(msg, nonce):
    # Create a ChaCha20 cipher object with the given key and nonce
    cipher = ChaCha20.new(key=randkey, nonce=long_to_bytes(nonce))
    # Update the nonce with a new random value (96 bits)
    nonce = random.getrandbits(12*8)
    # Encrypt the message and return the ciphertext
    return cipher.encrypt(msg.encode())


def main():
    # Prompt the user to provide a seed value for initializing the random generator
    seed = int(input(
        "Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> "))
    random.seed(seed)  # Initialize the random generator with the provided seed
    nonce = random.getrandbits(12*8)  # Generate an initial random nonce (96 bits)

    print("OK! I can now give you the encrypted secret!")
    # Encrypt the flag and display the ciphertext in hexadecimal format
    print(encrypt_and_update(flag, nonce).hex())

    # Ask the user if they want to encrypt additional messages
    confirm = input("Do you want to encrypt something else? (y/n)")
    while confirm.lower() != 'n':  # Continue until the user inputs 'n'
        if confirm.lower() == 'y':  # If the user inputs 'y', proceed to encrypt a message
            msg = input("What is the message? ")
            # Encrypt the user's message and display the ciphertext in hexadecimal format
            print(encrypt_and_update(msg, nonce).hex())
        # Ask again if the user wants to encrypt something else
        confirm = input("Do you want to encrypt something else? (y/n)")


if __name__ == '__main__':
    main()  # Entry point of the program

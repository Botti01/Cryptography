from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from random import randint
from secret import flag

# Ensure the flag length matches the expected format
assert (len(flag) == len("CRYPTO25{}") + 36)

key = get_random_bytes(24)  # Generate a random 24-byte key for AES encryption
padding = get_random_bytes(randint(1, 15))  # Generate random padding of length between 1 and 15 bytes
flag = flag.encode()  # Convert the flag to bytes


def encrypt() -> bytes:
    # Encrypts user-provided data along with padding and the flag
    data = bytes.fromhex(input("> ").strip())  # Read and decode user input as hexadecimal
    payload = padding + data + flag  # Construct the payload with padding, user data, and the flag

    cipher = AES.new(key=key, mode=AES.MODE_ECB)  # Create an AES cipher in ECB mode
    # print(cipher.encrypt(pad(payload, AES.block_size)).hex())  
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())  # Encrypt and print the result in hex


def main():
    # Display a menu and handle user commands
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip()  # Read user input and strip whitespace

        if cmd == "quit":  # Exit the program
            break
        elif cmd == "help":  # Show the menu again
            continue
        elif cmd == "enc":  # Encrypt user-provided data
            encrypt()


if __name__ == '__main__':
    main()  # Run the main function

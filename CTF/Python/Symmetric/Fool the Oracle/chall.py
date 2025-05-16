from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from secret import flag

# Ensure the flag length matches the expected format
assert (len(flag) == len("CRYPTO25{}") + 36)

key = get_random_bytes(24)  # Generate a random 24-byte key for AES encryption
flag = flag.encode()  # Convert the flag to bytes


def encrypt() -> bytes:
    # Read user input as a hex string and convert it to bytes
    data = bytes.fromhex(input("> "))
    payload = data + flag  # Append the flag to the user-provided data

    cipher = AES.new(key=key, mode=AES.MODE_ECB)  # Create an AES cipher in ECB mode
    # Encrypt the padded payload and print the result as a hex string
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())
    # print(cipher.encrypt(pad(payload, AES.block_size)))


def main():
    # Display the menu options to the user
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip()  # Read and sanitize user input

        if cmd == "quit":  # Exit the program
            break
        elif cmd == "help":  # Show the menu again
            continue
        elif cmd == "enc":  # Trigger the encryption function
            encrypt()


if __name__ == '__main__':
    main()  # Start the program

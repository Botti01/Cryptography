from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from random import randint
from secret import flag

# Ensure the flag has the expected length (prefix + 36 bytes)
assert (len(flag) == len("CRYPTO25{}") + 36)

# Generate a random 24-byte AES key (for AES-192)
key = get_random_bytes(24)
# Randomly choose the length of the first padding (between 1 and 6 bytes)
padding1_len = randint(1, 6)
# Generate the first random padding
padding1 = get_random_bytes(padding1_len)
# Generate the second random padding so that total padding is 10 bytes
padding2 = get_random_bytes(10 - padding1_len)
# Convert the flag to bytes
flag = flag.encode()


def encrypt() -> bytes:
    # Read user input as a hex string and convert to bytes
    data = bytes.fromhex(input("> ").strip())
    # Construct the payload: random padding1 + user data + random padding2 + flag
    payload = padding1 + data + padding2 + flag

    # Create AES cipher in ECB mode with the random key
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    # Pad the payload to the AES block size and encrypt it
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())


def main():
    # Display the menu options to the user
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        # Read user command
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "enc":
            # Call the encrypt function if user chooses 'enc'
            encrypt()


if __name__ == '__main__':
    # Start the main program loop
    main()

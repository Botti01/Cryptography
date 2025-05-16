from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from secret import flag
import json
import base64

# Generate a random 256-bit key for ChaCha20 encryption
key = get_random_bytes(32)


def make_cipher():
    # Create a new ChaCha20 cipher instance with a random nonce
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce, cipher


def get_user_token(name):
    # Generate a token for the user containing their username
    nonce, cipher = make_cipher()
    token = json.dumps({
        "username": name  # Store the username in the token
    })
    # print(token)  
    enc_token = cipher.encrypt(token.encode())
    # Return the nonce and encrypted token, both base64-encoded
    return f"{base64.b64encode(nonce).decode()}.{base64.b64encode(enc_token).decode()}"


def check_user_token(token):
    # Verify the provided token by decrypting it
    nonce, token = token.split(".")
    nonce = base64.b64decode(nonce)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    dec_token = cipher.decrypt(base64.b64decode(token))

    # Parse the decrypted token as JSON
    user = json.loads(dec_token)

    # Check if the user has admin privileges
    if user.get("admin", False) == True:
        return True
    else:
        return False


def get_flag():
    # Prompt the user for their token and validate it
    token = input("What is your token?\n> ").strip()
    if check_user_token(token):
        print("You are admin!")
        print(f"This is your flag!\n{flag}")  # Display the flag if the user is admin
    else:
        print("HEY! WHAT ARE YOU DOING!?")  # Reject non-admin users
        exit(1)


if __name__ == "__main__":
    # Ask the user for their name and generate a token
    name = input("Hi, please tell me your name!\n> ").strip()
    token = get_user_token(name)
    print("This is your token: " + token)

    # Provide a menu for the user to interact with the program
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break  # Exit the program
        elif cmd == "help":
            continue  # Show the menu again
        elif cmd == "flag":
            get_flag()  # Attempt to retrieve the flag

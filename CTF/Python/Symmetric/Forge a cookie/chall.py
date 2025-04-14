from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from secret import flag
import json
import base64

key = get_random_bytes(32)


def make_cipher():
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce, cipher


def get_user_token(name):
    nonce, cipher = make_cipher()
    token = json.dumps({
        "username": name
    })
    print(token)
    enc_token = cipher.encrypt(token.encode())
    return f"{base64.b64encode(nonce).decode()}.{base64.b64encode(enc_token).decode()}"


def check_user_token(token):
    nonce, token = token.split(".")
    nonce = base64.b64decode(nonce)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    dec_token = cipher.decrypt(base64.b64decode(token))

    user = json.loads(dec_token)

    if user.get("admin", False) == True:
        return True
    else:
        return False


def get_flag():
    token = input("What is your token?\n> ").strip()
    if check_user_token(token):
        print("You are admin!")
        print(f"This is your flag!\n{flag}")
    else:
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)


if __name__ == "__main__":
    name = input("Hi, please tell me your name!\n> ").strip()
    token = get_user_token(name)
    print("This is your token: " + token)

    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "flag":
            get_flag()

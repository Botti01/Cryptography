from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from secret import flag

key = get_random_bytes(32)


def sanitize_field(field: str):
    return field \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")


def parse_cookie(cookie: str) -> dict:
    parsed = {}
    for field in cookie.split("&"):
        key, value = field.strip().split("=")
        key = sanitize_field(key.strip())
        value = sanitize_field(value.strip())
        parsed[key] = value

    return parsed


def login():
    username = input("Username: ")
    username = sanitize_field(username)

    cipher = AES.new(key, AES.MODE_ECB)

    cookie = f"username={username}&admin=false"

    print(bytes_to_long(cipher.encrypt(pad(cookie.encode(), AES.block_size))))


def get_flag():
    cookie = int(input("Cookie: "))

    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    try:
        dec_cookie = unpad(cipher.decrypt(
            long_to_bytes(cookie)), AES.block_size).decode()
        token = parse_cookie(dec_cookie)

        if token["admin"] != 'true':
            print("You are not an admin!")
            return

        print(f"OK! Your flag: {flag}")
    except:
        print("Something didn't work :C")


if __name__ == "__main__":
    login()

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

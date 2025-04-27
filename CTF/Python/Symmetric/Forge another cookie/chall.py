from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from secret import flag

key = get_random_bytes(32)  # Generate a random 256-bit key for AES encryption


def sanitize_field(field: str):
    # Sanitize input by removing or replacing potentially dangerous characters
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
    # Parse a cookie string into a dictionary of sanitized key-value pairs
    parsed = {}
    for field in cookie.split("&"):
        key, value = field.strip().split("=")
        key = sanitize_field(key.strip())
        value = sanitize_field(value.strip())
        parsed[key] = value

    return parsed


def login():
    # Handle user login and generate an encrypted cookie
    username = input("Username: ")
    username = sanitize_field(username)

    cipher = AES.new(key, AES.MODE_ECB)  # Initialize AES cipher in ECB mode

    cookie = f"username={username}&admin=false"  # Default cookie with admin=false

    # Encrypt the cookie and print it as a long integer
    print(bytes_to_long(cipher.encrypt(pad(cookie.encode(), AES.block_size))))


def get_flag():
    # Validate the cookie and check if the user is an admin to retrieve the flag
    cookie = int(input("Cookie: "))

    cipher = AES.new(key=key, mode=AES.MODE_ECB)  # Initialize AES cipher in ECB mode

    try:
        # Decrypt and unpad the cookie
        dec_cookie = unpad(cipher.decrypt(
            long_to_bytes(cookie)), AES.block_size).decode()
        token = parse_cookie(dec_cookie)  # Parse the decrypted cookie

        # Check if the user is an admin
        if token["admin"] != 'true':
            print("You are not an admin!")
            return

        # If admin, print the flag
        print(f"OK! Your flag: {flag}")
    except:
        # Handle decryption or parsing errors
        print("Something didn't work :C")


if __name__ == "__main__":
    login()  # Prompt the user to log in

    # Display the menu and handle user commands
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

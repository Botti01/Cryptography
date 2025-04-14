from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import flag

key = get_random_bytes(16)
leak = b"mynamesuperadmin"


def make_cipher():
    IV = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    return IV, cipher


def encrypt():
    string = input("What do you want to encrypt?\n> ")
    string = bytes.fromhex(string)
    if len(string) != 16:
        print("Sorry, you can encrypt only 16 bytes!")
        return

    if leak == string:
        print("Sorry, you can't encrypt that!")
        return

    IV, cipher = make_cipher()
    encrypted = cipher.encrypt(string)

    print(F"IV: {IV.hex()}\nEncrypted: {encrypted.hex()}\n")


def decrypt():
    string = input("What do you want to decrypt?\n> ")
    string = bytes.fromhex(string)

    IV = input("Gimme the IV\n> ")
    IV = bytes.fromhex(IV)

    if (IV == leak):
        print("Nice try...")
        return

    cipher = AES.new(key, AES.MODE_CBC, IV=IV)

    decrypted = cipher.decrypt(string)
    if leak == decrypted:
        print(f"Good job. Your flag: {flag}")
    else:
        print(f"Mh, a normal day.\nDecrypted: {decrypted.hex()}")


if __name__ == '__main__':
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "dec - decrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "enc":
            encrypt()
        elif cmd == "dec":
            decrypt()

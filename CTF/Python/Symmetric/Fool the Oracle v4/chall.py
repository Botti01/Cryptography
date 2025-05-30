from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from random import randint
from secret import flag

assert (len(flag) == len("CRYPTO25{}") + 36)

key = get_random_bytes(24)
padding1_len = randint(1, 6)
padding1 = get_random_bytes(padding1_len)
padding2 = get_random_bytes(10 - padding1_len)
flag = flag.encode()


def encrypt() -> bytes:
    data = bytes.fromhex(input("> ").strip())
    payload = padding1 + data + padding2 + flag

    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())


def main():
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
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


if __name__ == '__main__':
    main()

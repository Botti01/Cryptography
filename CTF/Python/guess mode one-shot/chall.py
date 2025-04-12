# see note info on smartphone

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import flag
import random

modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}


class RandomCipherRandomMode():
    def __init__(self):
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes)
        self.key = get_random_bytes(32)
        if self.mode == AES.MODE_ECB:
            self.iv = None
            self.cipher = AES.new(key=self.key, mode=self.mode)
        else:
            self.iv = get_random_bytes(16)
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        return self.cipher.decrypt(data)


def main():

    for i in range(128):
        cipher = RandomCipherRandomMode()

        print(f"Challenge #{i}")

        otp = get_random_bytes(32)
        print(f"The otp I'm using: {otp.hex()}")
        data = bytes.fromhex(input("Input: ").strip())
        if len(data) != 32:
            print("Data must be 32 bytes long")
            return

        data = bytes([d ^ o for d, o in zip(data, otp)])
        print(f"Output: {cipher.encrypt(data).hex()}")

        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next")
        else:
            print("Wrong, sorry")
            return

    print(f"The flag is: {flag}")


if __name__ == "__main__":
    main()

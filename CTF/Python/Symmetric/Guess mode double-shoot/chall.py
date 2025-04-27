from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import flag
import random

# Mapping of mode names to their corresponding AES mode constants
modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}


class RandomCipherRandomMode():
    def __init__(self):
        # Randomly select between ECB and CBC modes
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes)
        self.key = get_random_bytes(32)  # Generate a random 256-bit key
        if self.mode == AES.MODE_ECB:
            self.iv = None  # ECB mode does not use an IV
            self.cipher = AES.new(key=self.key, mode=self.mode)
        else:
            self.iv = get_random_bytes(16)  # Generate a random 128-bit IV for CBC mode
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)

    def encrypt(self, data):
        # Encrypt the provided data using the initialized cipher
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        # Decrypt the provided data using the initialized cipher
        return self.cipher.decrypt(data)


def main():

    for i in range(128):  # Loop through 128 challenges
        cipher = RandomCipherRandomMode()  # Create a new cipher with a random mode

        print(f"Challenge #{i}")

        data = b"\00"*32  # Initialize data with 32 null bytes

        otp = get_random_bytes(len(data))  # Generate a one-time pad of the same length as data

        for _ in range(2):  # Allow two attempts to encrypt and guess the mode
            data = bytes.fromhex(input("Input: ").strip())  # Read user input as hex
            if len(data) != 32:  # Ensure the input is exactly 32 bytes
                print("Data must be 32 bytes long")
                return

            # XOR the input data with the one-time pad
            data = bytes([d ^ o for d, o in zip(data, otp)])
            print(f"Output: {cipher.encrypt(data).hex()}")  # Encrypt and print the result

        # Ask the user to guess the mode used
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next")  # Correct guess
        else:
            print("Wrong, sorry")  # Incorrect guess
            return

    # If all challenges are passed, reveal the flag
    print(f"The flag is: {flag}")


if __name__ == "__main__":
    main()

# see note info on smartphone

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
        # Initialize the cipher with a random mode (either ECB or CBC)
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes)        # Randomly choose a mode
        self.key = get_random_bytes(32)         # Generate a random 256-bit key

        # Configure the cipher based on the chosen mode
        if self.mode == AES.MODE_ECB:
            self.iv = None  # ECB mode does not use an IV
            self.cipher = AES.new(key=self.key, mode=self.mode)  # Create AES cipher in ECB mode
        else:
            self.iv = get_random_bytes(16)  # Generate a random 128-bit IV for CBC mode
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)  # Create AES cipher in CBC mode

    def encrypt(self, data):
        # Encrypt the provided data using the configured cipher
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        # Decrypt the provided data using the configured cipher
        return self.cipher.decrypt(data)


def main():
    # Main function to handle the challenge logic

    for i in range(128):  # Loop through 128 challenges
        cipher = RandomCipherRandomMode()  # Create a new cipher with a random mode

        print(f"Challenge #{i}")

        # Generate a random one-time pad (OTP) for XOR operation
        otp = get_random_bytes(32)
        print(f"The otp I'm using: {otp.hex()}")  # Display the OTP in hexadecimal format

        # Get user input and ensure it is 32 bytes long
        data = bytes.fromhex(input("Input: ").strip())
        if len(data) != 32:
            print("Data must be 32 bytes long")  # Input validation
            return

        # XOR the input data with the OTP
        data = bytes([d ^ o for d, o in zip(data, otp)])
        # Encrypt the XORed data and display the result in hexadecimal format
        print(f"Output: {cipher.encrypt(data).hex()}")

        # Ask the user to guess the mode used by the cipher
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        # Check if the user's guess matches the actual mode
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next")  # Correct guess
        else:
            print("Wrong, sorry")  # Incorrect guess
            return

    # If the user successfully completes all challenges, reveal the flag
    print(f"The flag is: {flag}")


if __name__ == "__main__":
    main()

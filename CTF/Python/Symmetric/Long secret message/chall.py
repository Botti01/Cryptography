import os
from Crypto.Cipher import ChaCha20

# Generate a random 256-bit key and a 96-bit nonce
key = os.urandom(32)
nonce = os.urandom(12)
print(f"Using key: {key.hex()}, nonce: {nonce.hex()}")  # Display the key and nonce for debugging purposes

# Read the content of the file line by line
with open("./hacker-manifesto.txt") as f:
    lines = f.readlines()

enc = []  # List to store the encrypted lines

# Encrypt each line of the file using ChaCha20
for line in lines:
    cipher = ChaCha20.new(key=key, nonce=nonce)  # Create a new cipher instance for each line
    enc.append(cipher.encrypt(line.encode()).hex())  # Encrypt the line and store its hex representation

# Write the encrypted lines to a new file
with open("./hacker-manifesto.enc", "w") as f:
    f.write("\n".join(enc))

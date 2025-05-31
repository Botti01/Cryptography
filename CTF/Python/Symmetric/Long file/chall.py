import os
from Crypto.Cipher import ChaCha20

# Generate a random 32-byte key and 12-byte nonce for ChaCha20 encryption
key = os.urandom(32)
nonce = os.urandom(12)
print(f"Using key: {key.hex()}, nonce: {nonce.hex()}")

# Read the plaintext data from 'bigfile.txt' and encode it as bytes
with open("./bigfile.txt", "r") as f:
    data = f.read().encode()

KEYSTREAM_SIZE = 1000  # Define the size of the keystream block

# Initialize the ChaCha20 cipher with the generated key and nonce
cipher = ChaCha20.new(key=key, nonce=nonce)

# Generate a keystream by encrypting a block of null bytes
keystream = bytes([x ^ y for x, y in zip(
    b"\00"*KEYSTREAM_SIZE, cipher.encrypt(b"\00"*KEYSTREAM_SIZE))])

print(len(data))  # Print the length of the plaintext data

# Encrypt the data in chunks using the generated keystream and write to 'file.enc'
with open("./file.enc", "wb") as f:
    for i in range(0, len(data), KEYSTREAM_SIZE):
        # XOR each chunk of plaintext with the keystream to produce ciphertext
        f.write(
            bytes([p ^ k for p, k in zip(data[i:i+KEYSTREAM_SIZE], keystream)]))

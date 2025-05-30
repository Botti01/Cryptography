import os
from Crypto.Cipher import ChaCha20


key = os.urandom(32)
nonce = os.urandom(12)
print(f"Using key: {key.hex()}, nonce: {nonce.hex()}")

with open("./bigfile.txt", "r") as f:
    data = f.read().encode()

KEYSTREAM_SIZE = 1000

cipher = ChaCha20.new(key=key, nonce=nonce)


keystream = bytes([x ^ y for x, y in zip(
    b"\00"*KEYSTREAM_SIZE, cipher.encrypt(b"\00"*KEYSTREAM_SIZE))])

print(len(data))

with open("./file.enc", "wb") as f:
    for i in range(0, len(data), KEYSTREAM_SIZE):
        f.write(
            bytes([p ^ k for p, k in zip(data[i:i+KEYSTREAM_SIZE], keystream)]))

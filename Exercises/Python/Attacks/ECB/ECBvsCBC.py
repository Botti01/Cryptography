# ECBvsCBC.py (server)
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

from myconfig import HOST, PORT
from mysecret import ecb_oracle_key

# Modalità di cifratura
ECB_MODE = 0
CBC_MODE = 1

# Creazione e bind della socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("socket created")
try:
    s.bind((HOST, PORT))
except socket.error as e:
    print(f"Bind failed. Errno: {e.errno}, Message: {e.strerror}")
    sys.exit()
print("Socket bind complete")

# Messa in ascolto
s.listen(10)
print("Socket now listening")

# Loop di accettazione connessioni
while True:
    conn, addr = s.accept()
    print("Connessione da", addr)
    data = conn.recv(1024)
    if not data:
        conn.close()
        continue

    # Scelta pseudo-casuale tra ECB e CBC
    if get_random_bytes(1)[0] % 2 == ECB_MODE:
        mode = AES.MODE_ECB
        cipher = AES.new(ecb_oracle_key, mode)
    else:
        mode = AES.MODE_CBC
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(ecb_oracle_key, mode, iv=iv)

    # Cifratura e invio
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    conn.send(ciphertext)
    conn.close()

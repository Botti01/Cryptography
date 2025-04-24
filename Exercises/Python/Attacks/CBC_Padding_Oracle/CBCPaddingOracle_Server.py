import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from mysecrets import cbc_oracle_key as key  # Import the secret key for AES decryption
from myconfig import HOST, PORT  # Import host and port configuration


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
print('Socket created')

try:
    s.bind((HOST, PORT))  # Bind the socket to the specified host and port
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])  # Handle binding errors
    sys.exit()
print('Socket bind complete')

s.listen(10)  # Start listening for incoming connections (max 10 queued connections)
print('Socket now listening')

# Wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()  # Accept a new connection
    print('A new padding test requested by ' + addr[0] + ':' + str(addr[1]))

    # Get the IV from the client
    iv = conn.recv(AES.block_size)
    # Get the ciphertext from the client
    ciphertext = conn.recv(1024)

    # Decrypt the ciphertext using AES in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        # Attempt to unpad the decrypted plaintext to verify padding correctness
        unpad(cipher.decrypt(ciphertext), AES.block_size)
        # PKCS#5 padding validation
    except ValueError:
        # If padding is invalid, notify the client and continue
        conn.send(b'NO')
        continue

    # If padding is valid, notify the client
    conn.send(b'OK')

    conn.close()  # Close the connection with the client

s.close()  # Close the server socket

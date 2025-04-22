import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

from mysecrets import ecb_oracle_key  # Import the secret key for encryption
from myconfig import HOST, PORT  # Import server configuration (host and port)

ECB_MODE = 0  # Constant for ECB mode
CBC_MODE = 1  # Constant for CBC mode

# Create a TCP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

# Bind the socket to the specified host and port
try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

# Start listening for incoming connections
s.listen(10)
print('Socket now listening')

# Main server loop to handle encryption requests
while 1:
    conn, addr = s.accept()  # Accept a new connection
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    # Randomly select a mode of operation: ECB or CBC
    selected_mode = getrandbits(1)
    print("Selected mode = ", end='')
    if selected_mode == ECB_MODE:
        print("ECB")
    else:
        print("CBC")

    # Receive plaintext input from the client
    input0 = conn.recv(1024).decode()
    message = "This is what I received: " + input0 + " -- END OF MESSAGE"
    print("Plaintext: " + message)

    # Initialize the cipher based on the selected mode
    if selected_mode == ECB_MODE:
        cipher = AES.new(ecb_oracle_key, AES.MODE_ECB)
    else:
        cipher = AES.new(ecb_oracle_key, AES.MODE_CBC)

    # Encrypt the padded plaintext
    message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(message)

    # Send the ciphertext back to the client
    conn.send(ciphertext)

    # Close the connection with the client
    conn.close()

# Close the server socket (unreachable in this loop)
s.close()

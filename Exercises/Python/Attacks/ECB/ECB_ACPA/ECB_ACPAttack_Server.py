import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from mysecrets import ecb_oracle_key,ecb_oracle_secret  # Importing secret key and secret message
from myconfig import HOST, PORT  # Importing host and port configuration


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creating a TCP socket
print('Socket created')

try:
    s.bind((HOST, PORT))  # Binding the socket to the specified host and port
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

s.listen(10)  # Start listening for incoming connections, with a backlog of 10
print('Socket now listening')

# Wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()  # Accept a new connection
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    input0 = conn.recv(1024).decode()  # Receive input from the client

    # Construct the message by appending the secret to the client input
    message = """Here is the msg:{0} - and the sec:{1}""".format( input0, ecb_oracle_secret)
    message = pad(message.encode(),AES.block_size)  # Pad the message to match AES block size
    cipher = AES.new( ecb_oracle_key, AES.MODE_ECB )  # Create an AES cipher in ECB mode
    ciphertext = cipher.encrypt(message)  # Encrypt the padded message

    conn.send(ciphertext)  # Send the ciphertext back to the client

    conn.close()  # Close the connection with the client

s.close()  # Close the socket

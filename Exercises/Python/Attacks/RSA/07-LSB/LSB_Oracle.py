import socket
import sys
from myconfig import HOST, PORT
from mysecrets import lsb_n as n, lsb_d as d

# Create a TCP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

try:
    # Bind the socket to the host and port specified in myconfig
    s.bind((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

# Listen for incoming connections (up to 10 in the queue)
s.listen(10)
print('Socket now listening')

# Main server loop: handle incoming connections one at a time
while 1:
    # Accept a new connection
    conn, addr = s.accept()
    print('A new RSA encrypted message received from ' + addr[0] + ':' + str(addr[1]))

    # receive the ciphertext
    ciphertext = conn.recv(4096)
    c = int.from_bytes(ciphertext, byteorder='big')
    # decrypt it
    # Compute the plaintext by RSA decryption and extract its least significant bit (LSB)
    lsb = pow(c, d, n) % 2
    # leak the LSB
    print(lsb)
    # Send the LSB back to the client as a single byte
    conn.send(int.to_bytes(lsb, 1, byteorder='big'))
    conn.close()

# Close the socket (unreachable code in this infinite loop)
s.close()
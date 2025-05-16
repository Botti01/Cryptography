import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

from myconfig import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

# Converts an integer to bytes, using the bit length of n by default
def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

# Converts bytes to an integer
def to_int(b):
    return int.from_bytes(b,byteorder='big')

# Prints the current lower and upper bounds of the plaintext interval
def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

# Test the connection with the server by sending the ciphertext and receiving a response
server = remote(HOST, PORT)
server.send(ciphertext.to_bytes(n.bit_length(),byteorder='big'))
bit = server.recv(1024)
print(bit)
server.close()

# Initialize the bounds for the plaintext interval
upper_bound = n
lower_bound = 0
print_bounds(lower_bound,upper_bound)

# Main loop: Perform the LSB oracle attack to recover the plaintext bit by bit
m = ciphertext
for i in range(n.bit_length()):
    # Multiply ciphertext by 2^e mod n to shift plaintext bits left
    m = (pow(2, e, n) * m) % n

    # Interact with the server: send the modified ciphertext and receive the LSB of the plaintext
    server = remote(HOST, PORT)
    server.send(to_bytes(m))
    bit = server.recv(1024)
    server.close()
    print(bit)

    # Update bounds based on the leaked LSB (bit[0])
    if  bit[0] == 1:
        # If LSB is 1, plaintext is in the upper half of the interval
        lower_bound = (upper_bound + lower_bound) // 2
    else:
        # If LSB is 0, plaintext is in the lower half of the interval
        upper_bound = (upper_bound + lower_bound) // 2
    print_bounds(lower_bound, upper_bound)

# Print the decoded plaintext message after the attack completes
print(to_bytes(lower_bound,n.bit_length()).decode())

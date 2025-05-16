# Configuration patch to allow pwntools to be run inside of an IDE
import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwnlib.tubes.remote import remote

# package for arbitrary precision floating point numbers
import decimal

# import attack data (RSA parameters and ciphertext)
from myconfig import HOST,PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

# Useful functions for byte/int conversion
def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

def to_int(b):
    return int.from_bytes(b,byteorder='big')

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

# Start with the ciphertext as the initial message
m = ciphertext

# define the upper bound with decimal
decimal.getcontext().prec = n.bit_length()
lower_bound = decimal.Decimal(0)
upper_bound = decimal.Decimal(n)
print_bounds(lower_bound,upper_bound)

# Main loop: Perform the LSB Oracle attack to recover the plaintext
# For each bit of the modulus, query the oracle and update the bounds
for i in range(n.bit_length()):

    # Multiply ciphertext by 2^e mod n to shift plaintext bits
    m = (pow(2, e, n) * m) % n
    server = remote(HOST, PORT)  # Connect to the LSB oracle server
    server.send(to_bytes(m))     # Send the modified ciphertext
    bit = server.recv(1024)      # Receive the LSB from the oracle
    server.close()
    print(bit)

    # Update bounds based on the oracle's response
    if  bit[0] == 1:
        lower_bound = (upper_bound + lower_bound) / 2
    else:
        upper_bound = (upper_bound + lower_bound) / 2
    print_bounds(lower_bound, upper_bound)

# Print the number of bits, the recovered plaintext as integer, and as decoded string
print(n.bit_length())
print(int(upper_bound))
print(to_bytes(int(upper_bound),n.bit_length()).decode())


import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from math import ceil
from Crypto.Cipher import AES

from myconfig import HOST,PORT

BLOCK_SIZE = AES.block_size  # AES block size in bytes
BLOCK_SIZE_HEX = 2*BLOCK_SIZE  # Block size in hexadecimal representation

server = remote(HOST, PORT)  # Connect to the remote server

# stole from the server code...
# message = "This is what I received: " + msg + " -- END OF MESSAGE"
start_str = "This is what I received: "
# print(len(start_str))
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str)  # Calculate padding length to align with block size

msg = b"A"*(16*2+pad_len)  # Construct the message to send (2 blocks of 'A' + padding)
print("Sending: "+str(msg))
server.send(msg)  # Send the crafted message to the server

ciphertext = server.recv(1024)  # Receive the ciphertext from the server
ciphertext_hex = ciphertext.hex()  # Convert the ciphertext to hexadecimal format
print(ciphertext_hex)

server.close()  # Close the connection to the server

# Split the ciphertext into blocks and print each block
for i in range(0,int(len(ciphertext_hex)//BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])

# Determine the encryption mode based on repeated blocks in the ciphertext
print("Selected mode is", end=' ')
if ciphertext[2*BLOCK_SIZE:3*BLOCK_SIZE] == ciphertext[3*BLOCK_SIZE:4*BLOCK_SIZE] :
    print("ECB")  # ECB mode detected (repeated blocks)
else:
    print("CBC")  # CBC mode detected (no repeated blocks)

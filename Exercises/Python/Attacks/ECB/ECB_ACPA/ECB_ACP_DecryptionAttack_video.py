import os
import string
from math import ceil

from Crypto.Cipher import AES

os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from myconfig import HOST, PORT

if __name__ == '__main__':
    # server = remote(HOST,PORT)
    # message = b"A"*10
    # server.send(message)
    # ciphertext = server.recv(1024)
    # server.close()
    # print(ciphertext.hex())
    # print(len(ciphertext))

    # message = """Here is the msg:{0} - and the sec:{1}""".format(input0, ecb_oracle_secret)
    prefix = b'Here is the msg:'  # Prefix used in the message format
    postfix = b' - and the sec:'  # Postfix used in the message format
    print(len(prefix))  # Print the length of the prefix
    print(len(postfix))  # Print the length of the postfix

    # for guess in string.printable:
    #     message = postfix + guess.encode()
    #     full_string = prefix + message + postfix + b'?'
    #     print(full_string)
    #     for i in range(ceil(len(full_string)/AES.block_size)):
    #         print(full_string[i*16:(i+1)*16])

    # Brute-force the first character of the secret by checking for repeated ciphertext blocks
    for guess in string.printable:
        message = postfix + guess.encode()  # Append the guess to the postfix
        server = remote(HOST, PORT)  # Connect to the remote server
        server.send(message)  # Send the crafted message
        ciphertext = server.recv(1024)  # Receive the ciphertext
        server.close()  # Close the connection
        if ciphertext[16:32] == ciphertext[32:48]:  # Check for repeated blocks
            print("Found 1st char=" + guess)  # Print the found character
            break

    # for guess in string.printable:
    #     message = postfix[1:] + b'H' + guess.encode() + b'A'*(AES.block_size-1)
    #     full_string = prefix + message + postfix + b'??'
    #     print(full_string)
    #     for i in range(ceil(len(full_string)/AES.block_size)):
    #         print(full_string[i*16:(i+1)*16])

    secret = b''  # Initialize the secret as an empty byte string
    for i in range(AES.block_size):  # Iterate over the block size to recover the secret
        pad = (AES.block_size - i) * b'A'  # Create padding to align the block
        for guess in string.printable:  # Iterate over all printable characters
            message = postfix + secret + guess.encode() + pad  # Construct the message
            print(message)  # Print the crafted message

            server = remote(HOST, PORT)  # Connect to the remote server
            server.send(message)  # Send the crafted message
            ciphertext = server.recv(1024)  # Receive the ciphertext
            server.close()  # Close the connection

            if ciphertext[16:32] == ciphertext[48:64]:  # Check for repeated blocks
                print("Found=" + guess)  # Print the found character
                secret += guess.encode()  # Append the found character to the secret
                postfix = postfix[1:]  # Remove the first byte of the postfix
                break
    print(secret)  # Print the recovered secret

import os
# Set environment variables to suppress pwntools terminal output
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

# Import configuration and data for the attack
from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext

from Crypto.Cipher import AES

if __name__ == '__main__':
    # Code for interacting with the server is commented out for now
    # server = remote(HOST,PORT)
    # server.send(iv)
    # server.send(ciphertext)
    # response = server. recv(1024)
    # print(response)
    # server.close()

    # server = remote(HOST,PORT)
    # server.send(iv)
    #
    # edt = bytearray(ciphertext)
    # edt[-1] = 0
    #
    # server.send(edt)
    # response = server. recv(1024)
    # print(response)
    # server.close()

#---------------------------------------------
    # Calculate the number of AES blocks in the ciphertext
    print(len(ciphertext)//AES.block_size)
    N = len(ciphertext)//AES.block_size

    # Split the ciphertext into parts for the attack
    initial_part = ciphertext[:(N-2)*AES.block_size]  # All blocks except the last two
    block_to_modify = bytearray(ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size])  # Second-to-last block
    last_block = ciphertext[(N-1)*AES.block_size:]  # Last block

    # Start with the last byte of the second-to-last block
    byte_index = AES.block_size - 1
    c_15 = block_to_modify[byte_index]  # Original value of the last byte in the block

    # Attempt to find the correct padding byte by brute-forcing c_prime_15
    for c_prime_15 in range(256):
        block_to_modify[byte_index] = c_prime_15  # Modify the last byte
        to_send = initial_part + block_to_modify + last_block  # Construct the modified ciphertext

        # Send the modified ciphertext to the server
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        # print(response)  # Uncomment to debug server responses
        server.close()

        # Check if the server indicates valid padding
        if response == b'OK':
            print("c_prime_15="+str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 1  # Calculate intermediate plaintext byte
            p_15 = p_prime_15 ^ c_15  # Recover the original plaintext byte
            print("p_prime_15=" + str(p_prime_15))
            print("p_15=" + str(p_15))

    # Assume p_prime_15 is known from the previous step
    p_prime_15 = 191
    print("---------------")

    # Modify the second-to-last byte to prepare for the next byte recovery
    c_second_15 = p_prime_15 ^ 2  # Adjust for padding value 2
    block_to_modify[byte_index] = c_second_15

    # Move to the second-to-last byte in the block
    byte_index -= 1
    c_14 = block_to_modify[byte_index]  # Original value of the second-to-last byte

    # Attempt to find the correct padding byte by brute-forcing c_prime_14
    for c_prime_14 in range(256):
        block_to_modify[byte_index] = c_prime_14  # Modify the second-to-last byte
        to_send = initial_part + block_to_modify + last_block  # Construct the modified ciphertext

        # Send the modified ciphertext to the server
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        server.close()

        # Check if the server indicates valid padding
        if response == b'OK':
            print("c_prime_14="+str(c_prime_14))
            p_prime_14 = c_prime_14 ^ 2  # Calculate intermediate plaintext byte
            p_14 = p_prime_14 ^ c_14  # Recover the original plaintext byte
            print("p_prime_14=" + str(p_prime_14))
            print("p_14=" + str(p_14))

    print("---------------")

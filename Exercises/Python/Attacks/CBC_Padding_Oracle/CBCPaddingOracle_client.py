from Crypto.Cipher import AES
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *


from myconfig import HOST,PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext


def num_blocks(ciphertext, block_size):
    # Calculate the number of blocks in the ciphertext given the block size
    return math.ceil(len(ciphertext)/block_size)

#first block is 0
def get_nth_block(ciphertext, n, block_size):
    # Retrieve the nth block (0-indexed) from the ciphertext
    return ciphertext[(n)*block_size:(n+1)*block_size]

def get_n_blocks_from_m(ciphertext, n, m, block_size):
    # Retrieve n blocks starting from the mth block in the ciphertext
    return ciphertext[(m)*block_size:(m+n)*block_size]


def check_oracle_good_padding():
    # Test the oracle with valid padding and print the response
    server = remote(HOST, PORT)
    server.send(iv)
    server.send(ciphertext)
    response = server.recv(1024)
    server.close()
    print("Oracle said: "+response.decode())


def check_oracle_bad_padding():
    # Test the oracle with invalid padding and print the response
    server = remote(HOST, PORT)
    server.send(iv)
    c2 = bytearray()
    c2 += ciphertext[:-1]  # Modify the last byte to create invalid padding
    c2 += bytes([ciphertext[-1] ^ 1])
    server.send(c2)
    response = server.recv(1024)
    server.close()
    print("Oracle said: "+response.decode())

def guess_byte(p,c,ciphertext,block_size):
    # Attempt to guess a single byte of plaintext using the padding oracle
    # p and c must have the same length
    padding_value = len(p)+1
    print("pad="+str(padding_value))
    n = num_blocks(ciphertext,block_size)
    print("n="+str(n))
    current_byte_index= len(ciphertext)-1 -block_size - len(p)
    print("current="+str(current_byte_index))

    # print(p)
    # print(c)
    plain = b'\x00'
    for i in range(0,256):  # Iterate over all possible byte values
        # print(i)
        ca = bytearray()
        ca += ciphertext[:current_byte_index]  # Modify the current byte
        ca += i.to_bytes(1,byteorder='big')

        # print(ca)
        for x in p:  # Adjust previous bytes to maintain valid padding
            ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(ca)
        ca += get_nth_block(ciphertext,n-1,block_size)  # Append the last block
        # print(ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ca)
        response = server.recv(1024)

        # print(response)

        if response == b'OK':  # Check if the padding is valid
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i  # Calculate the plaintext byte
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == b'\x01': #this is not sufficient in the general case, onyl wokrs for the last byte and not always
                continue
            # print(p_prime)
            # print(ciphertext[current_byte_index])
            # print(p_prime ^ ciphertext[current_byte_index])
            c.insert(0,i)  # Update the guessed ciphertext
            p.insert(0,p_prime)  # Update the guessed plaintext
            # print(p)
            # print(type(p_prime))
            # x= bytes([p_prime ^ ciphertext[current_byte_index]])
            # break


    return plain

def guess_byte_first_block(p,c,ciphertext,block_size):
    # Attempt to guess a single byte of plaintext for the first block using the IV
    # p and c must have the same length
    padding_value = len(p)+1
    # print("pad="+str(padding_value))
    current_byte_index= block_size - len(p)-1
    # print("current="+str(current_byte_index))

    # print(p)
    # print(c)

    for i in range(0,256):  # Iterate over all possible byte values
        # print(i)
        iv_ca = bytearray()
        iv_ca += iv[:current_byte_index]  # Modify the current byte in the IV
        iv_ca += i.to_bytes(1,byteorder='big')

        # print(iv_ca)
        for x in p:  # Adjust previous bytes in the IV to maintain valid padding
            iv_ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(iv_ca)
        # iv_ca += get_nth_block(ciphertext,n-1,block_size)
        # print(iv_ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv_ca)
        server.send(ciphertext)
        response = server.recv(1024)
        server.close()
        # print(response)

        if response == b'OK':  # Check if the padding is valid
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i  # Calculate the plaintext byte
            c.insert(0,i)  # Update the guessed ciphertext
            p.insert(0,p_prime)  # Update the guessed plaintext
            break

    return bytes([p_prime ^ iv[current_byte_index]])
            # print(ciphertext[current_byte_index])
            # print(p2)
            # print(pn14)

if __name__ == '__main__':

    check_oracle_good_padding()  # Test the oracle with valid padding
    check_oracle_bad_padding()  # Test the oracle with invalid padding


    n = num_blocks(ciphertext,AES.block_size)  # Determine the number of blocks
    plaintext = bytearray()
    for i in range(1,n):  # Iterate over all blocks except the first
        c = []
        p = []

        for j in range(0,AES.block_size):  # Guess each byte of the block
            plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
            print(plaintext)
        ciphertext = ciphertext[:-AES.block_size]  # Remove the last block


    print(len(ciphertext))
    c = []
    p = []
    for i in range(0,AES.block_size):  # Guess each byte of the first block
        plaintext[0:0] = guess_byte_first_block(p,c,ciphertext,AES.block_size)
    # plaintext[0:0] = plain
    # plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
    print(plaintext)

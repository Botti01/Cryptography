from myconfig import HOST, PORT
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Disable terminal features for pwntools
os.environ['PWNLIB_SILENT'] = 'True'  # Suppress pwntools output

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from pwn import *

if __name__ == '__main__':

    # Code for interacting with the server (commented out for now)
    # server = remote(HOST,PORT)
    # username = b'aldo'
    # server.send(username)
    # enc_cookie = server.recv(1024)
    #
    # server.send(enc_cookie)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()
    #
    #
    # server = remote(HOST,PORT)
    # username = b'aldo'
    # server.send(username)
    # enc_cookie = server.recv(1024)
    # edt = bytearray(enc_cookie)
    # edt[-1] = 0
    #
    #
    # server.send(edt)
    # ans = server.recv(1024)
    # print(ans)
    # server.close()

    # Crafting a cookie with the username and admin flag set to 0
    username = b'aldooo11'
    cookie = pad(b'username=' + username + b',admin=0', AES.block_size)
    print(cookie)  # Display the padded cookie
    print(cookie[:16], end=' || ')  # Print the first block
    print(cookie[16:])  # Print the second block

    # Locate the position of the '0' in the admin flag within the second block
    index = cookie.index(b'0') - AES.block_size
    print(index)

    # Calculate the XOR mask to flip '0' to '1'
    mask = ord(b'1') ^ ord(b'0')

    # Interact with the server to perform the bit-flipping attack
    server = remote(HOST, PORT)
    server.send(username)  # Send the username to the server
    enc_cookie = server.recv(1024)  # Receive the encrypted cookie
    edt = bytearray(enc_cookie)  # Convert the encrypted cookie to a mutable bytearray
    edt[index] = edt[index] ^ mask  # Flip the bit to change 'admin=0' to 'admin=1'
    server.send(edt)  # Send the modified encrypted cookie
    ans = server.recv(1024)  # Receive the server's response
    print(ans)  # Print the server's response

# At the end we need to be able to send a cookie to the server that has the admin flag set to true

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from myconfig import HOST, PORT, DELTA_PORT

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from ECB_CopyPaste_server_genCookie_service import profile_for, encode_profile

if __name__ == '__main__':
    # Connect to the server responsible for generating encrypted cookies
    server_gencookies = remote(HOST, PORT)
    email = b'aaaaaaa@b.com'  # Email used to generate the initial cookie

    # Send the email to the server and receive the encrypted cookie
    server_gencookies.send(email)
    encrpyted_cookie = server_gencookies.recv(1024)
    print(encrpyted_cookie)

    # Generate and print the encoded profile for the given email
    cookie_info = encode_profile(profile_for(email.decode()))
    print(cookie_info)
    print(cookie_info[0:16])  # Print the first block of the encoded profile
    print(cookie_info[16:32])  # Print the second block of the encoded profile

    # Create a padded "admin" block to manipulate the cookie
    padded_admin = b'A'*10 + pad(b'admin', AES.block_size)
    cookie_info = encode_profile(profile_for(padded_admin.decode()))
    print(cookie_info[0:16])  # Print the first block of the padded admin profile
    print(cookie_info[16:32].encode())  # Print the second block of the padded admin profile
    server_gencookies.close()

    # Generate a new encrypted cookie using the padded admin block
    server_gencookies = remote(HOST, PORT)
    server_gencookies.send(padded_admin)
    encrpyted_cookie_2 = server_gencookies.recv(1024)
    server_gencookies.close()

    print(encrpyted_cookie_2)

    # Construct the final authentication cookie by combining blocks
    auth_cookie = encrpyted_cookie[0:32] + encrpyted_cookie_2[16:32]
    
    # Send the manipulated cookie to the server to test for admin access
    server_test = remote(HOST, PORT + DELTA_PORT)
    server_test.send(auth_cookie)
    answer = server_test.recv(1024)

    # Print the server's response
    print(answer.decode())

# First we need to create a service that will generate the cookie for us

import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
from mysecrets import ecb_oracle_key as key

from myconfig import HOST, PORT

###############################
def profile_for(email):
    # Simulates a DB access to get user data
    # Sanitizes the email input to prevent injection of special characters
    email = email.replace('=', '')
    email = email.replace('&', '')

    dict = {}
    dict["email"] = email
    dict["UID"] = 10  # Static UID for simplicity
    dict["role"] = "user"  # Default role is "user"
    return dict

###############################
def encode_profile(dict):
    # Generates the string from user data
    """
    :type dict: dictionary
    """
    s = ""
    i = 0
    n = len(dict.keys())  # Number of keys in the dictionary
    print(n)
    for key in dict.keys():
        s += key + "=" + str(dict[key])  # Concatenates key-value pairs
        if i < (n - 1):  # Adds '&' between key-value pairs except the last one
            s += "&"
            i += 1
    return s

###############################
def encrypt_profile(encoded_profile):
    # Encrypts the encoded profile using AES in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(), AES.block_size)  # Pads the plaintext to match block size
    print(plaintext)
    return cipher.encrypt(plaintext)

###############################
def decrypt_msg(ciphertext):
    # Decrypts the ciphertext using AES in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)  # Removes padding after decryption

if __name__ == '__main__':

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        s.bind((HOST, PORT))  # Binds the socket to the specified host and port
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    s.listen(10)  # Listens for incoming connections (up to 10 in the queue)
    print('Socket now listening')

    # Wait to accept a connection - blocking call
    while 1:
        conn, addr = s.accept()  # Accepts a new connection
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        email = conn.recv(1024)  # Receives the email from the client
        cookie = encrypt_profile(encode_profile(profile_for(email.decode())))  # Generates the encrypted cookie

        print("Cookie: " + encode_profile(profile_for(email.decode())))  # Logs the plaintext profile

        conn.send(cookie)  # Sends the encrypted cookie back to the client
        conn.close()  # Closes the connection

    s.close()  # Closes the socket

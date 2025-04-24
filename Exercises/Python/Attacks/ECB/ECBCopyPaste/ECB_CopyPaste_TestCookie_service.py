# Second we need to create a service that will accept the cookie and decrypt it

import sys
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from mysecrets import ecb_oracle_key as key
from myconfig import HOST,PORT,DELTA_PORT


###############################
def profile_for(email):
    # Sanitize the email input to prevent injection of special characters
    email=email.replace('=','')
    email=email.replace('&','')

    # Create a dictionary with user profile information
    dict = {}
    dict["email"] = email
    dict["UID"] = 10
    dict["role"] = "user"
    return dict


###############################
def encode_profile(dict):
    """
    :type dict: dictionary
    """
    # Serialize the dictionary into a URL-like query string
    s = ""
    i=0
    n = len(dict.keys())
    print(n)
    for key in dict.keys():
        s+=key+"="+str(dict[key])
        if i < (n-1):
            s+="&"
            i+=1
    return s

###############################

def encrypt_profile(encoded_profile):
    # Encrypt the encoded profile using AES in ECB mode
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(),AES.block_size)
    print(plaintext)
    return cipher.encrypt(plaintext)

###############################
def decrypt_msg(ciphertext):
    # Decrypt the ciphertext and remove padding
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext),AES.block_size)


if __name__ == '__main__':

    # Create a socket for communication
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        # Bind the socket to the specified host and port
        s.bind((HOST, PORT+DELTA_PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Start listening for incoming connections
    s.listen(10)
    print('Socket now listening')

    # Wait to accept a connection - blocking call
    while 1:
        conn, addr = s.accept()
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        # Receive the encrypted cookie from the client
        received_cookie = conn.recv(1024)
        cipher_dec = AES.new(key,AES.MODE_ECB)

        try:
            # Attempt to decrypt the received cookie
            decrypted = unpad(cipher_dec.decrypt(received_cookie),AES.block_size)
        except ValueError:
            # Handle incorrect padding errors
            print("Wrong padding")
            continue

        print(decrypted)

        # Check if the decrypted message contains admin privileges
        if b'role=admin' in decrypted:
            print("You are an admin!")
            conn.send("You are an admin!".encode())
        else:
            # Extract and display user information for normal users
            i1 = decrypted.index(b'=')
            i2 = decrypted.index(b',')
            msg = "welcome"+decrypted[i1:i2].decode('utf-8')
            print("You are a normal user")
            print(msg)
            conn.send(msg.encode())

        # Close the connection after processing
        conn.close()

# Close the socket when the server shuts down
s.close()

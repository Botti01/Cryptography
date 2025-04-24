from Crypto.Cipher import AES
import socket
import sys

from Crypto.Util.Padding import unpad, pad

from mysecrets import bf_key,bf_iv  # Import secret key and IV for AES encryption
from myconfig import HOST, PORT  # Import server configuration


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
print('Socket created')

try:
    s.bind((HOST, PORT))  # Bind the socket to the specified host and port
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

s.listen(10)  # Start listening for incoming connections
print('Socket now listening')


# until this point is just uninteresting socket programming
# wait to accept a connection - blocking call
while 1:
    try:
        conn, addr = s.accept()  # Accept a new client connection
        print("Bit flipping server. Connection from " + addr[0] + ":"+ str(addr[1]))

        # receives the username from the client
        username = conn.recv(1024)  # Receive username from the client
        cookie = b'username='+username+b',admin=0'  # Create a cookie with admin privileges set to 0
        print(cookie)

        # encrypt cookie info
        cipher = AES.new(bf_key,AES.MODE_CBC,bf_iv)  # Initialize AES cipher in CBC mode
        ciphertext = cipher.encrypt(pad(cookie,AES.block_size))  # Encrypt the cookie with padding

        #send the encrypted cookie to the client
        conn.send(ciphertext)  # Send the encrypted cookie back to the client
        print("...cookie sent.")


        ######
        # after a while, when the user wants to connect again
        # sends its cookie, the one previously received
        ######

        received_cookie = conn.recv(1024)  # Receive the cookie sent back by the client
        cipher_dec = AES.new(bf_key,AES.MODE_CBC,bf_iv)  # Initialize AES cipher for decryption
        decrypted = unpad(cipher_dec.decrypt(received_cookie),AES.block_size)  # Decrypt and unpad the cookie
        print(decrypted)

        # only the administrator will have the admin field set to 1
        # when they show back, we recognize them
        if b'admin=1' in decrypted:  # Check if the admin field is set to 1
            print("You are an admin!")
            conn.send("You are an admin!".encode())  # Notify the client of admin privileges
        else:
            i1 = decrypted.index(b'=')  # Find the start of the username value
            i2 = decrypted.index(b',')  # Find the end of the username value
            msg = "welcome"+decrypted[i1:i2].decode('utf-8')  # Construct a welcome message for normal users
            print("You are a normal user")
            print(msg)
            conn.send(msg.encode())  # Send the welcome message to the client
        conn.close()  # Close the connection with the client
    except Exception:
        conn.send(b'Errors!')  # Notify the client of an error
        conn.close()  # Close the connection in case of an error

s.close()  # Close the server socket

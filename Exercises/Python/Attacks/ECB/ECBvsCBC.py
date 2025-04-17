import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

from mysecrets import ecb_oracle_key
from myconfig import HOST, PORT


ECB_MODE = 0
CBC_MODE = 1

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print ("socket created")

try:
    s.bind((HOST, PORT))
except socket.error as e:
    print("Bind failed. Error Code: " + str(e[0]) + " Message: " + e[1])
    sys.exit()
print("Socket bind complete")

s.listen(10)
print ("Socket now listening")


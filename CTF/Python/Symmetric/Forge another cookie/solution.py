"""

Needless to say, you need the proper authorization cookie to get the flag

nc 130.192.5.212 6552

"""

from pwn import *
import sys

host = "130.192.5.212"
port = 6552

conn = remote(host, port)


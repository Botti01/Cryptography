"""

Read and understand the code. You'll easily find a way to forge the target cookie.

nc 130.192.5.212 6521

"""


from pwn import remote
import sys

host = "130.192.5.212"
port = 6521

conn = remote(host, port)

def recv_until_prompt(prompt):
    """Receives data until the specified prompt is found."""
    return conn.recvuntil(prompt.encode()).decode()



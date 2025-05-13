from Crypto.Hash import MD4
import hashlib
from binascii import unhexlify
from secret import flag


def md4(data: bytes) -> str:
    h = MD4.new()
    h.update(data)
    return h.hexdigest()


print("Find two strings that are both equal and different! I'll use _optimized algorithms_ to check.")

s1 = unhexlify(input("Enter the first string: "))
s2 = unhexlify(input("Enter your second string: "))

md4_s1 = md4(s1)
md4_s2 = md4(s2)

md5_s1 = hashlib.md5(s1).hexdigest()
md5_s2 = hashlib.md5(s2).hexdigest()

if md4_s1 == md4_s2 and md5_s1 != md5_s2:
    print(f"Good job! {flag}")
else:
    print("Try again!")

from Crypto.Hash import MD4
import hashlib
from binascii import unhexlify
from secret import flag

# Function to compute the MD4 hash of input data and return its hex digest
def md4(data: bytes) -> str:
    h = MD4.new()
    h.update(data)
    return h.hexdigest()

# Print challenge instructions to the user
print("Find two strings that are both equal and different! I'll use _optimized algorithms_ to check.")

# Read two hex-encoded strings from user input and decode them to bytes
s1 = unhexlify(input("Enter the first string: "))
s2 = unhexlify(input("Enter your second string: "))

# Compute MD4 hashes for both input strings
md4_s1 = md4(s1)
md4_s2 = md4(s2)

# Compute MD5 hashes for both input strings
md5_s1 = hashlib.md5(s1).hexdigest()
md5_s2 = hashlib.md5(s2).hexdigest()

# Check if the MD4 hashes are equal but the MD5 hashes are different
# If so, print the flag; otherwise, prompt to try again
if md4_s1 == md4_s2 and md5_s1 != md5_s2:
    print(f"Good job! {flag}")
else:
    print("Try again!")

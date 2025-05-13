from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag
p, q = getPrime(512), getPrime(512)
n = p*q
e = [31, 71]
print(n)
m = bytes_to_long(flag.encode())
print([pow(m, ee, n) for ee in e])

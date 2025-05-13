from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

n1 = getPrime(512)*getPrime(512)
n2 = getPrime(512)*getPrime(512)
n3 = getPrime(512)*getPrime(512)
n = [n1, n2, n3]
print(n)
e = 3
m = bytes_to_long(flag.encode())
print([pow(m, e, nn) for nn in n])

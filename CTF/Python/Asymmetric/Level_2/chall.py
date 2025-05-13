from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from secret import flag


def next_prime(p):
    while True:
        p = p+1
        if isPrime(p):
            return p


p = getPrime(512)
q = next_prime(p)
n = p*q
e = 65537
print(n)
m = bytes_to_long(flag.encode())
print(pow(m, e, n))

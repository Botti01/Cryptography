from Crypto.Util.number import getPrime


n_length = 1024

p1 = getPrime(n_length)
p2 = getPrime(n_length)
print ("p1 = "+str(p1))
print ("p2 = "+str(p2))

n = p1 * p2
print ("n = "+str(n))

phi = (p1 - 1) * (p2 - 1)
print ("phi = "+str(phi))

#define the public exponent
e = 65537

from math import gcd

g = gcd(e, phi)
print(g)
if g != 1:
    raise ValueError("e and phi are not coprime")

d = pow(e, -1, phi)
print ("d = "+str(d))

pulic_rsa_key = (e, n)
private_rsa_key = (d, n)

# Encryption
msg = b'This is the message to encrypt'
msg_int = int.from_bytes(msg, byteorder='big')
print ("msg = "+str(msg))

if msg_int > n-1:
    raise ValueError("Message is too long")

C = pow(msg_int, e, n)
print ("C = "+str(C))

D = pow(C, d, n)
print ("D = "+str(D))

msg_dec = D.to_bytes(n_length, byteorder='big')
print ("msg = "+str(msg_dec))
print(msg.decode())



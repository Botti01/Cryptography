#!/usr/bin/env python3

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
from secret import flag

assert len(flag) == 23  # Ensure the flag is exactly 23 bytes

e = 3  # Public exponent for RSA

# n will be 8 * (100 + 100) = 1600 bits strong which is pretty good
while True:
    # Generate two random 100-bit prime numbers for p and q
    p = getPrime(100)
    q = getPrime(100)
    phi = (p - 1) * (q - 1)  # Compute Euler's totient function
    d = inverse(e, phi)  # Compute the modular inverse of e modulo phi
    if d != -1 and GCD(e, phi) == 1:  # Ensure e and phi are coprime and d exists
        break

n = p * q  # Compute the RSA modulus

pt = bytes_to_long(flag)  # Convert the flag to a long integer
ct = pow(pt, e, n)  # Encrypt the plaintext using RSA: ct = pt^e mod n

print(f"n = {n}")  # Output the modulus
print(f"e = {e}")  # Output the public exponent
print(f"ct = {ct}")  # Output the ciphertext

pt = pow(ct, d, n)  # Decrypt the ciphertext using the private exponent
decrypted = long_to_bytes(pt)  # Convert the decrypted integer back to bytes
assert decrypted == flag  # Ensure decryption is correct

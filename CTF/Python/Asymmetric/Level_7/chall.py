from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

# Generate two random 512-bit primes for RSA key generation
p, q = getPrime(512), getPrime(512)
n = p*q  # RSA modulus
e = 65537  # Common public exponent
print(n)  # Output the modulus (public key part)

# Convert the flag to a long integer and encrypt it with RSA
m = bytes_to_long(flag.encode())
print(pow(m, e, n))  # Output the encrypted flag (ciphertext)

# Compute Euler's totient for the modulus and the private exponent
phi = (p-1)*(q-1)
d = inverse(e, phi)  # RSA private exponent

# Oracle loop: for each input ciphertext, decrypt and reveal only the parity (LSB) of the plaintext
while True:
    req = input()
    dec = pow(int(req), d, n)  # Decrypt the input ciphertext
    print(dec % 2)  # Output 0 if plaintext is even, 1 if odd

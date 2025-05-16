from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

# Generate two random 512-bit prime numbers for RSA key generation
p, q = getPrime(512), getPrime(512)

# Compute the RSA modulus
n = p*q

# List of two different public exponents
e = [31, 71]

# Print the modulus (public key component)
print(n)

# Convert the secret flag to a long integer (plaintext message)
m = bytes_to_long(flag.encode())

# Encrypt the message with both exponents and print the ciphertexts
# This leaks two ciphertexts of the same message under different exponents, which is vulnerable to the common modulus attack
print([pow(m, ee, n) for ee in e])

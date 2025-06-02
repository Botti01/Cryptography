from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

# Generate two random 512-bit prime numbers for RSA key generation
p, q = getPrime(512), getPrime(512)
# Compute the RSA modulus n
n = p*q
# Print the modulus n (public key component)
print(n)
# Use a fixed large public exponent e (unusually large for RSA)

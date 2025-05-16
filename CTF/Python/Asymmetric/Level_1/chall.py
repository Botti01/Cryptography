from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

# Generate two random 64-bit primes for RSA
p, q = getPrime(64), getPrime(64)
n = p*q  # RSA modulus
e = 65537  # Common public exponent
print(n)

# Convert the flag to an integer
m = bytes_to_long(flag)
# Encrypt the flag using RSA and print the ciphertext
print(pow(m, e, n))

# 176278749487742942508568320862050211633
# 46228309104141229075992607107041922411

from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag
import numpy as np

# Generate a list of 10 random 512-bit prime numbers
primes = [getPrime(512) for _ in range(10)]

# Randomly select 2 distinct primes from the list, 6 times, and multiply each pair to create 6 moduli
mods = [np.random.choice(primes, 2, replace=False) for _ in range(6)]
mods = [m[0]*m[1] for m in mods]

# Public exponent for RSA encryption
e = 65537

# Print the 6 generated RSA moduli
print(mods)

# Convert the flag string to a long integer
m = bytes_to_long(flag.encode())

# Encrypt the flag under each modulus using RSA and print the ciphertexts
print([pow(m, e, n) for n in mods])

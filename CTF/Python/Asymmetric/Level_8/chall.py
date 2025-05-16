from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

# Generate three different RSA moduli, each as the product of two random 512-bit primes
n1 = getPrime(512)*getPrime(512)
n2 = getPrime(512)*getPrime(512)
n3 = getPrime(512)*getPrime(512)
n = [n1, n2, n3]
print(n)  # Print the list of moduli

e = 3  # Public exponent for RSA encryption (small exponent, often used in CTFs)
m = bytes_to_long(flag.encode())  # Convert the flag (secret message) to a long integer

# Encrypt the message m with each modulus using RSA encryption and print the ciphertexts
print([pow(m, e, nn) for nn in n])

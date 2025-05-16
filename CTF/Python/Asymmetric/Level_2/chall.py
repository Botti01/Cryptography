from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from secret import flag

# Function to find the next prime greater than a given number p
def next_prime(p):
    while True:
        p = p+1
        if isPrime(p):
            return p

# Generate a random 512-bit prime number p
p = getPrime(512)
# Find the next prime number after p to use as q
q = next_prime(p)
# Compute the RSA modulus n as the product of p and q
n = p*q
# Set the public exponent e to 65537 (common choice in RSA)
e = 65537
# Print the modulus n (public key component)
print(n)
# Convert the flag (secret message) to a long integer
m = bytes_to_long(flag.encode())
# Encrypt the message m using RSA encryption and print the ciphertext
print(pow(m, e, n))

from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

# Generate two random 512-bit primes for RSA key generation
p, q = getPrime(512), getPrime(512)
n = p*q  # RSA modulus
e = 65537  # Common public exponent

# Convert the secret flag to a long integer
m = bytes_to_long(flag.encode())

# Print the RSA encryption of the flag (ciphertext)
print(pow(m, e, n))

# Allow the user to interact with the encryption/decryption oracle 3 times
for _ in range(3):
    req = input()
    if req[0] == 'e':
        # Encrypt the provided integer using the public key (e, n)
        print(pow(int(req[1:]), e, n))
    elif req[0] == 'd':
        # Decrypt the provided integer using the private key (d, n)
        phi = (p-1)*(q-1)  # Euler's totient function
        d = inverse(e, phi)  # Private exponent
        dec = pow(int(req[1:]), d, n)
        # Ensure the decrypted message is not the original flag
        assert dec != m
        print(dec)

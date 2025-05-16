from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

# Generate two random 512-bit primes for RSA key generation
p, q = getPrime(512), getPrime(512)
n = p*q  # RSA modulus
e = 65537  # Common public exponent
print(n)  # Output the modulus

# Convert the secret flag to a long integer and encrypt it with RSA
m = bytes_to_long(flag.encode())
print(pow(m, e, n))  # Output the encrypted flag

req = input()  # Read user input for encryption or decryption

# If input starts with 'e', encrypt the provided number with the public key
if req[0] == 'e':
    print(pow(int(req[1:]), e, n))
# If input starts with 'd', decrypt the provided number with the private key
elif req[0] == 'd':
    phi = (p-1)*(q-1)  # Compute Euler's totient
    d = inverse(e, phi)  # Compute private exponent
    dec = pow(int(req[1:]), d, n)  # Decrypt the ciphertext
    assert dec != m  # Ensure the decrypted value is not the original flag
    print(dec)  # Output the decrypted value


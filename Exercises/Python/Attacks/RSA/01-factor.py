from Crypto.Util.number import getPrime

# Generate a random 20-bit prime number and assign it to p1
p1 = getPrime(20)
# Generate another random 20-bit prime number and assign it to p2
p2 = getPrime(20)
# p1 = getPrime(60) factorization is not possible

# Print the first prime number
print(p1)
# Print the second prime number
print(p2)
# Print the product of the two prime numbers (simulates an RSA modulus)
print(p1 * p2)
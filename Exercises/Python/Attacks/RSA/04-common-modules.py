from Crypto.Util.number import getPrime

# Extended Euclidean Algorithm to find gcd and coefficients
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
    
if __name__ == '__main__':
    n_len = 1024  # Bit length for prime numbers
    
    # Generate two large random primes p1 and p2
    p1 = getPrime(n_len)
    p2 = getPrime(n_len)
    n = p1 * p2  # RSA modulus
    print("p1 = " + str(p1))
    print("p2 = " + str(p2))
    print("n = " + str(n))
    
    e1 = 65537  # First public exponent
    e2 = 17     # Second public exponent
    
    phi = (p1 - 1) * (p2 - 1)  # Euler's totient function for n
    
    # Check if e1 and phi are coprime
    res = egcd(e1, phi)
    if res[0] != 1:
        raise ValueError
    # Check if e2 and phi are coprime
    res = egcd(e2, phi)
    if res[0] != 1:
        raise ValueError
    
    # Compute private exponents d1 and d2 for each public exponent
    d1 = pow(e1, -1, phi)
    d2 = pow(e2, -1, phi)
    
    # RSA key pairs for both exponents
    rsa1_pub = (e1, n)
    rsa1_priv = (d1, n)
    
    rsa2_pub = (e2, n)
    rsa2_priv = (d2, n)
    
    
    ###########################################
    
    # Example plaintext as bytes
    plaintext = b'This is a byte string'
    # Convert plaintext to integer for encryption
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    print(plaintext_int)
    
    # Encrypt plaintext with both public exponents
    c1 = pow(plaintext_int, e1, n)
    c2 = pow(plaintext_int, e2, n)
    
    # Compute coefficients u, v such that u*e1 + v*e2 = gcd(e1, e2) = 1
    res = egcd(e1, e2)  
    u = res[1]
    v = res[2]
    
    val = u*e1 + v*e2  # Should print 1
    print(val)
    
    # Decrypt using the common modulus attack (when same plaintext is encrypted with different exponents)
    decrypted = pow(c1, u, n)*pow(c2, v, n) % n
    print (decrypted)
    # Convert decrypted integer back to bytes and decode to string
    print (decrypted.to_bytes(decrypted.bit_length()// 8 + 1, byteorder='big').decode())
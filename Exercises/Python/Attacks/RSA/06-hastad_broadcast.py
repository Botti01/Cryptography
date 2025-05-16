from Crypto.PublicKey import RSA

def iroot(k, n):
    # Computes the integer k-th root of n using Newton's method
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1)*s + n // pow(s, k-1)
        u = t // k
    return s

def egcd(a, b):
    # Extended Euclidean Algorithm
    # Returns a tuple of (gcd, x, y) such that ax + by = gcd
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

if __name__ == '__main__':
    n_length = 1024  # RSA modulus length in bits
    e = 3           # Public exponent for RSA (small for Hastad's attack)

    # Generate three different RSA key pairs with the same exponent e
    rsa1 = RSA.generate(n_length, e=e)
    rsa2 = RSA.generate(n_length, e=e)
    rsa3 = RSA.generate(n_length, e=e)

    n1 = rsa1.n  # Modulus for first key
    n2 = rsa2.n  # Modulus for second key
    n3 = rsa3.n  # Modulus for third key

    print(n1)
    print(n2)
    print(n3)

    print(rsa1.e)
    
    n = b'This is the message to decrypt'  # The plaintext message
    
    n_int = int.from_bytes(n, byteorder='big')  # Convert message to integer
    
    # Encrypt the message under each public key
    c1 = pow(n_int, e, n1)
    c2 = pow(n_int, e, n2)
    c3 = pow(n_int, e, n3)
    
    
    # N = n1 * n2 * n3
    # c modulo N
    # c1, c2, c3, n1, n2, n3
    # n_int
    
    # Compute the coefficients for the Chinese Remainder Theorem (CRT)
    # n1
    g, u1, v1 = egcd(n2 * n3, n1)
    # n2
    g, u2, v2 = egcd(n1 * n3, n2)
    # n3
    g, u3, v3 = egcd(n1 * n2, n3)
    
    # Combine the ciphertexts using CRT to get c ≡ m^e mod N
    c = c1 * u1 * n2 * n3 + c2 * u2 * n1 * n3 + c3 * u3 * n1 * n2
    
    # Recover the plaintext integer by taking the integer e-th root
    dec_int = iroot(e, c)
    # Convert the integer back to bytes and decode to string
    print(dec_int.to_bytes(dec_int.bit_length() // 8 + 1, byteorder='big').decode())
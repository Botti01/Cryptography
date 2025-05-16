from Crypto.PublicKey import RSA

# kth root of the number n
def iroot(k, n):
    # This function attempts to compute the integer k-th root of n using Newton's method.
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1)*s + n // pow(s, k-1)
        u = t // k
    return s

if __name__ == '__main__':
    # Generate an RSA keypair with a low public exponent e=3
    rsa_keypair = RSA.generate(2048, e=3)
    e = rsa_keypair.e
    # d = rsa_keypair.d
    n = rsa_keypair.n

    # The plaintext message to be encrypted
    m = b'This message needs to be encrypted'
    # Convert the message from bytes to an integer
    m_int = int.from_bytes(m, byteorder='big')

    # Encrypt the message using RSA encryption: c = m^e mod n
    c = pow(m_int, e, n)

    # Attempt to decrypt by taking the integer e-th root of c (works if m^e < n)
    decrypted_int = iroot(e, c)
    print(decrypted_int)
    # Convert the decrypted integer back to bytes and decode to string
    print(decrypted_int.to_bytes(decrypted_int.bit_length() // 8 + 1, byteorder='big').decode())

    # Attempt to decrypt using floating point root (not reliable for large integers)
    dec = pow(c, 1/3)
    print(dec)
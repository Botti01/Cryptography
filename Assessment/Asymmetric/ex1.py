# Function to compute the integer k-th root of n
def iroot(k, n):
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s

# Given ciphertext c (same across all tuples)
c = 73971582172221720975480290180657782856630731412501396897039088286823790752122440241066935345942112042897458901087025651772933251156524141953655795753578733202992406563839419064891460444221435902619902400562012855658283339255681701088409382676950930475265838295258904

# Compute cube root of c
m_candidate = iroot(3, c)

# Verify that m_candidate^3 == c
assert pow(m_candidate, 3) == c, "Cube root not exact"

# Convert integer to bytes and decode as UTF-8
secret = m_candidate.to_bytes((m_candidate.bit_length() + 7) // 8, byteorder='big').decode()

print("Secret:", secret)
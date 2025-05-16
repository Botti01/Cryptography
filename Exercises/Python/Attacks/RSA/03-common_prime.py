from Crypto.Util.number import getPrime
from gmpy2 import gcd

# This script demonstrates how two RSA moduli sharing a common prime factor
# can be factored using the greatest common divisor (GCD).

if __name__ == '__main__':
    
    # Generate three random 1024-bit prime numbers
    p1 = getPrime(1024)
    p2 = getPrime(1024)
    p3 = getPrime(1024)
    
    # Construct two RSA moduli that share the prime p1
    n1 = p1 * p2
    n2 = p1 * p3
    
    # Print the generated primes
    print(p1)
    print("---------------")
    print(p2)
    print("---------------")
    print(p3)
    
    # Compute the GCD of n1 and n2 to recover the shared prime p1
    p = gcd(n1, n2)
    print("---------------")
    print(p)
    print("---------------")
    # Print the other prime factors of n1 and n2
    print(n1 // p)
    print("---------------")
    print(n2 // p)

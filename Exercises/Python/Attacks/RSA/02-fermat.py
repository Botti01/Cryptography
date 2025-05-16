from Crypto.Util.number import getPrime
from Crypto.Util.number import getRandomInteger

from gmpy2 import next_prime
from gmpy2 import isqrt

if __name__ == '__main__':
    
    n = 400
    
    # Generate a random 400-bit prime number p1
    p1 = getPrime(n)
    # Generate a random integer delta (up to 215 bits)
    delta = getRandomInteger(215)
    # Find the next prime after p1 + delta to get p2
    p2 = next_prime(p1 + delta)
    print(p1)
    print(p2)
    
    # Compute the modulus n as the product of two primes
    n = p1 * p2
    
    # a^2 - b^2 = (a-b)(a+b)
    # a --> independent variable
    # b will be dependent on n, a
    # b2 = a^2 - n
    
    # Start with a and b as the integer square root of n
    a = b = isqrt(n)
    # Compute b2 = a^2 - n
    b2 = pow(a, 2) - n
    print ("a = "+ str(a))
    print ("b = "+ str(b))
    print ("b2 = "+ str(b2))
    # Print the difference between b^2 and b2 modulo n
    print ("delta = "+ str(pow(b, 2)-b2 %n))
    
    i = 0
    
    # Fermat's factorization loop: increment a until b2 is a perfect square
    while True:
        print ("Iteration # = " + str(i))
        # Check if b2 is a perfect square (i.e., b^2 == b2)
        if b2 == pow(b, 2):
            print ("Solution found b = " + str(b))
            break
        else:
            # Increment a and recompute b2 and b
            a += 1
            b2 = pow(a, 2) - n
            b = isqrt(b2)
            print ("a = "+ str(a))
            print ("b = "+ str(b))
            print ("b2 = "+ str(b2))
            print ("delta = "+ str(pow(b, 2)-b2))
            print ()
            
        i += 1
        
    # Recover the two prime factors from a and b
    p = a+b
    q = a-b
    print ("p = " + str(p))
    print ("q = " + str(q))
        
    
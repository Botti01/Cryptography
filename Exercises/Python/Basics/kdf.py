from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

if __name__ == "__main__":
    
    password = b"WeakP4assword"
    
    # First parameter is the password
    # Second parameter is the salt
    # Third parameter is the length of the key
    # Fourth parameter is the cost factor
    # Fifth parameter is the block size
    # Sixth parameter is the parallelization factor
    key = scrypt (password, get_random_bytes(16), 16, N = 2**14, r = 8, p = 1)
    # scrypt use so much resources, play with the cost factor
    
    print()
    print(key)
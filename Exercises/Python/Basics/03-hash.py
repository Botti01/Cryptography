from Crypto.Hash import SHA256, SHA3_256


if __name__ == "__main__":
    
##### ---------------Hash a message--------------- #####
    
    # hash_generator = SHA256.new()
    
    # hash_generator.update(b"Text to hash")
    # hash_generator.update(b" even more text")
    
    # print()
    # # hexadecimal representation of the hash
    # print(hash_generator.hexdigest())
    # # binary representation of the hash
    # print(hash_generator.digest())
    
    
    # hash_generator = SHA256.new(data = b'Initial bytes')
    # hash_generator.update(b"Text to hash")
    # hash_generator.update(b" even more text")
    
    # print()
    # # hexadecimal representation of the hash
    # print(hash_generator.hexdigest())
    # # binary representation of the hash
    # print(hash_generator.digest())
    
    
##### ---------------Hash a file--------------- #####
    
    hash_generator = SHA3_256.new()
    
    # with open(__file__, "rb") as f_input:
    #     hash_generator.update(f_input.read())
    
    with open(__file__) as f_input:
        hash_generator.update(f_input.read().encode())
        
    print()
    print(hash_generator.hexdigest())
    print(hash_generator.digest())
    
    
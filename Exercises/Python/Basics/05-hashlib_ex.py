import hashlib
import hmac

from Crypto.Random import get_random_bytes


if __name__ == "__main__":
    
    dig_generator = hashlib.sha256()
    dig_generator.update(b"First chunk of data")
    dig_generator.update(b"Second chunk of data")
    
    print()
    # hexadecimal representation of the hash
    print(dig_generator.hexdigest())
    
##### -------------HMAC------------- #####
    
    secret = get_random_bytes(32)
    
    mac_generator = hmac.new(secret, b"message to hash", hashlib.sha256)
    
    # print(mac_generator.hexdigest())
    hmacsender = mac_generator.hexdigest()
    
    mac_gen_rec = hmac.new(secret, b"message to hash", hashlib.sha256)
    hmac_ver = mac_gen_rec.hexdigest()
    
    print()
    if hmac.compare_digest(hmacsender, hmac_ver):
        print("HMAC are OK")
    else:
        print("HMAC are different!")
    
    
    
    
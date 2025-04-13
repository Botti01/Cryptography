from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

if __name__ == "__main__":
    
    IV = get_random_bytes(AES.block_size)
    
    print(AES.key_size)     # To get the key size available
    # Generate a random key
    key = get_random_bytes(AES.key_size[2])
    
    # Plaintext must be a multiple of the block size
    # in this case 32 
    plaintext = b'These are the data to encrypt!!!'
    print(len(plaintext))
    
    # Create a cipher object using the key and IV, select also the mode of operation
    # The mode can be optional
    cipher = AES.new(key, AES.MODE_CBC, IV)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)
    print(ciphertext)
    
    # Decrypt the ciphertext
    cipher_dec = AES.new(key, AES.MODE_CBC, IV)
    decrypted = cipher_dec.decrypt(ciphertext)
    print(decrypted)
    
    
    # plaintext = b'Unaligned string...'
    plaintext = b'Aligned string..'
    print(len(plaintext))
    
    cipher = AES.new(key, AES.MODE_CBC, IV)
    
    # I need to pad the plaintext to be a multiple of the block size
    # The padding is done using the pad function imported from Crypto.Util.Padding
    # padded = pad(plaintext, AES.block_size)
    # print(padded)
    # ciphertext = cipher.encrypt(padded)
    print(plaintext)
    ciphertext = cipher.encrypt(plaintext)
    
    
    plaintext2 = b'. More text to encrypt...'
    padded = pad(plaintext2, AES.block_size)
    ciphertext += cipher.encrypt(padded) 
    
    print()
    print(ciphertext)
    
    # Decrypt and unpad the ciphertext
    cipher_dec = AES.new(key, AES.MODE_CBC, IV)
    decrypted = cipher_dec.decrypt(ciphertext)
    unpadded = unpad(decrypted, AES.block_size)
    print()
    print(unpadded)
    
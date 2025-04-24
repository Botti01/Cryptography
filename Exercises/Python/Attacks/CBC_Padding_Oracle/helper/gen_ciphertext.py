from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Importing the secret key and IV from external files
from attacks.CBCPaddingOracle.mysecrets import cbc_oracle_key as key
from attacks.CBCPaddingOracle.mydata import cbc_oracle_iv as iv

# Initialize AES cipher in CBC mode with the provided key and IV
cipher = AES.new(key, AES.MODE_CBC, iv)

# The plaintext message to be encrypted
# msg = b'03LPYOV{How_many_nice_things_can_you_find_1_bit_at_the_time?}'
msg = b'03LPYOV{How_many_nice_things_can_you_find_1_bit_at_the_time?}'

# Print the length of the plaintext message
print(len(msg))

# Print the initialization vector (IV)
print(iv)

# Print the encryption key
print(key)

# Encrypt the padded plaintext message
ctxt = cipher.encrypt(pad(msg, AES.block_size))

# Print the resulting ciphertext
print(ctxt)

# Reinitialize the AES cipher to demonstrate decryption
cipher2 = AES.new(key, AES.MODE_CBC, iv)

# Decrypt the ciphertext and print the result
print(cipher2.decrypt(ctxt))

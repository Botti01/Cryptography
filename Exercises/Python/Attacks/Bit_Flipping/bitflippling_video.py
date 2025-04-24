from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    plaintext = b'This is the message to encrypt but the attacker knows there is a specific sequence of numbers 12345'
    # attacker knows that b'1' in a specific position
    index = plaintext.index(b'1')  # Find the index of the known byte in the plaintext
    print(index)

    key = get_random_bytes(32)  # Generate a random 256-bit key
    nonce = get_random_bytes(12)  # Generate a random 96-bit nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)  # Initialize ChaCha20 cipher with key and nonce
    ciphertext = cipher.encrypt(plaintext)  # Encrypt the plaintext

    # ciphertext, index, b'1'

    new_value = b'9'  # Desired new value to replace the known byte
    new_int = ord(new_value)  # ASCII code of the new value

    mask = ord(b'1') ^ new_int  # XOR mask to flip the known byte to the desired value

    edt_ciphertext = bytearray(ciphertext)  # Convert ciphertext to mutable bytearray
    edt_ciphertext[index] = ciphertext[index] ^ mask  # Apply the XOR mask to modify the ciphertext

    # edt_ciphertext is received by the recipient,

    cipher_dec = ChaCha20.new(key=key, nonce=nonce)  # Reinitialize ChaCha20 cipher for decryption
    decrypted_text = cipher_dec.decrypt(edt_ciphertext)  # Decrypt the modified ciphertext
    print(decrypted_text)  # Print the decrypted text to verify the modification

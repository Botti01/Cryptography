from Crypto.Cipher import Salsa20, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import base64
import sys
import json

if __name__ == "__main__":
    
    # key = get_random_bytes(Salsa20.key_size[1])
    # nonce = get_random_bytes(8)
    
    # cipher = Salsa20.new(key = key, nonce = nonce)
    
    # # f_output = open("enc.enc", "wb")
    # f_output = open(sys.argv[2], "wb")
    
    # ciphertext = b''
    
    # with open(sys.argv[1], "rb") as f_input:
    # # with open(__file__, "rb") as f_input:
    #     plaintext = f_input.read(1024)
    #     while plaintext:
    #         ciphertext = cipher.encrypt(plaintext)
    #         f_output.write(ciphertext)
    #         plaintext = f_input.read(1024)
    
    # print("Nonce = " + base64.b64encode(nonce).decode())
    
    
    
    key = get_random_bytes(AES.key_size[0])
    iv = get_random_bytes(AES.block_size)
    
    # __file__ = "stream2.py"
    # Is the file that you stay working in
    f_input = open(__file__, "rb")
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    ciphertext = cipher.encrypt(pad(f_input.read(), AES.block_size))
    
    f_output = open("enc.enc", "wb")
    f_output.write(ciphertext)
    print()
    print(base64.b64encode(iv))
    
    # with json.dumps() you can send the ciphertext and iv to the recipient
    # so that they can decrypt the ciphertext
    result = json.dumps({
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
    })
    print(result)
    
    
# -----------------the recipient has received result----------------

    #ready to decrypt
    b64_output = json.loads(result)
    
    # retrieve the ciphertext and iv from the recipient
    iv_rec = base64.b64decode(b64_output['iv'])
    ciphertext_rec = base64.b64decode(b64_output['ciphertext'])
    
    cipher_dec = AES.new(key, AES.MODE_CBC, iv_rec)    
    plaintext_rec = cipher_dec.decrypt(ciphertext_rec)
    
    print()
    print(plaintext_rec)
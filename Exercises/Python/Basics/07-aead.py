from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import json
import base64

if __name__ == "__main__":
    
    header = b'This only needs authentication'
    payload = b'This also needs confidentiality'
    
    key = get_random_bytes(AES.key_size[2])
    
    cipher = AES.new(key, AES.MODE_GCM)     #don't explicit use IV
    
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    
    # json_keys and json_values are used to create the JSON object
    json_keys = ['nonce', 'header', 'ciphertext', 'tag']
    json_values = [cipher.nonce, header, ciphertext, tag]
    
    # json_b64_values are used to encode the values in base64
    json_b64_values = [base64.b64encode(x).decode() for x in json_values]
    
    # json_obj is the JSON object that will be printed
    json_obj = json.dumps(dict(zip(json_keys, json_b64_values)))
    
    print()
    print(json_obj)
    
#####----------------Verify the message---------------------#####

    b64_obj = json.loads(json_obj)
    json_keys = ['nonce', 'header', 'ciphertext', 'tag']
    
    # jv is the JSON object that will be used to verify the message
    jv = {k: base64.b64decode(b64_obj[k]) for k in json_keys}
    
    cipher_receiver = AES.new(key, AES.MODE_GCM, nonce = jv['nonce'])
    cipher_receiver.update(jv['header'])
    
    try:
        cipher_receiver.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        
        # This will raise an exception
        # cipher_receiver.decrypt_and_verify(b'wrong message', jv['tag'])
        
        print()
        print("Everything is ok.")
    except (ValueError, KeyError):
        print()
        print("Errors occurred with the tag!")
    
    
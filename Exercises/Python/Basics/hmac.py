from Crypto.Hash import SHA3_256, HMAC
from Crypto.Random import get_random_bytes

import json
import base64

if __name__ == "__main__":

##### ---------------HMAC--------------- #####
    
    msg = b"This is the message used in input"
    
    # secret = get_random_bytes(32)
    secret = b'deadbeefdeadbeefdeadbeefdeadbeef'
    
    hmac_generator = HMAC.new(secret, digestmod = SHA3_256)
    
    hmac_generator.update(msg)
    # using msg[:5] and msg[5:] to show that the HMAC is the same
    # but with get_random_bytes it will be different
    # hmac_generator.update(msg[:5])
    # hmac_generator.update(msg[5:])
    
    print()
    # print(hmac_generator.hexdigest())
    
    obj = json.dumps({
        "message": msg.decode(),
        "MAC": base64.b64encode(hmac_generator.digest()).decode()
    })
    
    print(obj)
    
    b64_obj = json.loads(obj)
    hmac_verifier = HMAC.new(secret, digestmod = SHA3_256)
    
    hmac_verifier.update(b64_obj["message"].encode())
    
    # hmac_verifier.verify(base64.b64decode(b64_obj["MAC"]))
    # print()
    # print("The HMAC is valid.")
    
    # To modify the message
    mac = bytearray(base64.b64decode(b64_obj["MAC"]))
    mac[0] = 0
    try:
        hmac_verifier.verify(mac)
        print()
        print("The message is authentic.")
    except ValueError:
        print()
        print("Wrong message or secret!")

    
    
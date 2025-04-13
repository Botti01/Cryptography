from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, constant_time

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

message = b'The message to sign is here'
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
        ),
    hashes.SHA256()
)

public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
        ),
    hashes.SHA256()
)
print()
print("Signature is valid.")

hash_func = hashes.SHA384()
hasher = hashes.Hash(hash_func, default_backend())
hasher.update(b"First part of data")
hasher.update(b"Second part of data")
digest = hasher.finalize()


from cryptography.hazmat.primitives.asymmetric import utils

signature2 = private_key.sign(
    digest,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
        ),
    utils.Prehashed(hash_func)
)


hash_func2 = hashes.SHA384()
hasher2 = hashes.Hash(hash_func2, default_backend())
hasher2.update(b"First part of data")
hasher2.update(b"Second part of data")
digest2 = hasher2.finalize()

public_key.verify(
    signature2,
    digest2,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
        ),
    utils.Prehashed(hash_func2)
)


###### Encryption ######

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext.decode())
print(constant_time.bytes_eq(plaintext, message))
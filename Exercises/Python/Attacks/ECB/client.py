import os

os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from myconfig import HOST, PORT
from Crypto.Cipher import AES

from pwn import *

server = remote(HOST, PORT)

input_message = b"A" * 48
server.send(input_message)
ciphertext = server.recv(1024)

print(ciphertext)
print(len(ciphertext))

for i in range (len(ciphertext)//AES.block_size):
    print(ciphertext[i*AES.block_size:(i+1)*AES.block_size])
    
if ciphertext[32:48] == ciphertext[16:32]:
    print("ECB mode")
else:
    print("CBC mode")
server.close()


# import os

# # Disabilitiamo output interattivo di pwntools
# os.environ['PWNLIB_NOTERM'] = 'True'
# os.environ['PWNLIB_SILENT'] = 'True'

# from myconfig import HOST, PORT
# from Crypto.Cipher import AES

# from pwn import *

# # Connessione al server
# server = remote(HOST, PORT)

# # Messaggio di prova (48 byte = 3 blocchi da 16)
# input_message = b"A" * 48
# server.send(input_message)

# # Ricevi ciphertext
# ciphertext = server.recv(1024)
# server.close()

# # Stampo risultati
# print("Ciphertext:", ciphertext)
# print("Lunghezza:", len(ciphertext))
# print("Blocchi da 16 byte:")
# for i in range(len(ciphertext) // AES.block_size):
#     block = ciphertext[i*AES.block_size:(i+1)*AES.block_size]
#     print(f"Blocco {i}: {block}")

# # Rilevazione ECB vs CBC: se due blocchi adiacenti coincidono => ECB
# if ciphertext[16:32] == ciphertext[32:48]:
#     print("Modalità: ECB")
# else:
#     print("Modalità: CBC")
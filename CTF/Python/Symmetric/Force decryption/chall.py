from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import flag

# Generate a random 16-byte key for encryption
key = get_random_bytes(16)
leak = b"mynamesuperadmin"  # Predefined value to restrict encryption/decryption

def make_cipher():
    # Create a new AES cipher in CBC mode with a random IV
    IV = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    return IV, cipher

def encrypt():
    # Prompt the user for input to encrypt
    string = input("What do you want to encrypt?\n> ")
    string = bytes.fromhex(string)  # Convert input from hex to bytes
    if len(string) != 16:  # Ensure the input is exactly 16 bytes
        print("Sorry, you can encrypt only 16 bytes!")
        return

    if leak == string:  # Restrict encryption of the predefined value
        print("Sorry, you can't encrypt that!")
        return

    IV, cipher = make_cipher()  # Generate a new cipher with a random IV
    encrypted = cipher.encrypt(string)  # Encrypt the input

    # Output the IV and encrypted data in hex format
    print(F"IV: {IV.hex()}\nEncrypted: {encrypted.hex()}\n")

def decrypt():
    # Prompt the user for input to decrypt
    string = input("What do you want to decrypt?\n> ")
    string = bytes.fromhex(string)  # Convert input from hex to bytes

    # Prompt the user for the IV
    IV = input("Gimme the IV\n> ")
    IV = bytes.fromhex(IV)  # Convert IV from hex to bytes

    if (IV == leak):  # Restrict decryption with the predefined value as IV
        print("Nice try...")
        return

    # Create a cipher with the provided IV
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)

    decrypted = cipher.decrypt(string)  # Decrypt the input
    if leak == decrypted:  # Check if the decrypted value matches the predefined value
        print(f"Good job. Your flag: {flag}")
    else:
        # Output the decrypted data in hex format
        print(f"Mh, a normal day.\nDecrypted: {decrypted.hex()}")

if __name__ == '__main__':
    # Menu for user interaction
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "dec - decrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip()  # Get user command

        if cmd == "quit":  # Exit the program
            break
        elif cmd == "help":  # Show the menu again
            continue
        elif cmd == "enc":  # Call the encryption function
            encrypt()
        elif cmd == "dec":  # Call the decryption function
            decrypt()

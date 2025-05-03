"""
    
You may have to make different guesses if you want to go in the past, but if you understood the code, they would not be too much!

HINT: have a look at the Python requests library, don't be scared by the sessions.

HINT2: pay 80 points... if you think yoou have the solution but are encountering some problems when executing the exploit...

http://130.192.5.212:6522

"""

import requests               # HTTP client library for Python
from Crypto.Util.number import long_to_bytes, bytes_to_long  # for integer↔bytes conversion
import time                   # system time functions

# ─── Configuration ───────────────────────────────────────────────────────────────
URL = "http://130.192.5.212:6522"  # base URL of the target web service

def str_to_cookie_bytes(cookie_str: str) -> bytes:
    # Convert a cookie string to raw bytes.
    # We will XOR these bytes with the keystream to forge new cookies.
    return cookie_str.encode()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    # Bytewise XOR of two byte-strings of equal length.
    # Used to recover and apply the ChaCha20 keystream.
    return bytes(x ^ y for x, y in zip(a, b))

# ─── Session Setup ──────────────────────────────────────────────────────────────
# Use a persistent HTTP session so that the server retains the same ChaCha20 key
# and expiration state across multiple requests.
session = requests.Session()

# ─── Step 1: Perform initial login and recover keystream ─────────────────────────
def initial_login():
    """
    1) Send /login?username=admin&admin=1 to obtain encrypted cookie.
    2) Compute expected plaintext (includes current expires timestamp).
    3) Recover ChaCha20 keystream: keystream = plaintext_bytes ⊕ ciphertext_bytes.
    Returns:
      - nonce (as raw bytes)
      - keystream (as raw bytes)
    """
    params = {
        "username": "admin",
        "admin": "1"
    }
    r = session.get(f"{URL}/login", params=params)
    data = r.json()

    # Extract nonce and ciphertext from JSON response (as integers)
    nonce = long_to_bytes(data['nonce'])
    ciphertext = long_to_bytes(data['cookie'])

    # Build the exact plaintext the server encrypted:
    # "username=admin&expires=<timestamp>&admin=1"
    expires_timestamp = int(time.time()) + 30 * 86400  # 30 days from now
    plaintext = f"username=admin&expires={expires_timestamp}&admin=1"
    plaintext_bytes = str_to_cookie_bytes(plaintext)

    # Derive the keystream for ChaCha20: keystream = plaintext ⊕ ciphertext
    keystream = xor_bytes(plaintext_bytes, ciphertext)

    print(f"[+] Login complete. Keystream recovered.\n    plaintext: {plaintext}")
    return nonce, keystream

# ─── Step 2: Forge cookies with varied timestamps ────────────────────────────────
def forge_and_check(nonce: bytes, keystream: bytes):
    """
    Bruteforce different past expiration dates to satisfy the server's
    get_flag() check, which allows a window of ~300 days.
    For each guess:
      1) Compute a forged expires timestamp.
      2) XOR with recovered keystream to produce new ciphertext.
      3) Send /flag?nonce=<>&cookie=<> and check for the flag in the response.
    """
    now = int(time.time())

    # Try guessing how many days ago the admin_expire_date was set (10–259 days)
    for guessed_days_ago in range(10, 260):
        # Reconstruct the server's original random admin_expire_date:
        guessed_admin_expire = now - guessed_days_ago * 86400
        # We then add 295 days so that the difference falls in the valid range (290–300 days)
        forged_expires = guessed_admin_expire + 295 * 86400

        # Build the new cookie plaintext with forced expires
        cookie_str = f"username=admin&expires={forged_expires}&admin=1"
        cookie_bytes = str_to_cookie_bytes(cookie_str)

        # Apply keystream: new_ciphertext = new_plaintext ⊕ keystream
        forged_ciphertext = xor_bytes(cookie_bytes, keystream)

        # Send the forged cookie and check the response
        params = {
            "nonce": str(bytes_to_long(nonce)),
            "cookie": str(bytes_to_long(forged_ciphertext))
        }
        r = session.get(f"{URL}/flag", params=params)
        print(f"[{guessed_days_ago}] Tried expires={forged_expires} → {r.text}")

        if "flag" in r.text.lower():
            print("\nFLAG FOUND!")
            break

# ─── Main Entrypoint ─────────────────────────────────────────────────────────────
def main():
    nonce, keystream = initial_login()
    forge_and_check(nonce, keystream)

if __name__ == "__main__":
    main()



# ─── Flag ───────────────────────────────────────────────────────────────────────
# CRYPTO25{90c01f7e-8cb7-408b-82b4-07e8e7c72d12}

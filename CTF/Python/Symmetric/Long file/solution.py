"""

this file has not been encrypted one line at the time... maybe...

"""

# ─── Attack ─────────────────────────────────────────────────────────────────────
# Repeating‐Key XOR Decryption via Single‐Byte XOR Cracking 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Read the full ciphertext (encrypted by XOR with a 1000‐byte repeating keystream).
#   2. For each key‐byte position j in [0..999]:
#        a) Extract the “column” of ciphertext bytes at positions j, j+1000, j+2000, …
#        b) Treat this column as having been XOR’d with a single key‐byte K[j].
#        c) Brute‐force all 256 possible byte values for K[j], scoring each by English‐likeness.
#        d) Select the key‐byte that gives the highest English score for the column plaintext.
#   3. Reconstruct the full 1000‐byte keystream from the recovered key bytes.
#   4. Decrypt the entire ciphertext by XOR’ing it with the repeating keystream.
#   5. Write the resulting plaintext to disk and inspect for the flag.

import sys

# ─── English Scoring Function ────────────────────────────────────────────────────
english_frequencies = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074, ' ': 0.13000  # approximate space frequency in English
}

def score_english(text_bytes: bytes) -> float:

    # Compute a heuristic 'English‐likeness' score for a byte string:
    #   - Add character frequency score if [A–Z, a–z, space].
    #   - Small positive for printable ASCII (33–126) and whitespace (tab, LF, CR).
    #   - Heavy penalty for non‐printable or high‐bit bytes.
    # Higher scores indicate more English‐like plaintext.

    score = 0.0
    for b in text_bytes:
        # Uppercase letters: convert to lowercase and add frequency
        if 65 <= b <= 90:  # 'A'–'Z'
            score += english_frequencies.get(chr(b + 32), 0.0)
        # Lowercase letters: add frequency
        elif 97 <= b <= 122:  # 'a'–'z'
            score += english_frequencies.get(chr(b), 0.0)
        # Space character
        elif b == 32:  # space
            score += english_frequencies[' ']
        # Whitespace (tab, LF, CR): small positive
        elif b in (9, 10, 13):
            score += 0.01
        # Other printable ASCII: tiny positive bonus
        elif 33 <= b <= 126:
            score += 0.001
        else:
            # Non‐printable/high‐bit bytes: penalty
            score -= 0.05
    return score

# ─── Single‐Byte XOR Cracker ─────────────────────────────────────────────────────
def crack_single_byte_xor(column_bytes: bytes) -> (int, bytes, float):

    # Given a sequence of bytes each XOR’d with the same single key byte,
    # try all 256 possible keys. For each candidate key k:
    #   - XOR every byte in column_bytes with k to produce plain_candidate.
    #   - Score plain_candidate using score_english().
    # Return (best_key, best_plaintext, best_score).

    best_key = 0
    best_score = float('-inf')
    best_plain = b''
    for k in range(256):
        # XOR each byte with k
        plain_candidate = bytes([b ^ k for b in column_bytes])
        s = score_english(plain_candidate)
        if s > best_score:
            best_score = s
            best_plain = plain_candidate
            best_key = k
    return best_key, best_plain, best_score

# ─── Main Routine: Repeating‐Key XOR Decryption ─────────────────────────────────
def main():
    # (a) Read the ciphertext from 'file.enc'
    try:
        with open('file.enc', 'rb') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print("ERROR: Could not open 'file.enc'. Make sure you are in the right directory.")
        sys.exit(1)

    L = len(ciphertext)
    KEYLEN = 1000
    keystream = bytearray(KEYLEN)

    print(f"[*] Ciphertext length = {L} bytes.")
    print("[*] Cracking each of the 1000 key‐bytes via single‐byte‐XOR…")

    # (b) For each key byte index j = 0..999:
    for j in range(KEYLEN):
        # Collect all ciphertext bytes at positions j, j+KEYLEN, j+2*KEYLEN, ...
        column_indices = list(range(j, L, KEYLEN))
        if not column_indices:
            # If no bytes correspond to this key‐position, default to zero
            keystream[j] = 0
            continue

        column_bytes = bytes(ciphertext[i] for i in column_indices)
        best_key_byte, best_plain_col, best_score = crack_single_byte_xor(column_bytes)
        keystream[j] = best_key_byte

        # Optional progress indicator every 100 bytes
        if (j + 1) % 100 == 0 or j == KEYLEN - 1:
            print(f"    → Recovered K[{j}] = 0x{best_key_byte:02x}   (score={best_score:.1f})")

    # (c) Decrypt entire ciphertext using the recovered keystream
    print("[*] Reassembling full plaintext by XOR’ing with repeating keystream…")
    plaintext = bytearray(L)
    for i in range(L):
        plaintext[i] = ciphertext[i] ^ keystream[i % KEYLEN]

    # (d) Write plaintext to output file 'file.dec'
    outname = 'file.txt'
    with open(outname, 'wb') as f:
        f.write(plaintext)

    print(f"[+] Done! Decrypted plaintext written to '{outname}'.")
    
    # ─── Print the flag if it matches the expected pattern ─────────────────────
    import re
    m = re.search(rb"CRYPTO25\{[0-9a-fA-F\-]{36}\}", plaintext)
    if m:
        print("FLAG FOUND:", m.group(0).decode("utf-8"))
    else:
        print("No CRYPTO25{…} pattern found in decrypted bytes.")

if __name__ == '__main__':
    main()



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{6afd02cd-127e-4de1-8a97-397668f10141}

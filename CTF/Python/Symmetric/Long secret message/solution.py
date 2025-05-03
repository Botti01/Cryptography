"""

This is a long message encrypted a line at the time...

(Remember, flag format is CRYPTO25{<uuid4>})

"""

import binascii       # for hex decoding
import re             # for regex UUID matching

# ─── Step 1: Read encrypted lines and known plaintext ─────────────────────────────
with open("hacker-manifesto.enc", "r") as f:
    encrypted_lines = [binascii.unhexlify(line.strip()) for line in f]  # Decode hex-encoded ciphertext lines

with open("hacker-manifesto.txt", "r", encoding="utf-8") as f:
    known_plaintext = [line.encode("utf-8") for line in f]  # Encode plaintext lines to bytes

print("🔍 Searching for valid keystream...\n")

# ─── Step 2: Try to derive a keystream from each known line ──────────────────────
for idx, (ct_line, pt_line) in enumerate(zip(encrypted_lines, known_plaintext)):
    min_len = min(len(ct_line), len(pt_line))  # Ensure we only XOR up to the shortest line
    keystream = bytes(ct_line[i] ^ pt_line[i] for i in range(min_len))  # Derive keystream by XORing ciphertext and plaintext

    decrypted_full = b""  # Accumulate decrypted text for all lines
    valid = True  # Flag to check if the keystream is valid for all lines

    # ─── Step 3: Try decrypting all lines with this keystream ─────────────────────
    for ciphertext in encrypted_lines:
        decrypted = bytes(
            ciphertext[j] ^ keystream[j % len(keystream)]  # Decrypt using the derived keystream (cyclically if needed)
            for j in range(len(ciphertext))
        )
        try:
            decoded = decrypted.decode("utf-8")  # Check if the decrypted text is valid UTF-8
            decrypted_full += decoded.encode("utf-8")  # Append valid decoded text
        except UnicodeDecodeError:  # If decoding fails, the keystream is invalid
            valid = False
            break

    if valid:
        print(f"Valid keystream found using line {idx + 1}")
        print("Decrypted text:\n")
        print(decrypted_full.decode("utf-8"))

        # ─── Step 4: Search for flag prefix ───────────────────────────────────────
        flag_start = decrypted_full.find(b"CRYPTO25{")  # Look for the flag prefix
        if flag_start == -1:
            print("\n'CRYPTO25{' not found.")  # If prefix not found, continue to the next keystream
            continue

        # ─── Step 5: Search for UUID v4 in the decrypted text ─────────────────────
        uuid_pattern = re.compile(
            rb"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"  # Regex pattern for UUID v4
        )
        uuid_matches = list(uuid_pattern.finditer(decrypted_full))  # Find all UUID matches in the decrypted text

        if not uuid_matches:
            print("\nNo UUID4 found.")  # If no UUID is found, continue to the next keystream
            continue

        # ─── Step 6: Use the last UUID as the most plausible flag ─────────────────
        last_uuid_match = uuid_matches[-1]  # Assume the last UUID match is the correct one
        uuid = last_uuid_match.group(0).decode("utf-8")  # Extract and decode the UUID

        # ─── Step 7: Build the final flag ─────────────────────────────────────────
        flag = f"CRYPTO25{{{uuid}}}"  # Construct the flag using the extracted UUID
        print("\nFLAG FOUND!")
        print("Reconstructed flag:", flag)
        break

else:
    print("No valid keystream found.")  # If no valid keystream is found after all iterations, print a failure message
    

# ─── Flag ────────────────────────────────────────────────────────────────────────
# CRYPTO25{c0ec7b27-16e8-4c60-9aad-3a83dcc1597b}

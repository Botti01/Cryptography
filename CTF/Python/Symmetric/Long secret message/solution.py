"""
This is a long message encrypted a line at the time...

(Remember, flag format is CRYPTO25{<uuid4>})
"""

import binascii       # for hex decoding
import re             # for regex UUID matching

# ─── Step 1: Read encrypted lines and known plaintext ─────────────────────────────
with open("hacker-manifesto.enc", "r") as f:
    encrypted_lines = [binascii.unhexlify(line.strip()) for line in f]

with open("hacker-manifesto.txt", "r", encoding="utf-8") as f:
    known_plaintext = [line.encode("utf-8") for line in f]

print("🔍 Searching for valid keystream...\n")

# ─── Step 2: Try to derive a keystream from each known line ──────────────────────
for idx, (ct_line, pt_line) in enumerate(zip(encrypted_lines, known_plaintext)):
    min_len = min(len(ct_line), len(pt_line))
    keystream = bytes(ct_line[i] ^ pt_line[i] for i in range(min_len))

    decrypted_full = b""
    valid = True

    # ─── Step 3: Try decrypting all lines with this keystream ─────────────────────
    for ciphertext in encrypted_lines:
        decrypted = bytes(
            ciphertext[j] ^ keystream[j % len(keystream)]
            for j in range(len(ciphertext))
        )
        try:
            decoded = decrypted.decode("utf-8")
            decrypted_full += decoded.encode("utf-8")
        except UnicodeDecodeError:
            valid = False
            break

    if valid:
        print(f"Valid keystream found using line {idx + 1}")
        print("Decrypted text:\n")
        print(decrypted_full.decode("utf-8"))

        # ─── Step 4: Search for flag prefix ───────────────────────────────────────
        flag_start = decrypted_full.find(b"CRYPTO25{")
        if flag_start == -1:
            print("\n'CRYPTO25{' not found.")
            continue

        # ─── Step 5: Search for UUID v4 in the decrypted text ─────────────────────
        uuid_pattern = re.compile(
            rb"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
        )
        uuid_matches = list(uuid_pattern.finditer(decrypted_full))

        if not uuid_matches:
            print("\nNo UUID4 found.")
            continue

        # ─── Step 6: Use the last UUID as the most plausible flag ─────────────────
        last_uuid_match = uuid_matches[-1]
        uuid = last_uuid_match.group(0).decode("utf-8")

        # ─── Step 7: Build the final flag ─────────────────────────────────────────
        flag = f"CRYPTO25{{{uuid}}}"
        print("\nFLAG FOUND!")
        print("Reconstructed flag:", flag)
        break

else:
    print("No valid keystream found.")

# ─── Flag ────────────────────────────────────────────────────────────────────────
# CRYPTO25{c0ec7b27-16e8-4c60-9aad-3a83dcc1597b}

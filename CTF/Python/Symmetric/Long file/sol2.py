#!/usr/bin/env python3
import sys

# —————————————————————————————————————————————————————————————————————————— #
# 1) Same helper to check “printable ASCII”:
#    Allow 0x20..0x7E (space..tilde) plus tab (0x09), LF (0x0A), CR (0x0D).
# —————————————————————————————————————————————————————————————————————————— #
def is_printable_ascii(b: int) -> bool:
    if 0x20 <= b <= 0x7E:
        return True
    if b in (0x09, 0x0A, 0x0D):
        return True
    return False

# —————————————————————————————————————————————————————————————————————————— #
# 2) “Crack a single column by maximizing space‐count”:
#    Input: column_bytes = ciphertext[j : j+1000 : step=1000]
#    Output: best key-byte K[j].
#
#    - Filter out any k that produces ANY non-printable byte.
#    - Among the survivors, pick k that yields the highest count of 0x20 bytes.
#    - If *no* candidate yields 100% printable ASCII, we fall back to picking the k
#      that simply maximizes “printable‐byte count” instead of requiring all printable.
# —————————————————————————————————————————————————————————————————————————— #
def crack_column_by_spaces(column_bytes: bytes) -> int:
    best_k = None
    best_space_count = -1
    best_printable_count = -1

    for k in range(256):
        # XOR‐decrypt the column with candidate k
        plain_candidate = bytes(b ^ k for b in column_bytes)

        # Count how many bytes are printable ASCII
        printable_flags = [is_printable_ascii(bc) for bc in plain_candidate]
        printable_count = sum(printable_flags)

        if printable_count == len(plain_candidate):
            # This k yields 100% printable ASCII
            # Now count how many of those are EXACTLY spaces (0x20)
            space_count = plain_candidate.count(0x20)
            if space_count > best_space_count:
                best_space_count = space_count
                best_k = k
                best_printable_count = printable_count

        else:
            # If no k ever makes the whole column printable, we record the “most printable”:
            # keep track of the k that gives the largest printable_count, to use as fallback.
            if printable_count > best_printable_count:
                best_printable_count = printable_count
                best_k = k
                # best_space_count stays as –1 or whatever; we only use printable_count in fallback.

    return best_k

# —————————————————————————————————————————————————————————————————————————— #
# 3) Main routine:
#    - Read “file.enc”
#    - For j = 0..999, build column_bytes = ciphertext[j::1000]
#    - Recover K[j] = crack_column_by_spaces(column_bytes)
#    - Decrypt entire ciphertext with repeating keystream[K[0..999]]
#    - Write output to “file.dec”
# —————————————————————————————————————————————————————————————————————————— #
def main():
    try:
        with open('file.enc', 'rb') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print("ERROR: Could not find 'file.enc' in the current directory.")
        sys.exit(1)

    L = len(ciphertext)
    PERIOD = 1000
    keystream = bytearray(PERIOD)

    print(f"[*] Loaded ciphertext; length = {L} bytes.")
    print(f"[*] Recovering each of the {PERIOD} keystream bytes via space‐count…\n")

    for j in range(PERIOD):
        # Gather every 1000th byte starting at position j
        column_indices = list(range(j, L, PERIOD))
        if not column_indices:
            # No data for this column (i.e. L < j). Just set K[j]=0
            keystream[j] = 0
            continue

        column_bytes = bytes(ciphertext[i] for i in column_indices)
        best_k = crack_column_by_spaces(column_bytes)
        keystream[j] = best_k

        # Print progress every 100 columns (or on last)
        if j % 100 == 0 or j == PERIOD - 1:
            print(f"    → Recovered K[{j}] = 0x{best_k:02x}")

    # Reassemble full plaintext
    print("\n[*] Decrypting full ciphertext with recovered 1000‐byte keystream…")
    plaintext = bytearray(L)
    for i in range(L):
        plaintext[i] = ciphertext[i] ^ keystream[i % PERIOD]

    # Write output
    outname = 'file.dec'
    with open(outname, 'wb') as f:
        f.write(plaintext)

    print(f"[+] Done! Plaintext written to '{outname}'. Open it (e.g. `less file.dec`) to verify.")

if __name__ == '__main__':
    main()

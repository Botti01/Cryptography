"""

Find a string that is both the same and different than another string!

nc 130.192.5.212 6631

"""

# ─── Attack ──────────────────────────────────────────────────────────────────────
# Collision attack on MD4 

# ─── Steps ──────────────────────────────────────────────────────────────────────
#   1. Use the `Collision()` function to generate two distinct messages m1, m2
#      such that MD4(m1) == MD4(m2).
#   2. Connect to the remote service.
#   3. Send m1 (hex-encoded) when prompted for the first string.
#   4. Send m2 (hex-encoded) when prompted for the second string.
#   5. Read and display the server’s response (the flag).

import socket
from MD4Collision import Collision  # provides m1, m2 collision generator

def main():
    # Step 1: Generate two colliding messages
    m1_hex, m2_hex, h1, h2 = Collision()
    print(f"Generated MD4 collision:\n MD4(m1) = {h1}\n MD4(m2) = {h2}\n")

    host = "130.192.5.212"
    port = 6631

    # Step 2: Connect to the remote CTF service
    with socket.create_connection((host, port)) as s:
        # Helper to receive until a specific prompt appears
        def recv_until(prompt: bytes) -> bytes:
            buf = b""
            while prompt not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    raise ConnectionError("Connection closed by remote host")
                buf += chunk
            return buf

        # Step 3: Wait for and send the first colliding string
        data = recv_until(b"Enter the first string:")
        print(data.decode(), end="")
        s.sendall((m1_hex + "\n").encode())

        # Step 4: Wait for and send the second colliding string
        data = recv_until(b"Enter your second string:")
        print(data.decode(), end="")
        s.sendall((m2_hex + "\n").encode())

        # Step 5: Read and print the remainder (flag or error)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            print(chunk.decode(), end="")

if __name__ == "__main__":
    main()



# ─── FLAG ───────────────────────────────────────────────────────────────────────
# CRYPTO25{4dc2e2e9-a14f-4382-8a44-f57852a626ef}

import hashlib
import os
import re
from binascii import unhexlify, hexlify
from secret import flag

# Secret key used for MAC generation (randomly generated at runtime)
SECRET = os.urandom(16)


def mac(message: bytes) -> str:
    # Computes a SHA-256 based MAC using the secret and the message
    return hashlib.sha256(SECRET + message).hexdigest()


def get_coupon(username: str) -> tuple[str, str]:
    # Generates a coupon for the given username with a fixed value of 10
    # Returns the hex-encoded coupon and its MAC
    # Sanitize username to allow only alphanumeric characters and underscores
    sanitized_username = re.sub(r"[^\w]", "", username)
    coupon = f"username={sanitized_username}&value=10".encode()
    return hexlify(coupon).decode(), mac(coupon)


def buy(coupon: str, mac_hex: str) -> str:
    # Verifies the MAC and processes the coupon purchase
    # If the value field is greater than 100, reveals the flag
    coupon = unhexlify(coupon)
    if mac(coupon) != mac_hex:
        return "Invalid MAC!"

    try:
        # Parse coupon fields into a dictionary
        fields = dict(kv.split(b"=", 1)
                      for kv in coupon.split(b"&") if b"=" in kv)
        if fields.get(b"username") is None or fields.get(b"value") is None:
            return "Missing required fields."

        if int(fields[b"value"]) > 100:
            # Successful purchase, flag is revealed
            return f"Purchase successful! Flag: {flag}"
        else:
            return "Insufficient balance!"
    except Exception as e:
        return f"Error: {e}"


def run_cli():
    # Command-line interface for interacting with the coupon system
    print("=== Welcome to HA-SHop ===")
    while True:
        print("\nMenu:")
        print("1. Get a coupon")
        print("2. Buy")
        print("3. Exit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            # User requests a coupon
            username = input("Enter your name: ").strip()
            msg, tag = get_coupon(username)
            print(f"\nCoupon: {msg}")
            print(f"MAC:     {tag}")

        elif choice == "2":
            # User attempts to redeem a coupon
            msg = input("Enter your coupon: ").strip()
            tag = input("Enter your MAC: ").strip()
            print(f"\nResult: {buy(msg, tag)}")

        elif choice == "3":
            # Exit the program
            print("Goodbye!")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    # Entry point for the CLI application
    run_cli()

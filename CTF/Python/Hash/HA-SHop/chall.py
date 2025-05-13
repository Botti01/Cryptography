import hashlib
import os
import re
from binascii import unhexlify, hexlify
from secret import flag

SECRET = os.urandom(16)


def mac(message: bytes) -> str:
    return hashlib.sha256(SECRET + message).hexdigest()


def get_coupon(username: str) -> tuple[str, str]:
    # Sanitize username to allow only alphanumeric characters and underscores
    sanitized_username = re.sub(r"[^\w]", "", username)
    coupon = f"username={sanitized_username}&value=10".encode()
    return hexlify(coupon).decode(), mac(coupon)


def buy(coupon: str, mac_hex: str) -> str:
    coupon = unhexlify(coupon)
    if mac(coupon) != mac_hex:
        return "Invalid MAC!"

    try:
        fields = dict(kv.split(b"=", 1)
                      for kv in coupon.split(b"&") if b"=" in kv)
        if fields.get(b"username") is None or fields.get(b"value") is None:
            return "Missing required fields."

        if int(fields[b"value"]) > 100:
            return f"Purchase successful! Flag: {flag}"
        else:
            return "Insufficient balance!"
    except Exception as e:
        return f"Error: {e}"


def run_cli():
    print("=== Welcome to HA-SHop ===")
    while True:
        print("\nMenu:")
        print("1. Get a coupon")
        print("2. Buy")
        print("3. Exit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            username = input("Enter your name: ").strip()
            msg, tag = get_coupon(username)
            print(f"\nCoupon: {msg}")
            print(f"MAC:     {tag}")

        elif choice == "2":
            msg = input("Enter your coupon: ").strip()
            tag = input("Enter your MAC: ").strip()
            print(f"\nResult: {buy(msg, tag)}")

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    run_cli()

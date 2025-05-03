from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
from random import randint
from secret import flag
from flask import Flask, session, jsonify, request
from flask_session import Session

app = Flask(__name__)
app.secret_key = get_random_bytes(16).hex()  # Generate a random secret key for Flask sessions
app.config['SESSION_TYPE'] = 'filesystem'  # Store session data in the filesystem
sess = Session()
sess.init_app(app)


def make_cipher():
    # Create a new ChaCha20 cipher with a random key and nonce
    key = get_random_bytes(32)  # Generate a 256-bit key
    nonce = get_random_bytes(12)  # Generate a 96-bit nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce, key, cipher


def sanitize_field(field: str):
    # Sanitize input fields by removing or replacing potentially dangerous characters
    return field \
        .replace(" ", "_") \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")


def parse_cookie(cookie: str) -> dict:
    # Parse a cookie string into a dictionary after sanitizing its fields
    parsed = {}
    for field in cookie.split("&"):
        key, value = field.split("=")
        key = sanitize_field(key)
        value = sanitize_field(value)
        parsed[key] = value

    return parsed


@app.route("/login", methods=["GET"])
def login():
    # Handle the login endpoint
    username = request.args.get("username")  # Get the username from the request
    admin = int(request.args.get("admin"))  # Get the admin flag from the request

    nonce, key, cipher = make_cipher()  # Generate a new cipher
    session['key'] = key  # Store the key in the session

    username = sanitize_field(username)  # Sanitize the username

    if admin != 1:
        admin = 0  # Ensure admin is either 0 or 1
    else:
        # Set an admin expiration date in the past
        session['admin_expire_date'] = int(time.time()) - randint(10, 259) * 24 * 60 * 60
    expire_date = int(time.time()) + 30 * 24 * 60 * 60  # Set the cookie expiration date to 30 days from now
    cookie = f"username={username}&expires={expire_date}&admin={admin}"  # Construct the cookie string

    return jsonify({
        "nonce": bytes_to_long(nonce),  # Return the nonce as a long integer
        "cookie": bytes_to_long(cipher.encrypt(cookie.encode()))  # Encrypt the cookie and return it as a long integer
    })


@app.route("/flag", methods=["GET"])
def get_flag():
    # Handle the flag endpoint
    nonce = int(request.args.get("nonce"))  # Get the nonce from the request
    cookie = int(request.args.get("cookie"))  # Get the encrypted cookie from the request

    cipher = ChaCha20.new(nonce=long_to_bytes(nonce), key=session['key'])  # Recreate the cipher using the nonce and session key

    try:
        dec_cookie = cipher.decrypt(long_to_bytes(cookie)).decode()  # Decrypt the cookie
        token = parse_cookie(dec_cookie)  # Parse the decrypted cookie

        if int(token["admin"]) != 1:
            return "You are not an admin!"  # Check if the user is an admin

        # Check if the admin expiration date is within the valid range
        if 290 * 24 * 60 * 60 < abs(int(token["expires"]) - session['admin_expire_date']) < 300 * 24 * 60 * 60:
            return f"OK! Your flag: {flag}"  # Return the flag if all conditions are met
        else:
            return "You have expired!"  # Expiration date is invalid
    except:
        return "Something didn't work :C"  # Handle decryption or parsing errors

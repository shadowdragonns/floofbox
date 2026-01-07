import os
import hmac
import hashlib
import base64

ITERATIONS = 200_000
SALT_SIZE = 16

def hash_password(password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    dk = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode(),
        salt,
        ITERATIONS
    )
    return base64.b64encode(salt + dk).decode()

def check_password(password: str, stored: str) -> bool:
    raw = base64.b64decode(stored.encode())
    salt = raw[:SALT_SIZE]
    stored_dk = raw[SALT_SIZE:]

    new_dk = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode(),
        salt,
        ITERATIONS
    )

    return hmac.compare_digest(stored_dk, new_dk)

import hashlib
import hmac
import math
import secrets
import time


def generate_shared_secret() -> str:
    return secrets.token_hex(16)


def dynamic_truncation(raw_key: hmac.HMAC, length: int) -> str:
    bitstring = bin(int(raw_key.hexdigest(), base=16))
    last_four_bits = bitstring[-4:]
    offset = int(last_four_bits, base=2)
    chosen_32_bits = bitstring[offset * 8 : offset * 8 + 32]
    full_totp = str(int(chosen_32_bits, base=2))

    return full_totp[-length:]


def generate_totp(shared_key: str, length: int = 6) -> str:
    now_in_seconds = math.floor(time.time())
    step_in_seconds = 30
    t = math.floor(now_in_seconds / step_in_seconds)
    hash = hmac.new(
        bytes(shared_key, encoding="utf-8"),
        t.to_bytes(length=8, byteorder="big"),
        hashlib.sha256,
    )

    return dynamic_truncation(hash, length)


def validate_totp(totp: str, shared_key: str) -> bool:
    return totp == generate_totp(shared_key)


if __name__ == "__main__":
    secret = input("Insert a secret, or leave blank to generate one.")
    if not secret:
        print("Generating shared secret key...")
        secret = generate_shared_secret()
        print(f"Done. It is: {secret}")

    print("Generating One-Time Password...")
    totp = generate_totp(secret)
    print(f"Done. It is: {totp}")

    print("Validating One-Time Password...")
    if validate_totp(totp, secret):
        print("It is valid!")
    else:
        print("It is invalid.")

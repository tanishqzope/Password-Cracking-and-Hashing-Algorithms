"""
Demo: salting for non-bcrypt hashes (MD5/SHA)
Run: python examples/demo_salting.py or python -m examples.demo_salting
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.salting import generate_salt, hash_with_salt, verify_hash_with_salt


def main():
    pw = "mysecret"
    salt = generate_salt(8)  # 8 bytes -> 16 hex chars
    print("=" * 50)
    print(" Salting & Verification Demonstration")
    print("=" * 50)
    print("Password       :", pw)
    print("Salt (hex)     :", salt)
    hashed = hash_with_salt(pw, salt, algo="sha256")
    print("Salted SHA256  :", hashed)
    print("Verify correct :", verify_hash_with_salt(pw, salt, hashed, algo="sha256"))
    print("Verify wrong   :", verify_hash_with_salt("wrong", salt, hashed, algo="sha256"))


if __name__ == "__main__":
    main()

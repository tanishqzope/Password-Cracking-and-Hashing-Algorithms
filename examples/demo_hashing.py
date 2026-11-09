"""
Demo: hashing using various algorithms
Run: python examples/demo_hashing.py or python -m examples.demo_hashing
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.hash_functions import (
    hash_md5,
    hash_sha256,
    hash_sha512,
    hash_bcrypt,
    verify_bcrypt,
    hash_pbkdf2_sha256,
    verify_pbkdf2_sha256,
)


def main():
    plaintext = "password123"
    print("=" * 50)
    print(" Hashing Algorithms Demonstration")
    print("=" * 50)
    print("Plaintext:", plaintext)
    print("\n--- Fast Digest Hashes (Integrity / Signatures) ---")
    print("MD5     :", hash_md5(plaintext))
    print("SHA256  :", hash_sha256(plaintext))
    print("SHA512  :", hash_sha512(plaintext))

    print("\n--- Adaptive Key Derivation Functions (Password Storage) ---")
    bcrypt_hash = hash_bcrypt(plaintext, rounds=12)
    print("bcrypt  :", bcrypt_hash)
    print("bcrypt verify (correct):", verify_bcrypt(plaintext, bcrypt_hash))
    print("bcrypt verify (wrong)  :", verify_bcrypt("badpass", bcrypt_hash))

    pbkdf2_hash = hash_pbkdf2_sha256(plaintext, iterations=100_000)
    print("\nPBKDF2  :", pbkdf2_hash)
    print("PBKDF2 verify (correct):", verify_pbkdf2_sha256(plaintext, pbkdf2_hash))
    print("PBKDF2 verify (wrong)  :", verify_pbkdf2_sha256("badpass", pbkdf2_hash))


if __name__ == "__main__":
    main()

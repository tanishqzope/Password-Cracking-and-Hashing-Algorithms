"""
Interactive CLI Runner for Password Cracking and Hashing Algorithms
"""
import sys
import subprocess
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.hash_functions import (
    hash_md5,
    hash_sha256,
    hash_sha512,
    hash_bcrypt,
    verify_bcrypt,
    hash_pbkdf2_sha256,
    verify_pbkdf2_sha256,
)
from src.salting import generate_salt, hash_with_salt, verify_hash_with_salt
from src.password_cracker import PasswordCracker
from src.utils import detect_hash_algorithm


def print_banner():
    print("=" * 60)
    print("  Password Cracking & Hashing Algorithms - Interactive CLI")
    print("=" * 60)


def menu():
    print("\nSelect an option:")
    print("  [1] Hash a password (MD5, SHA-256, SHA-512, bcrypt, PBKDF2)")
    print("  [2] Generate salted hash and verify")
    print("  [3] Run dictionary attack against a hash")
    print("  [4] Run small brute-force attack against a hash")
    print("  [5] Run full Pytest test suite")
    print("  [0] Exit")


def option_hash():
    pw = input("\nEnter password to hash: ").strip()
    if not pw:
        print("[!] Password cannot be empty.")
        return
    print("\n--- Hashes Generated ---")
    print(f"Plaintext : {pw}")
    print(f"MD5       : {hash_md5(pw)}")
    print(f"SHA-256   : {hash_sha256(pw)}")
    print(f"SHA-512   : {hash_sha512(pw)}")
    print("\nComputing adaptive key derivation functions...")
    bc = hash_bcrypt(pw, rounds=12)
    print(f"bcrypt    : {bc}")
    print(f"  -> verify correct: {verify_bcrypt(pw, bc)}")
    print(f"  -> verify wrong  : {verify_bcrypt('wrong_password', bc)}")

    pb = hash_pbkdf2_sha256(pw, iterations=100_000)
    print(f"PBKDF2    : {pb}")
    print(f"  -> verify correct: {verify_pbkdf2_sha256(pw, pb)}")
    print(f"  -> verify wrong  : {verify_pbkdf2_sha256('wrong_password', pb)}")


def option_salting():
    pw = input("\nEnter password to salt & hash: ").strip()
    if not pw:
        print("[!] Password cannot be empty.")
        return
    algo = input("Choose algorithm (md5 / sha256 / sha512) [default: sha256]: ").strip().lower() or "sha256"
    salt = generate_salt(8)
    print(f"\nGenerated Salt (hex): {salt}")
    hashed = hash_with_salt(pw, salt, algo=algo)
    print(f"Salted Hash ({algo}) : {hashed}")
    print(f"Verification check  : {verify_hash_with_salt(pw, salt, hashed, algo=algo)}")


def option_dictionary():
    target = input("\nEnter target hash to crack: ").strip()
    if not target:
        print("[!] Hash cannot be empty.")
        return
    wordlist = input("Path to wordlist [default: examples/wordlist_small.txt]: ").strip() or "examples/wordlist_small.txt"
    salt = input("Enter hex salt (leave blank if unsalted): ").strip() or None

    detected = detect_hash_algorithm(target)
    if not detected:
        print("[!] Could not auto-detect algorithm from hash length/format.")
        detected = input("Please specify algorithm (md5 / sha256 / sha512 / bcrypt / pbkdf2): ").strip().lower()
        if detected not in ("md5", "sha256", "sha512", "bcrypt", "pbkdf2"):
            print("[!] Invalid or unsupported algorithm.")
            return

    print(f"Algorithm: {detected}")
    try:
        cracker = PasswordCracker(target, algorithm=detected, salt=salt)
        found = cracker.dictionary_attack(wordlist)
        if found:
            print(f"\n[+] SUCCESS! Password found: '{found}'")
        else:
            print("\n[-] Password not found in wordlist.")
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] Error: {e}")


def option_bruteforce():
    target = input("\nEnter target hash to crack: ").strip()
    if not target:
        print("[!] Hash cannot be empty.")
        return
    max_len_str = input("Max password length to attempt [default: 3]: ").strip() or "3"
    try:
        max_len = int(max_len_str)
        if max_len < 1:
            print("[!] Length must be at least 1.")
            return
    except ValueError:
        print("[!] Invalid length.")
        return
    salt = input("Enter hex salt (leave blank if unsalted): ").strip() or None

    detected = detect_hash_algorithm(target)
    if not detected:
        print("[!] Could not auto-detect algorithm from hash length/format.")
        detected = input("Please specify algorithm (md5 / sha256 / sha512 / bcrypt / pbkdf2): ").strip().lower()
        if detected not in ("md5", "sha256", "sha512", "bcrypt", "pbkdf2"):
            print("[!] Invalid or unsupported algorithm.")
            return

    print(f"Algorithm: {detected}")
    if detected in ("bcrypt", "pbkdf2"):
        print("[!] Note: Brute-forcing slow KDFs (bcrypt/PBKDF2) is intentionally very slow.")
    print(f"Attempting brute-force up to length {max_len}...")
    try:
        cracker = PasswordCracker(target, algorithm=detected, salt=salt)
        found = cracker.brute_force(max_len=max_len)
        if found:
            print(f"\n[+] SUCCESS! Password found: '{found}'")
        else:
            print(f"\n[-] Password not found within length {max_len}.")
    except ValueError as e:
        print(f"[!] Error: {e}")


def option_tests():
    print("\nRunning pytest...")
    subprocess.run([sys.executable, "-m", "pytest", "-v"])


def main():
    print_banner()
    while True:
        menu()
        choice = input("\nEnter choice [0-5]: ").strip()
        if choice == "1":
            option_hash()
        elif choice == "2":
            option_salting()
        elif choice == "3":
            option_dictionary()
        elif choice == "4":
            option_bruteforce()
        elif choice == "5":
            option_tests()
        elif choice == "0":
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice, please select between 0 and 5.")


if __name__ == "__main__":
    main()

"""
Demo cracker script (CLI)
Examples:
  python examples/demo_cracker.py --mode dictionary --hash "<hash>" --wordlist examples/wordlist_small.txt
  python examples/demo_cracker.py --mode brute --hash "<hash>" --max-len 3
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse
from src.password_cracker import PasswordCracker
from src.utils import detect_hash_algorithm


def main():
    parser = argparse.ArgumentParser(description="Demo password cracker (educational).")
    parser.add_argument("--mode", choices=["dictionary", "brute"], required=True, help="Attack mode")
    parser.add_argument("--hash", dest="target_hash", required=True, help="Target hash to crack")
    parser.add_argument("--algo", choices=["md5", "sha256", "sha512", "bcrypt", "pbkdf2"], help="Hash algorithm (auto-detected if omitted)")
    parser.add_argument("--wordlist", help="Path to wordlist for dictionary attack")
    parser.add_argument("--max-len", type=int, default=4, help="Max length for brute-force (keep small!)")
    parser.add_argument("--salt", help="Hex salt (if target is salted sha/md5)")
    parser.add_argument("--charset", help="Custom charset for brute force")
    args = parser.parse_args()

    algo = args.algo or detect_hash_algorithm(args.target_hash)
    if not algo:
        print("[!] Error: Could not auto-detect hash algorithm. Please specify with --algo (md5, sha256, sha512, bcrypt, pbkdf2)")
        return

    print("Detected/Selected algorithm:", algo)
    try:
        cracker = PasswordCracker(args.target_hash, algorithm=algo, salt=args.salt)
    except ValueError as e:
        print(f"[!] Error: {e}")
        return

    if args.mode == "dictionary":
        if not args.wordlist:
            print("[!] Error: Dictionary mode requires --wordlist")
            return
        try:
            found = cracker.dictionary_attack(args.wordlist)
            if found:
                print(f"[+] FOUND: {found}")
            else:
                print("[-] Not found in wordlist.")
        except FileNotFoundError as e:
            print(f"[!] Error: {e}")
    else:
        found = cracker.brute_force(max_len=args.max_len, charset=args.charset)
        if found:
            print(f"[+] FOUND: {found}")
        else:
            print(f"[-] Not found with brute-force up to length {args.max_len}")


if __name__ == "__main__":
    main()

"""
Simple PasswordCracker class implementing:
- dictionary attack
- small brute-force attack (letters + digits) for short passwords
This is for educational/demo purposes only.
"""

import itertools
import string
from typing import Optional
from .utils import load_wordlist, detect_hash_algorithm, compare_hash
from .hash_functions import hash_md5, hash_sha256, hash_sha512, verify_bcrypt, verify_pbkdf2_sha256
from .salting import hash_with_salt


class PasswordCracker:
    def __init__(self, target_hash: str, algorithm: Optional[str] = None, salt: Optional[str] = None):
        """
        target_hash: the hash to crack
        algorithm: optional, if not provided we try to auto-detect
        salt: optional, hex salt for salted hashes (for MD5/SHA variants)
        """
        if not target_hash or not target_hash.strip():
            raise ValueError("Target hash cannot be empty.")

        self.target_hash = target_hash.strip()
        self.algorithm = (algorithm.strip().lower() if algorithm else None) or detect_hash_algorithm(self.target_hash)
        self.salt = salt.strip() if salt else None

        if self.algorithm is None:
            raise ValueError(
                f"Could not determine hash algorithm for target hash: '{self.target_hash}'. "
                "Please specify algorithm explicitly (e.g. md5, sha256, sha512, bcrypt, pbkdf2)."
            )

    def _hash_candidate(self, candidate: str) -> str:
        """Hash candidate based on selected algorithm."""
        algo = self.algorithm
        if algo == "md5":
            return hash_md5(candidate)
        if algo == "sha512":
            return hash_sha512(candidate)
        if algo == "sha256":
            return hash_sha256(candidate)
        return candidate

    def _verify_candidate(self, candidate: str) -> bool:
        """Verify whether a candidate plaintext matches the target hash."""
        if self.salt and self.algorithm in ("sha256", "sha512", "md5"):
            cand_hash = hash_with_salt(candidate, self.salt, algo=self.algorithm)
            return compare_hash(cand_hash, self.target_hash)
        elif self.algorithm == "bcrypt":
            return verify_bcrypt(candidate, self.target_hash)
        elif self.algorithm == "pbkdf2":
            return verify_pbkdf2_sha256(candidate, self.target_hash)
        else:
            cand_hash = self._hash_candidate(candidate)
            return compare_hash(cand_hash, self.target_hash)

    def dictionary_attack(self, wordlist_path: str) -> Optional[str]:
        """Try each word in wordlist to match the target hash."""
        words = load_wordlist(wordlist_path)
        for word in words:
            if self._verify_candidate(word):
                return word
        return None

    def brute_force(self, max_len: int = 4, charset: Optional[str] = None) -> Optional[str]:
        """
        Very small brute-force generator for demo:
        - max_len: max length to attempt (keep small for performance)
        - charset: string of characters to try; default is lowercase + digits
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits

        for length in range(1, max_len + 1):
            for tup in itertools.product(charset, repeat=length):
                candidate = "".join(tup)
                if self._verify_candidate(candidate):
                    return candidate
        return None

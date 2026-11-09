"""
Helper utilities:
- load_wordlist
- compare_hash (timing-safe)
- detect_hash_algorithm (heuristic based on format/length)
"""

from typing import List, Optional
import os
import hmac
import string


def load_wordlist(path: str) -> List[str]:
    """Load lines from a wordlist, stripping whitespace and skipping blank lines."""
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines


def compare_hash(candidate_hash: str, target_hash: str) -> bool:
    """Compare two hashes in constant-time (case-insensitive)."""
    return hmac.compare_digest(candidate_hash.strip().lower(), target_hash.strip().lower())


def detect_hash_algorithm(hash_str: str) -> Optional[str]:
    """
    Detector based on format and length:
    - MD5: 32 hex chars
    - SHA256: 64 hex chars
    - SHA512: 128 hex chars
    - bcrypt: starts with $2a$, $2b$, or $2y$ (typically ~60 chars)
    - pbkdf2: starts with pbkdf2:sha256:
    Returns 'md5', 'sha256', 'sha512', 'bcrypt', 'pbkdf2' or None
    """
    s = hash_str.strip()
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        return "bcrypt"
    if s.startswith("pbkdf2:"):
        return "pbkdf2"

    hex_len = len(s)
    # Check if string consists purely of hexadecimal characters
    if hex_len in (32, 64, 128) and all(c in string.hexdigits for c in s):
        if hex_len == 32:
            return "md5"
        if hex_len == 64:
            return "sha256"
        if hex_len == 128:
            return "sha512"

    return None

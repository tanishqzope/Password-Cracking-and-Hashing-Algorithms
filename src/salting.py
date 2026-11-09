"""
Simple salting utilities for non-bcrypt hashes.
bcrypt and PBKDF2 already contain salts internally, but for MD5/SHA you should add salt manually.
"""

import os
import hashlib
import hmac


def generate_salt(length: int = 16) -> str:
    """Generate a hex salt of `length` bytes (returned as hex string)."""
    return os.urandom(length).hex()


def hash_with_salt(plaintext: str, salt: str, algo: str = "sha256") -> str:
    """
    Hash plaintext + salt with chosen algorithm.
    - salt is a hex string
    - algo can be 'md5', 'sha256', 'sha512'
    Returns hex digest.
    """
    algo_lower = algo.lower()
    if algo_lower == "md5":
        h = hashlib.md5()
    elif algo_lower == "sha512":
        h = hashlib.sha512()
    elif algo_lower == "sha256":
        h = hashlib.sha256()
    else:
        # Support other hashlib algorithms dynamically if available
        try:
            h = hashlib.new(algo_lower)
        except ValueError:
            h = hashlib.sha256()

    # Combine as salt + password
    combined = (salt + plaintext).encode("utf-8")
    h.update(combined)
    return h.hexdigest()


def verify_hash_with_salt(plaintext: str, salt: str, expected_hash: str, algo: str = "sha256") -> bool:
    """Verify a salted hash using constant-time comparison to prevent timing attacks."""
    computed_hash = hash_with_salt(plaintext, salt, algo)
    return hmac.compare_digest(computed_hash.lower(), expected_hash.lower())

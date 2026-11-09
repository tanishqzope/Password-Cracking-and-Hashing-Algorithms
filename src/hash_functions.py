"""
Implementations of common hash functions:
- MD5
- SHA256
- SHA512
- bcrypt (password-focused)
- PBKDF2-HMAC-SHA256 (NIST-recommended password KDF)
"""

import hashlib
import hmac
import os
import bcrypt
from typing import Optional, Union


def hash_md5(plaintext: Union[str, bytes]) -> str:
    """Return MD5 hex digest of plaintext."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return hashlib.md5(plaintext).hexdigest()


def hash_sha256(plaintext: Union[str, bytes]) -> str:
    """Return SHA-256 hex digest of plaintext."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return hashlib.sha256(plaintext).hexdigest()


def hash_sha512(plaintext: Union[str, bytes]) -> str:
    """Return SHA-512 hex digest of plaintext."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return hashlib.sha512(plaintext).hexdigest()


def hash_bcrypt(plaintext: Union[str, bytes], rounds: int = 12) -> str:
    """
    Return a bcrypt hashed password (as a string).
    rounds: cost/work factor (default 12). Lower is faster; higher is slower but safer.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    salt = bcrypt.gensalt(rounds)
    hashed = bcrypt.hashpw(plaintext, salt)
    return hashed.decode("utf-8")


def verify_bcrypt(plaintext: Union[str, bytes], hashed: Union[str, bytes]) -> bool:
    """Verify plaintext against a bcrypt hash."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(hashed, str):
        hashed = hashed.encode("utf-8")
    try:
        return bcrypt.checkpw(plaintext, hashed)
    except ValueError:
        return False


def hash_pbkdf2_sha256(plaintext: Union[str, bytes], salt: Optional[str] = None, iterations: int = 100_000) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations by default.
    Returns serialized format: pbkdf2:sha256:<iterations>$<salt_hex>$<hash_hex>
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if salt is None:
        salt_bytes = os.urandom(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_hex = salt
        salt_bytes = bytes.fromhex(salt_hex)

    derived = hashlib.pbkdf2_hmac("sha256", plaintext, salt_bytes, iterations)
    return f"pbkdf2:sha256:{iterations}${salt_hex}${derived.hex()}"


def verify_pbkdf2_sha256(plaintext: Union[str, bytes], serialized_hash: str) -> bool:
    """Verify plaintext against a serialized PBKDF2 hash using timing-safe comparison."""
    try:
        header, salt_hex, expected_hex = serialized_hash.split("$")
        parts = header.split(":")
        iterations = int(parts[2])
        computed = hash_pbkdf2_sha256(plaintext, salt=salt_hex, iterations=iterations)
        return hmac.compare_digest(computed, serialized_hash)
    except (ValueError, IndexError):
        return False

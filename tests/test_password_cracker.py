import os
import hashlib
import pytest
from src.hash_functions import hash_md5, hash_bcrypt, hash_pbkdf2_sha256
from src.salting import hash_with_salt
from src.password_cracker import PasswordCracker

# Prepare a tiny wordlist file for the test
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "tmp_wordlist.txt")


def setup_module(module):
    with open(WORDLIST_PATH, "w") as f:
        f.write("\n".join(["abc", "testpw", "password123", "hello123"]))


def teardown_module(module):
    try:
        os.remove(WORDLIST_PATH)
    except OSError:
        pass


def test_dictionary_attack_md5():
    target = hash_md5("password123")
    cracker = PasswordCracker(target, algorithm="md5")
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found == "password123"


def test_dictionary_attack_bcrypt():
    target = hash_bcrypt("testpw", rounds=4)
    cracker = PasswordCracker(target, algorithm="bcrypt")
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found == "testpw"


def test_dictionary_attack_pbkdf2():
    target = hash_pbkdf2_sha256("hello123", iterations=500)
    cracker = PasswordCracker(target)
    assert cracker.algorithm == "pbkdf2"
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found == "hello123"


def test_dictionary_attack_salted_sha256():
    salt = "abcd1234ef567890"
    target = hash_with_salt("testpw", salt, algo="sha256")
    cracker = PasswordCracker(target, algorithm="sha256", salt=salt)
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found == "testpw"


def test_dictionary_attack_not_found():
    target = hash_md5("not_in_wordlist_xyz")
    cracker = PasswordCracker(target, algorithm="md5")
    found = cracker.dictionary_attack(WORDLIST_PATH)
    assert found is None


def test_cracker_invalid_inputs():
    with pytest.raises(ValueError):
        PasswordCracker("")
    with pytest.raises(ValueError):
        PasswordCracker("unknown_hash_format_not_hex")
    with pytest.raises(FileNotFoundError):
        cracker = PasswordCracker(hash_md5("abc"))
        cracker.dictionary_attack("non_existent_file.txt")


def test_bruteforce_small():
    # simple test: try to crack "ab" with md5 using brute_force with charset 'ab'
    pw = "ab"
    target = hashlib.md5(pw.encode()).hexdigest()
    cracker = PasswordCracker(target, algorithm="md5")
    found = cracker.brute_force(max_len=2, charset="ab")
    assert found == "ab"

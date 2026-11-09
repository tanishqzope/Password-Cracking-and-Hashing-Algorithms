# Password Cracking & Hashing Algorithms 🔐

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Testing: Pytest](https://img.shields.io/badge/Tested%20with-Pytest-0A9EDC.svg?logo=pytest&logoColor=white)](https://pytest.org/)
[![Security: Educational](https://img.shields.io/badge/Purpose-Educational%20%26%20Research-red.svg)](#-ethical-disclaimer)

> **Hands-on implementation, analysis, and testing of password security algorithms in Python.**  
> Covers **MD5, SHA-256, SHA-512, bcrypt, PBKDF2-HMAC-SHA256, cryptographic salting, and password cracking (dictionary & brute force)**.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Key Security Concepts](#-key-security-concepts)
  - [Algorithm Comparison Matrix](#algorithm-comparison-matrix)
  - [Cryptographic Salting](#cryptographic-salting)
  - [Password Cracking Mechanisms](#password-cracking-mechanisms)
- [Project Architecture](#-project-architecture)
- [Installation & Quick Start](#-installation--quick-start)
- [Running the Project](#-running-the-project)
  - [1. Interactive CLI Runner (Recommended)](#1-interactive-cli-runner-recommended)
  - [2. Standalone Demo Scripts](#2-standalone-demo-scripts)
  - [3. CLI Password Cracker](#3-cli-password-cracker)
- [Python API Usage](#-python-api-usage)
- [Running Unit Tests](#-running-unit-tests)
- [Git Repository Setup & Pushing](#-git-repository-setup--pushing)
- [Ethical Disclaimer](#-ethical-disclaimer)
- [Author & Acknowledgments](#-author--acknowledgments)

---

## 🧠 Overview

In cybersecurity, passwords should never be stored in plaintext. However, using general-purpose fast digests (such as unsalted MD5 or raw SHA-256) leaves credentials defenseless against high-speed GPU cracking, precomputed lookup tables, and rainbow tables.

This project provides an educational, modular reference suite in Python demonstrating:
1. **Fast cryptographic hash functions** (MD5, SHA-256, SHA-512) and why their high speed is dangerous for passwords.
2. **Adaptive key derivation functions** (`bcrypt`, `PBKDF2-HMAC-SHA256`) that incorporate configurable work factors and built-in salts to thwart GPU cracking.
3. **Cryptographic salting** using `os.urandom` to neutralize rainbow table lookups and identical hash correlation.
4. **Timing-safe digest comparison** (`hmac.compare_digest`) to prevent side-channel timing attacks.
5. **Practical password recovery techniques** demonstrating dictionary matching and combinatorial brute-force search.

---

## 🛡️ Key Security Concepts

### Algorithm Comparison Matrix

| Algorithm | Output Format | Collision Resistant? | Speed / GPU Resistance | Recommended for Passwords? |
| :--- | :--- | :--- | :--- | :--- |
| **MD5** | 128-bit hex (32 chars) | ❌ Broken (known collisions) | Extremely Fast (billions/sec) | 🚫 **Never** |
| **SHA-256** | 256-bit hex (64 chars) | ✅ Strong | Very Fast (hardware accelerated) | ⚠️ **Not alone** (requires KDF) |
| **SHA-512** | 512-bit hex (128 chars)| ✅ Strong | Fast | ⚠️ **Not alone** (requires KDF) |
| **PBKDF2-HMAC**| NIST serialized string | ✅ Strong | 🛡️ **Configurable Iterations** |  **Yes** (NIST Standard) |
| **bcrypt** | Standardized crypt string| ✅ Strong | 🛡️ **Adaptive Cost / Memory-Hard** |  **Yes** (Industry Standard) |

---

### Cryptographic Salting

A **salt** is unique, cryptographically random entropy appended or prepended to a password before hashing:

$$\text{Hash} = \text{H}(\text{Salt} \mathbin{\Vert} \text{Password})$$

- **Prevents Rainbow Tables:** Precomputed rainbow tables cannot be reused across different users because each user's unique salt requires a dedicated table.
- **Eliminates De-duplication:** Two users with the identical password (e.g., `password123`) produce completely different stored hashes.
- **Timing Safety:** This codebase implements `hmac.compare_digest` across all verifications to ensure constant-time comparison, eliminating timing attack vulnerabilities.

---

### Password Cracking Mechanisms

1. **Dictionary Attack:** Iterates through common password wordlists (e.g. `wordlist_small.txt`, `rockyou.txt`) to test pre-hashed candidates. Highly effective against predictable passwords.
2. **Brute-Force Attack:** Systematically computes hashes for all combinations of characters within a character set up to a given length ($O(|\Sigma|^L)$). Demonstrates why increasing password length and entropy drastically raises attack complexity.

---

## 🗂️ Project Architecture

```
Password-Cracking-and-Hashing-Algorithms/
├── docs/
│   ├── algorithm_explanations.md     # In-depth explanations of algorithms
│   ├── project_overview.md           # High-level architecture notes
│   └── screenshots/                  # Demonstration screenshots
│       ├── hash_demo.png
│       ├── crack_demo.png
│       └── salted_hash.png
├── src/
│   ├── __init__.py                   # Package exports
│   ├── hash_functions.py             # MD5, SHA-256, SHA-512, bcrypt, PBKDF2 implementations
│   ├── salting.py                    # Secure salt generator and timing-safe salted hashing
│   ├── password_cracker.py           # PasswordCracker engine (dictionary & brute force)
│   └── utils.py                      # Wordlist loading, timing-safe comparison, hash detection
├── examples/
│   ├── demo_hashing.py               # Compare fast hashes vs bcrypt vs PBKDF2
│   ├── demo_salting.py               # Demonstrate salting & verification
│   ├── demo_cracker.py               # CLI tool for dictionary & brute force recovery
│   └── wordlist_small.txt            # Sample wordlist for demonstrations
├── tests/
│   ├── test_hash_functions.py        # Pytest suite for hash digests & KDF roundtrips
│   ├── test_salting.py               # Pytest suite for salting and verification
│   └── test_password_cracker.py      # Pytest suite for dictionary and brute force cracking
├── main.py                           # Interactive CLI runner
├── requirements.txt                  # Project dependencies (bcrypt, pytest)
├── .gitignore                        # Git ignore rules for venv, cache, and temp files
└── README.md                         # Documentation
```

---

## ⚙️ Installation & Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/tanishqzope/Password-Cracking-and-Hashing-Algorithms.git
cd Password-Cracking-and-Hashing-Algorithms
```

### 2. Set Up Virtual Environment
* **Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  ```
* **macOS / Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Project

### 1. Interactive CLI Runner (Recommended)

Run the menu-driven application:

```bash
python main.py
```

Menu options:
```text
============================================================
  Password Cracking & Hashing Algorithms - Interactive CLI
============================================================

Select an option:
  [1] Hash a password (MD5, SHA-256, SHA-512, bcrypt, PBKDF2)
  [2] Generate salted hash and verify
  [3] Run dictionary attack against a hash
  [4] Run small brute-force attack against a hash
  [5] Run full Pytest test suite
  [0] Exit
```

---

### 2. Standalone Demo Scripts

Run individual demonstration scripts directly:

* **Hashing Demonstration:**
  ```bash
  python examples/demo_hashing.py
  ```
* **Salting & Verification Demonstration:**
  ```bash
  python examples/demo_salting.py
  ```

---

### 3. CLI Password Cracker

Run the command-line cracker on any target hash:

* **Dictionary Attack:**
  ```bash
  python examples/demo_cracker.py --mode dictionary --hash "482c811da5d5b4bc6d497ffa98491e38" --wordlist examples/wordlist_small.txt
  ```
  *Output:*
  ```text
  Detected algorithm: md5
  [+] FOUND: password123
  ```

* **Brute-Force Attack:**
  ```bash
  python examples/demo_cracker.py --mode brute --hash "8c1f1046219ddd216a023f792356ddf127fce372a72ec9b4cdac989ee5b0b455" --max-len 2
  ```
  *Output:*
  ```text
  Detected algorithm: sha256
  [+] FOUND: 99
  ```

---

## 💻 Python API Usage

Import and integrate modules directly into your own Python code:

```python
from src.hash_functions import hash_bcrypt, verify_bcrypt, hash_pbkdf2_sha256, verify_pbkdf2_sha256
from src.salting import generate_salt, hash_with_salt, verify_hash_with_salt
from src.password_cracker import PasswordCracker

# 1. Bcrypt Password Hashing
bc_hash = hash_bcrypt("Secret123!", rounds=12)
assert verify_bcrypt("Secret123!", bc_hash) is True

# 2. PBKDF2-HMAC-SHA256 (NIST Standard)
pb_hash = hash_pbkdf2_sha256("Secret123!", iterations=100_000)
assert verify_pbkdf2_sha256("Secret123!", pb_hash) is True

# 3. Custom Salted Hash with Constant-Time Verification
salt = generate_salt(16)
salted = hash_with_salt("Secret123!", salt, algo="sha256")
assert verify_hash_with_salt("Secret123!", salt, salted, algo="sha256") is True

# 4. Dictionary Recovery
cracker = PasswordCracker(target_hash="482c811da5d5b4bc6d497ffa98491e38", algorithm="md5")
cracked = cracker.dictionary_attack("examples/wordlist_small.txt")
print(f"Recovered: {cracked}")  # password123
```

---

## 🧪 Running Unit Tests

Run the full automated test suite with `pytest`:

```bash
pytest
```

Expected result:
```text
============================= test session starts =============================
platform win32 -- Python 3.14.x, pytest-9.2.0, pluggy-1.7.0
rootdir: ...
collected 10 items

tests\test_hash_functions.py .....                                       [ 50%]
tests\test_password_cracker.py ....                                      [ 90%]
tests\test_salting.py .                                                  [100%]

============================= 10 passed in 0.40s ==============================
```

---

## 🌐 Git Repository Setup & Pushing

To link and push this project to your GitHub repository:

```bash
# 1. Initialize git (if not already initialized)
git init -b main

# 2. Add remote origin
git remote add origin https://github.com/tanishqzope/Password-Cracking-and-Hashing-Algorithms.git

# 3. Stage and commit files
git add .
git commit -m "Initial commit: Password Cracking and Hashing Algorithms with interactive CLI"

# 4. Push to GitHub
git push -u origin main
```

---

## ⚠️ Ethical Disclaimer

> **FOR EDUCATIONAL AND DEFENSIVE AUDITING USE ONLY.**  
> This software is created to help students, developers, and security professionals understand password security fundamentals, verify authentication architectures, and test against common vulnerabilities. It must **not** be used against any target without explicit, documented authorization. The author and contributors assume no liability for misuse.

---

## ✍️ Author & Acknowledgments

- **Author:** [Tanishq Zope](https://github.com/tanishqzope)  
- **Repository:** [tanishqzope/Password-Cracking-and-Hashing-Algorithms](https://github.com/tanishqzope/Password-Cracking-and-Hashing-Algorithms.git)
- **Acknowledgments:** Python `hashlib` & `bcrypt` maintainers, open-source cybersecurity community.

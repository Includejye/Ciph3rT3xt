 Secure Cryptography System

## Project Overview

A Python application developed for the PSB500IT Cryptography coursework. It demonstrates cryptographic techniques for protecting files and messages, checking data integrity, and verifying digital signatures.

## Technologies

- Python
- cryptography library
- hashlib and hmac standard libraries
- Tkinter, if used by the graphical interface

## Cryptographic Functions

- AES-256-GCM encryption and decryption
- ChaCha20-Poly1305 encryption and decryption
- SHA-256 hashing
- HMAC-SHA256 generation and verification
- RSA-OAEP encryption and decryption
- RSA-PSS digital signatures

Only list the functions that are implemented and tested in the submitted version.

## Installation

Install Python 3, then install the dependency:

```bash
python -m pip install -r requirements.txt
```

## Running the Application

For the graphical interface:

```bash
python gui.py
```

For the command-line interface:

```bash
python main.py
```

## Testing

Run the available automated tests with:

```bash
python -m unittest
```

Confirm that the test files support this command before relying on it. Document the tests you actually perform and their results.

## Security Notice

For educational use and authorised testing only. Never publish private keys, secret keys, passwords, or confidential data.

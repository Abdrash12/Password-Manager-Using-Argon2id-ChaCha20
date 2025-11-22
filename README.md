# SecureVault CLI

A high-security, Zero-Knowledge password manager built for the command line.

Unlike standard password managers that rely on older cryptographic standards like PBKDF2 or AES-CBC, SecureVault uses Argon2id (winner of the Password Hashing Competition) for GPU/ASIC-resistant hashing, and ChaCha20-Poly1305 for authenticated encryption.

## Features

### Zero-Knowledge Architecture
- Your Master Password and Encryption Keys are never stored on disk.
- Keys exist only in RAM during your session.

### Modern Cryptography
- Hashing: Argon2id (memory-hard key derivation)
- Encryption: ChaCha20-Poly1305 (Authenticated Encryption with Associated Data)

### Local Storage
- Stores data using a local PostgreSQL database.

### Secure Inputs
- Password input is hidden (no asterisks) to prevent shoulder surfing.

### Portable
- Can be compiled into a single executable using PyInstaller.

## Tech Stack

### Language
- Python 3.x

### Database
- PostgreSQL

### Libraries
- argon2-cffi: Secure password hashing and key derivation
- pycryptodome: ChaCha20-Poly1305 encryption
- psycopg2-binary: PostgreSQL adapter
- tabulate: CLI table formatting

## Installation & Setup

### Prerequisites
- Python 3.8+
- PostgreSQL installed and running locally

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/securevault-cli.git
cd securevault-cli
```

2. Install Dependencies
pip install argon2-cffi pycryptodome psycopg2-binary tabulate pyinstaller
3. Configure Database
Update the DB_CONFIG dictionary inside vault.py with your local PostgreSQL credentials:
DB_CONFIG = {
    "dbname": "passmanager",
    "user": "postgres",
    "password": "your_password",
    "host": "localhost",
    "port": "5432"
}
Note: You do not need to manually create tables; the script creates them on the first run.
Usage
Run the Script
python vault.py
Compile into an Executable
pyinstaller --onefile --name="SecureVault" --hidden-import="psycopg2" --hidden-import="argon2" vault.py
First Run

The application will detect a fresh install.

You will be prompted to create a Master Password.

This password derives your encryption key.

Do not forget it; if lost, your data is unrecoverable.

Security Architecture

SecureVault uses a Two-Path Key Derivation system to separate authentication from encryption.

Path A (Authentication)

Input: Master Password

Algorithm: Argon2id

Output: Stored hash used to authenticate the user

Path B (Encryption Key)

Input: Master Password + Unique Encryption Salt

Algorithm: Argon2id (Raw Output)

Output: 32-byte key held only in RAM, used for ChaCha20 encryption and decryption

Disclaimer

This project is for educational and personal use. While it uses industry-standard cryptographic algorithms, ensure your machine is free from malware or keyloggers when handling sensitive data.

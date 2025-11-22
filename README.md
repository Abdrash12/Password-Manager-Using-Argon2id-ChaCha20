#SecureVault CLI
A high-security, Zero-Knowledge password manager built for the command line.

Unlike standard password managers that rely on older standards like PBKDF2 or AES-CBC, SecureVault utilizes Argon2id (winner of the Password Hashing Competition) for resistance against GPU/ASIC cracking and ChaCha20-Poly1305 for modern, authenticated encryption.

##Features:

Zero-Knowledge Architecture: Your Master Password and Encryption Keys are never stored on disk. They exist only in RAM during your session.

Modern Cryptography: * Hashing: Argon2id (Memory-hard key derivation).

Encryption: ChaCha20-Poly1305 (Authenticated Encryption with Associated Data).

Local Storage: Uses a local PostgreSQL database for robust data management.

Secure Inputs: Password inputs are hidden (no asterisks) to prevent shoulder surfing.

Portable: Can be compiled into a single .exe file using PyInstaller.

##Tech Stack:

Language: Python 3.x

Database: PostgreSQL

##Libraries:

argon2-cffi: For secure password hashing and key derivation.

pycryptodome: For ChaCha20-Poly1305 encryption.

psycopg2-binary: PostgreSQL adapter.

tabulate: For pretty-printing CLI tables.

##Installation & Setup:

Prerequisites

Python 3.8+ installed.

PostgreSQL installed and running locally.

##1. Clone the Repository

git clone [https://github.com/yourusername/securevault-cli.git](https://github.com/yourusername/securevault-cli.git)
cd securevault-cli


##2. Install Dependencies

pip install argon2-cffi pycryptodome psycopg2-binary tabulate pyinstaller


##3. Configure Database

Open vault.py and update the DB_CONFIG dictionary with your local Postgres credentials:

DB_CONFIG = {
    "dbname": "passmanager",
    "user": "postgres",
    "password": "your_password",  # <--- Update this
    "host": "localhost",
    "port": "5432"
}


Note: You do not need to create the tables manually; the script creates them automatically on the first run.

##Usage:

Run the script directly with Python:

python vault.py


Or compile it into an executable:

pyinstaller --onefile --name="SecureVault" --hidden-import="psycopg2" --hidden-import="argon2" vault.py


##First Run:

The app will detect a fresh install.

You will be prompted to create a Master Password.

This password derives your encryption key. Do not forget it. If lost, your data cannot be recovered.

##Security Architecture:

This application uses a Two-Path Key Derivation system to separate authentication from encryption:

##Path A (Authentication): * Input: Master Password.

Algo: Argon2id.

Result: Stored in DB to verify you are the correct user.

##Path B (Encryption Key):

Input: Master Password + Unique Encryption Salt.

Algo: Argon2id (Raw Output).

##Result: A 32-byte key held only in RAM. It is used to encrypt/decrypt your vault via ChaCha20.

##Disclaimer:

This project is for educational purposes and personal use. While it uses industry-standard algorithms, always ensure your local machine is free from malware/keyloggers when handling sensitive passwords.

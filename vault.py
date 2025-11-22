import os
import sys
import getpass
import psycopg2
from tabulate import tabulate

# Cryptography Imports
from argon2 import PasswordHasher, Type
from argon2.low_level import hash_secret_raw
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

# --- CONFIGURATION ---
# UPDATE THESE TO MATCH YOUR LOCAL POSTGRES SETUP
DB_CONFIG = {
    "dbname": "meow",
    "user": "postgres",
    "password": "johar118",
    "host": "localhost",
    "port": "5432"
}

class CryptoManager:
    def __init__(self):
        # Argon2id for Master Password Hashing
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, type=Type.ID)
        self.encryption_key = None # RAM ONLY - NEVER STORED

    def generate_salt(self):
        return get_random_bytes(16)

    def derive_key(self, password, salt):
        """
        Uses Argon2id to turn the password + salt into a 32-byte raw key.
        This key is used for the ChaCha20 encryption.
        """
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32, # 32 bytes = 256 bits (Standard for ChaCha20)
            type=Type.ID
        )

    def encrypt_data(self, plaintext):
        if not self.encryption_key:
            raise ValueError("Vault locked. Key not in RAM.")
        
        # ChaCha20-Poly1305 (Authenticated Encryption)
        # This automatically generates a unique Nonce for every encryption
        cipher = ChaCha20_Poly1305.new(key=self.encryption_key)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        return {
            'nonce': cipher.nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        }

    def decrypt_data(self, nonce_hex, ciphertext_hex, tag_hex):
        if not self.encryption_key:
            raise ValueError("Vault locked. Key not in RAM.")

        try:
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            tag = bytes.fromhex(tag_hex)

            # Reconstruct the cipher with the nonce used during encryption
            cipher = ChaCha20_Poly1305.new(key=self.encryption_key, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        except (ValueError, KeyError):
            return "[Decryption Failed: Data Corrupted or Wrong Key]"

class DatabaseManager:
    def __init__(self):
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.conn.autocommit = True
            self.init_db()
        except Exception as e:
            print(f"Database Error: {e}")
            print("Ensure Postgres is running and DB_CONFIG in the script is correct.")
            input("Press Enter to exit...")
            sys.exit(1)

    def init_db(self):
        with self.conn.cursor() as cur:
            # Table for the Master Password Check (Path A)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS master_auth (
                    id SERIAL PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    encryption_salt TEXT NOT NULL
                );
            """)
            # Table for the actual secrets (Path B)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id SERIAL PRIMARY KEY,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    tag TEXT NOT NULL
                );
            """)

    def is_setup(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM master_auth")
            return cur.fetchone()[0] > 0

    def register_master(self, password_hash, enc_salt_hex):
        with self.conn.cursor() as cur:
            # Clear old master if exists (simulation for this example)
            cur.execute("TRUNCATE master_auth") 
            cur.execute(
                "INSERT INTO master_auth (password_hash, encryption_salt) VALUES (%s, %s)",
                (password_hash, enc_salt_hex)
            )

    def get_master_auth(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT password_hash, encryption_salt FROM master_auth LIMIT 1")
            return cur.fetchone()

    def save_secret(self, service, username, crypto_data):
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO secrets (service, username, ciphertext, nonce, tag)
                VALUES (%s, %s, %s, %s, %s)
            """, (service, username, crypto_data['ciphertext'], crypto_data['nonce'], crypto_data['tag']))

    def get_all_secrets(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT id, service, username, ciphertext, nonce, tag FROM secrets ORDER BY id ASC")
            return cur.fetchall()

    def delete_secret(self, secret_id):
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM secrets WHERE id = %s", (secret_id,))
            return cur.rowcount > 0

# --- APP LOGIC ---

crypto = CryptoManager()
db = DatabaseManager()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def setup_vault():
    clear_screen()
    print("=== FIRST TIME SETUP ===")
    print("We need to create your Master Password.")
    print("WARNING: If you forget this, your data is lost forever.\n")
    
    while True:
        pw1 = getpass.getpass("Create Master Password: ")
        pw2 = getpass.getpass("Confirm Master Password: ")
        
        if pw1 == pw2 and len(pw1) > 0:
            break
        print("Passwords do not match or are empty. Try again.")

    # 1. Create Auth Hash (For logging in)
    auth_hash = crypto.ph.hash(pw1)
    
    # 2. Generate Salt for Encryption Key Derivation
    enc_salt = crypto.generate_salt()
    
    # 3. Save to DB
    db.register_master(auth_hash, enc_salt.hex())
    
    print("\nVault Initialized Successfully!")
    input("Press Enter to Login...")

def login_screen():
    clear_screen()
    if not db.is_setup():
        setup_vault()
        clear_screen()

    print("=== VAULT LOGIN ===")
    stored_auth = db.get_master_auth()
    stored_hash = stored_auth[0]
    enc_salt = bytes.fromhex(stored_auth[1])

    while True:
        pw = getpass.getpass("Enter Master Password: ")
        
        try:
            # 1. Verify Auth Hash
            crypto.ph.verify(stored_hash, pw)
            
            # 2. If successful, Derive the Encryption Key (Path B)
            print("Verifying...")
            crypto.encryption_key = crypto.derive_key(pw, enc_salt)
            break
        except:
            print("Wrong password.")
            retry = input("Try again? (y/n): ")
            if retry.lower() != 'y':
                sys.exit()

def menu_add_password():
    clear_screen()
    print("--- Add New Secret ---")
    service = input("Service (e.g. Google): ")
    username = input("Username/Email: ")
    password = getpass.getpass("Password: ")
    
    if not password:
        print("Password cannot be empty.")
        return

    encrypted_data = crypto.encrypt_data(password)
    db.save_secret(service, username, encrypted_data)
    print(f"\nSuccessfully saved password for {service}!")
    input("Press Enter to return...")

def menu_view_passwords():
    clear_screen()
    print("--- My Passwords ---")
    
    secrets = db.get_all_secrets()
    
    if not secrets:
        print("No passwords stored.")
        input("Press Enter to return...")
        return

    table_data = []
    for row in secrets:
        s_id, service, user, c_text, nonce, tag = row
        try:
            # Decrypt on the fly
            decrypted_pass = crypto.decrypt_data(nonce, c_text, tag)
            table_data.append([s_id, service, user, decrypted_pass])
        except Exception:
            table_data.append([s_id, service, user, "ERROR"])

    print(tabulate(table_data, headers=["ID", "Service", "Username", "Password"], tablefmt="fancy_grid"))
    input("\nPress Enter to return...")

def menu_delete_password():
    clear_screen()
    print("--- Delete Password ---")
    secrets = db.get_all_secrets()
    
    # Show list first
    display_data = [[r[0], r[1], r[2]] for r in secrets]
    print(tabulate(display_data, headers=["ID", "Service", "Username"], tablefmt="simple"))
    
    try:
        target_id = int(input("\nEnter ID to delete (or 0 to cancel): "))
        if target_id == 0: return
        
        if db.delete_secret(target_id):
            print("Entry deleted.")
        else:
            print("ID not found.")
    except ValueError:
        print("Invalid input.")
    
    input("Press Enter to return...")

def main_menu():
    login_screen()
    
    while True:
        clear_screen()
        print("=== SECURE VAULT (ChaCha20) ===")
        print("1. View Passwords")
        print("2. Add Password")
        print("3. Delete Password")
        print("4. Exit")
        
        choice = input("\nSelect Option: ")
        
        if choice == '1':
            menu_view_passwords()
        elif choice == '2':
            menu_add_password()
        elif choice == '3':
            menu_delete_password()
        elif choice == '4':
            # Wipe key from RAM before exit
            crypto.encryption_key = None
            sys.exit()

if __name__ == "__main__":
    main_menu()
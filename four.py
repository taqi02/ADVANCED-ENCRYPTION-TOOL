import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(password: str, input_path: str, output_path: str):
    if not os.path.exists(input_path):
        print(f"[ERROR] Input file not found: {input_path}")
        return

    if os.path.exists(output_path):
        overwrite = input(f"[!] Output file '{output_path}' exists. Overwrite? (y/n): ").strip().lower()
        if overwrite != 'y':
            print("Encryption cancelled.")
            return

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    with open(input_path, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted)

    print("✅ File encrypted successfully.")

def decrypt_file(password: str, input_path: str, output_path: str):
    if not os.path.exists(input_path):
        print(f"[ERROR] Encrypted file not found: {input_path}")
        return

    if os.path.exists(output_path):
        overwrite = input(f"[!] Output file '{output_path}' exists. Overwrite? (y/n): ").strip().lower()
        if overwrite != 'y':
            print("Decryption cancelled.")
            return

    with open(input_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted = f.read()

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    try:
        decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

        with open(output_path, 'wb') as f:
            f.write(decrypted)

        print("✅ File decrypted successfully.")
    except Exception as e:
        print("[ERROR] Decryption failed. Wrong password or corrupt file.")

def main():
    print("=== AES-256 File Encryption Tool ===")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Exit")

    choice = input("Enter your choice (1/2/3): ").strip()

    if choice not in {'1', '2'}:
        print("Goodbye.")
        sys.exit()

    input_path = input("Enter input file path: ").strip()
    output_path = input("Enter output file path: ").strip()

    if choice == '1':
        while True:
            password = getpass("Create a password: ")
            confirm = getpass("Confirm password: ")
            if password != confirm:
                print("[!] Passwords do not match. Try again.")
            elif len(password) < 6:
                print("[!] Use a longer password (6+ characters recommended).")
            else:
                break
        encrypt_file(password, input_path, output_path)

    elif choice == '2':
        password = getpass("Enter password: ")
        decrypt_file(password, input_path, output_path)

if __name__ == "__main__":
    main()

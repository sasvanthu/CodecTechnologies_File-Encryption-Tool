import os
import sys
import getpass
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet key from password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename):
    """
    Encrypt the given file and produce <filename>.enc
    """
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        return

    output_filename = filename + ".enc"
    if os.path.exists(output_filename):
        print(f"Error: Encrypted file '{output_filename}' already exists. Aborting.")
        return

    password = getpass.getpass("Enter password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        with open(filename, 'rb') as file:
            data = file.read()
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return

    encrypted_data = fernet.encrypt(data)

    try:
        with open(output_filename, 'wb') as file:
            file.write(salt + encrypted_data)
        print(f"File '{filename}' encrypted successfully as '{output_filename}'")
    except Exception as e:
        print(f"Error writing encrypted file '{output_filename}': {e}")

def decrypt_file(encrypted_filename, output_filename):
    """
    Decrypt an encrypted file (produced by encrypt_file).
    """
    if not os.path.exists(encrypted_filename):
        print(f"Error: Encrypted file '{encrypted_filename}' not found.")
        return

    if os.path.exists(output_filename):
        print(f"Error: Output file '{output_filename}' already exists. Aborting.")
        return

    password = getpass.getpass("Enter password: ")

    try:
        with open(encrypted_filename, 'rb') as file:
            salt = file.read(16)
            encrypted_data = file.read()
    except Exception as e:
        print(f"Error reading encrypted file '{encrypted_filename}': {e}")
        return

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("Decryption failed! Possibly wrong password or corrupted file.")
        return

    try:
        with open(output_filename, 'wb') as file:
            file.write(decrypted_data)
        print(f"File '{encrypted_filename}' decrypted successfully as '{output_filename}'")
    except Exception as e:
        print(f"Error writing decrypted file '{output_filename}': {e}")

def print_usage():
    print("Usage:")
    print("  python file_encryptor_password.py encrypt <filename>")
    print("  python file_encryptor_password.py decrypt <encrypted_filename> <output_filename>")

def main():
    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    command = sys.argv[1]

    if command == "encrypt" and len(sys.argv) == 3:
        encrypt_file(sys.argv[2])
    elif command == "decrypt" and len(sys.argv) == 4:
        decrypt_file(sys.argv[2], sys.argv[3])
    else:
        print("Invalid command or arguments.")
        print_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()

import os
import sys
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

# derive a Fernet key from password and salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename):
    password = getpass.getpass("Enter password: ")
    salt = os.urandom(16)  # generate a new random salt
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filename, 'rb') as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    # write salt + encrypted data to output file
    with open(filename + ".enc", 'wb') as file:
        file.write(salt + encrypted_data)

    print(f"File '{filename}' encrypted as '{filename}.enc'")

def decrypt_file(encrypted_filename, output_filename):
    password = getpass.getpass("Enter password: ")

    with open(encrypted_filename, 'rb') as file:
        salt = file.read(16)  # read first 16 bytes as salt
        encrypted_data = file.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print("Decryption failed! Possibly wrong password.")
        return

    with open(output_filename, 'wb') as file:
        file.write(decrypted_data)

    print(f"File '{encrypted_filename}' decrypted as '{output_filename}'")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python file_encryptor_password.py encrypt <filename>")
        print("  python file_encryptor_password.py decrypt <encrypted_filename> <output_filename>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "encrypt" and len(sys.argv) == 3:
        encrypt_file(sys.argv[2])
    elif command == "decrypt" and len(sys.argv) == 4:
        decrypt_file(sys.argv[2], sys.argv[3])
    else:
        print("Invalid command or arguments.")

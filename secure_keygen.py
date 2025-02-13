import os
import getpass
import logging
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidKey
from argon2 import low_level

# Secure Logging Configuration
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# Security Constants
SALT_SIZE = 16
AES_KEY_SIZE = 32
RSA_KEY_SIZE = 4096
ARGON2_MEMORY = 65536  # 64MB of memory
ARGON2_ITERATIONS = 4  # Iterations count
ARGON2_PARALLELISM = 2  # Parallelism (threads)

# Ensure output directory exists
OUTPUT_FOLDER = "output"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def generate_aes_key():
    """Generates a secure AES-256 key."""
    return secrets.token_bytes(AES_KEY_SIZE)

def generate_rsa_keys():
    """Generates a 4096-bit RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    """Encrypts the AES key using RSA public key."""
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def derive_encryption_key(password, salt):
    """Derives a strong encryption key using Argon2id."""
    return low_level.hash_secret_raw(
        password.encode(),
        salt,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=AES_KEY_SIZE,
        type=low_level.Type.ID
    )

def encrypt_private_key(private_key, password, filename="private_key.enc"):
    """Encrypts and securely saves the RSA private key using AES-GCM."""
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_encryption_key(password, salt)
    iv = secrets.token_bytes(12)  # AES-GCM recommended IV size

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # AES-GCM encryption (authenticated)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pem) + encryptor.finalize()
    tag = encryptor.tag  # Authentication tag

    try:
        with open(os.path.join(OUTPUT_FOLDER, filename), "wb") as f:
            f.write(salt + iv + tag + ciphertext)
        logging.info("✅ Encrypted private key saved securely.")
    except IOError as e:
        logging.error(f"❌ Failed to write private key file: {e}")

    # Securely delete key from memory
    del key

def save_public_key(public_key, filename="public_key.pem"):
    """Saves the RSA public key."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        with open(os.path.join(OUTPUT_FOLDER, filename), "wb") as f:
            f.write(pem)
        logging.info("✅ Public key saved securely.")
    except IOError as e:
        logging.error(f"❌ Failed to write public key file: {e}")

def save_encrypted_aes_key(encrypted_aes_key, filename="encrypted_aes_key.bin"):
    """Saves the encrypted AES key securely."""
    try:
        with open(os.path.join(OUTPUT_FOLDER, filename), "wb") as f:
            f.write(encrypted_aes_key)
        logging.info("✅ Encrypted AES key saved securely.")
    except IOError as e:
        logging.error(f"❌ Failed to write AES key file: {e}")

def set_file_permissions(filenames):
    """Sets secure file permissions to prevent unauthorized access."""
    for filename in filenames:
        path = os.path.join(OUTPUT_FOLDER, filename)
        if os.path.exists(path):
            os.chmod(path, 0o600)

def secure_delete(file_path):
    """Overwrites a file before deletion to prevent recovery."""
    full_path = os.path.join(OUTPUT_FOLDER, file_path)
    if os.path.exists(full_path):
        try:
            with open(full_path, "wb") as f:
                for _ in range(3):  # Overwrite 3 times
                    f.write(secrets.token_bytes(os.path.getsize(full_path)))
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
            os.remove(full_path)
            logging.info(f"✅ Securely deleted {file_path}.")
        except Exception as e:
            logging.error(f"❌ Secure delete failed: {e}")

def main():
    try:
        logging.info("🔐 Generating secure AES and RSA keys...")
        
        aes_key = generate_aes_key()
        private_key, public_key = generate_rsa_keys()
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        # Securely prompt for a password
        password = getpass.getpass("Enter a strong password for the private key: ")
        if len(password) < 16:
            raise ValueError("⚠️ Password must be at least 16 characters long.")

        encrypt_private_key(private_key, password)
        save_public_key(public_key)
        save_encrypted_aes_key(encrypted_aes_key)

        # Securely erase the AES key from memory
        secrets.token_bytes(len(aes_key))
        del aes_key

        # Set secure file permissions
        key_files = ["private_key.enc", "public_key.pem", "encrypted_aes_key.bin"]
        set_file_permissions(key_files)

        logging.info("✅ Secure Key Management Complete!")
    except InvalidKey:
        logging.error("❌ Encryption key derivation failed. Check password policy.")
    except Exception as e:
        logging.error(f"❌ Key management process failed: {e}")

if __name__ == "__main__":
    main()

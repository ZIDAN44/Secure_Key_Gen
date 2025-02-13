import os
import json
import getpass
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import low_level

# Get absolute path of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "../output")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Paths to key files
AES_KEY_FILE = os.path.join(OUTPUT_DIR, "encrypted_aes_key.bin")
PRIVATE_KEY_FILE = os.path.join(OUTPUT_DIR, "private_key.enc")
ENCRYPTED_DATA_FILE = os.path.join(OUTPUT_DIR, "encrypted_data.json")

# Get password securely
private_key_password = os.environ.get("PRIVATE_KEY_PASSWORD") or getpass.getpass("Enter the password for the private key: ").strip()
private_key_password = private_key_password.encode('utf-8')

# Load encrypted RSA private key
with open(PRIVATE_KEY_FILE, "rb") as f:
    encrypted_private_key = f.read()

# Extract encryption parameters
salt, iv, tag, ciphertext = encrypted_private_key[:16], encrypted_private_key[16:28], encrypted_private_key[28:44], encrypted_private_key[44:]

# Derive decryption key
key = low_level.hash_secret_raw(
    private_key_password, salt, time_cost=4, memory_cost=65536, parallelism=2, hash_len=32, type=low_level.Type.ID
)

# Decrypt RSA private key
cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
decryptor = cipher.decryptor()
private_key_pem = decryptor.update(ciphertext) + decryptor.finalize()
private_key = serialization.load_pem_private_key(private_key_pem, password=None)

# Load and decrypt AES key
with open(AES_KEY_FILE, "rb") as f:
    encrypted_aes_key = f.read()

aes_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Load encrypted data
with open(ENCRYPTED_DATA_FILE, "r") as f:
    encrypted_output = json.load(f)

# Convert hex to bytes
encrypted_data = bytes.fromhex(encrypted_output["ciphertext"])
iv, ciphertext, tag = encrypted_data[:12], encrypted_data[12:-16], encrypted_data[-16:]

# Decrypt data using AES-GCM
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
decryptor = cipher.decryptor()
decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

# Convert decrypted JSON text to dictionary and print original data
original_data = json.loads(decrypted_text.decode())["data"]
print(f"🔓 Decrypted Data: {original_data}")

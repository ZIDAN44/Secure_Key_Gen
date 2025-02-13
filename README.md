# 🔐 SecureKeyGen - A Secure Key Generating Tool

SecureKeyGen is a Python-based tool that generates secure keys. It allows users to securely encrypt and decrypt data with a randomly generated key.

## 🚀 Features
- AES-256 key generation
- RSA-4096 key pair generation
- Secure encryption of the private key with Argon2id & AES-GCM
- Public key encryption of AES key (RSA-OAEP)
- Data encryption and decryption with AES-GCM

---

## 📂 Project Structure
```
SecureKeyGen/
│── output/
│   ├── private_key.enc           # Encrypted RSA private key
│   ├── public_key.pem            # RSA public key
│   ├── encrypted_aes_key.bin     # AES key encrypted with RSA
│   ├── encrypted_data.json       # Encrypted user data
│
│── test/
│   ├── encrypt_data.py           # Encrypts user data using AES key
│   ├── decrypt_data.py           # Decrypts and retrieves original data
│
│── secure_keygen.py              # Main key generating script
│── requirements.txt              # Dependencies for the project
│── .gitignore                    # Specifies files to exclude from Git
│── LICENSE                       # License file
│── README.md                     # Documentation
```

---

## 🔑 Key Generation Process
1. **Clone the Repository**
   ```sh
   git clone https://github.com/ZIDAN44/Secure_Key_Gen.git
   cd Secure_Key_Gen
   ```

2. **Create a Virtual Environment**
   ```sh
   python -m venv .venv
   source .venv/bin/activate  # On macOS/Linux
   .venv\Scripts\activate     # On Windows
   ```

3. **Install Dependencies**
   ```sh
   pip install -r requirements.txt
   ```

4. **Generate Secure Keys**
   ```sh
   python secure_keygen.py
   ```
   **Note:** You'll be prompted to enter a **strong password** for private key.

---

## 🛠️ Test Case

### 🔒 Encrypt Data
Run the encryption script and enter data to encrypt:
```sh
python test/encrypt_data.py
```
This will encrypt the input data and save it in `output/encrypted_data.json`.

### 🔓 Decrypt Data
Run the decryption script to retrieve the original input:
```sh
python test/decrypt_data.py
```
You'll need to enter the **same password** used during key generation.

---

## 🔐 Security Features
✅ **AES-256 Encryption** - Ensures strong data protection
✅ **RSA-4096 Key Pair** - Asymmetric encryption for key security
✅ **Argon2id Key Derivation** - Strong password-based key derivation
✅ **AES-GCM Authenticated Encryption** - Prevents data tampering

---

## ⚠️ Security Disclaimer
SecureKeyGen is designed with modern cryptographic best practices in mind; however, no system is guaranteed to be 100% secure.
Given sufficient time and computational power, any encryption method may be compromised.
To ensure the highest level of security, always follow best practices for key management and keep sensitive keys private.

***🚨This project is intended as a demonstration and should not be used in production level without proper security evaluation!!***

---

## Credits

- [**Zinadin Zidan**](https://github.com/ZIDAN44)

---

## 📝 License
This project is licensed under the [MIT License](LICENSE).

---

## 📢 Contributing
Feel free to fork, modify, and submit pull requests! For major changes, please open an issue first.

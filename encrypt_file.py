import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

# Function to generate a random AES key
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

# Function to encrypt a file with AES
def encrypt_file(file_path, aes_key):
    iv = os.urandom(16)  # Initialization Vector (IV)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Read the file and pad it if necessary
    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length  # PKCS7 Padding

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the encrypted file
    with open(file_path + ".enc", "wb") as f:
        f.write(iv + ciphertext)

    print(f"File '{file_path}' encrypted successfully!")

# Function to encrypt AES key with RSA
def encrypt_aes_key(aes_key, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("aes_key.enc", "wb") as key_file:
        key_file.write(encrypted_key)

    print("AES Key encrypted successfully!")

# Main execution
if __name__ == "__main__":
    file_path = input("Enter the file path to encrypt: ")
    aes_key = generate_aes_key()
    encrypt_file(file_path, aes_key)
    encrypt_aes_key(aes_key, "public_key.pem")

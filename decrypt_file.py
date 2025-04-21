from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Function to decrypt AES key with RSA
def decrypt_aes_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    with open("aes_key.enc", "rb") as key_file:
        encrypted_key = key_file.read()

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key

# Function to decrypt a file with AES
def decrypt_file(file_path, aes_key):
    with open(file_path, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]  # Remove padding

    original_file_path = file_path.replace(".enc", "")

    with open(original_file_path, "wb") as f:
        f.write(plaintext)

    print(f"File '{original_file_path}' decrypted successfully!")

# Main execution
if __name__ == "__main__":
    file_path = input("Enter the encrypted file path: ")
    aes_key = decrypt_aes_key("private_key.pem")
    decrypt_file(file_path, aes_key)

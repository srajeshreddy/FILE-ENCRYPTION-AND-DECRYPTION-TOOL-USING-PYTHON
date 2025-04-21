import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

# Function to generate a random AES key
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

# Function to encrypt AES key with RSA
def encrypt_aes_key(aes_key, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.MGF1(algorithm=hashes.SHA256())),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("aes_key.enc", "wb") as key_file:
        key_file.write(encrypted_key)

# Function to decrypt AES key with RSA
def decrypt_aes_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    with open("aes_key.enc", "rb") as key_file:
        encrypted_key = key_file.read()

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.MGF1(algorithm=hashes.SHA256())),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Function to encrypt a file with AES
def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if not file_path:
        return
    
    aes_key = generate_aes_key()
    iv = os.urandom(16)  # Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        plaintext = f.read()
    
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length]) * padding_length  # PKCS7 Padding

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + ciphertext)

    encrypt_aes_key(aes_key, "public_key.pem")

    progress_bar["value"] = 100
    messagebox.showinfo("Success", f"✅ File Encrypted Successfully!\nSaved as: {encrypted_file_path}")

# Function to decrypt a file with AES
def decrypt_file():
    file_path = filedialog.askopenfilename(title="Select Encrypted File to Decrypt")
    if not file_path:
        return
    
    aes_key = decrypt_aes_key("private_key.pem")

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

    progress_bar["value"] = 100
    messagebox.showinfo("Success", f"✅ File Decrypted Successfully!\nRestored as: {original_file_path}")

# Function to toggle between dark and light mode
def toggle_theme():
    if root.tk.call("ttk::style", "theme", "use") == "clam":
        root.tk.call("ttk::style", "theme", "use", "alt")
    else:
        root.tk.call("ttk::style", "theme", "use", "clam")

# GUI Setup
root = tk.Tk()
root.title("🔒 Secure File Encryptor & Decryptor - Fares")
root.geometry("600x500")
root.configure(bg="#121212")

# Apply ttk theme
style = ttk.Style()
root.tk.call("ttk::style", "theme", "use", "clam")  # Dark theme

style.configure("TButton", font=("Arial", 12), padding=10, background="#00bfff", foreground="black")
style.configure("TLabel", font=("Arial", 14, "bold"), background="#121212", foreground="white")
style.configure("TFrame", background="#121212")

# Top Label with Name
title_label = ttk.Label(root, text="🔒 Secure File Encryptor & Decryptor", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# Frame for buttons
button_frame = ttk.Frame(root)
button_frame.pack(pady=20)

# Encrypt Button
encrypt_button = ttk.Button(button_frame, text="🔐 Encrypt File", command=encrypt_file)
encrypt_button.grid(row=0, column=0, padx=20, pady=10)

# Decrypt Button
decrypt_button = ttk.Button(button_frame, text="🔓 Decrypt File", command=decrypt_file)
decrypt_button.grid(row=0, column=1, padx=20, pady=10)

# Progress Bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=20)

# Drag & Drop Feature (Future Feature)
drop_label = ttk.Label(root, text="(Drag & Drop Feature Coming Soon!)", font=("Arial", 10))
drop_label.pack(pady=5)

# Theme Toggle Button
theme_button = ttk.Button(root, text="🌙 Toggle Dark/Light Mode", command=toggle_theme)
theme_button.pack(pady=10)

# Exit Button
exit_button = ttk.Button(root, text="🚪 Exit", command=root.quit)
exit_button.pack(pady=20)

# **Created by Fares Label (Bottom Right)**
credits_label = ttk.Label(root, text="Created by Fares", font=("Arial", 10), background="#121212", foreground="gray")
credits_label.pack(side="bottom", anchor="se", padx=10, pady=10)  # Align bottom right

root.mainloop()

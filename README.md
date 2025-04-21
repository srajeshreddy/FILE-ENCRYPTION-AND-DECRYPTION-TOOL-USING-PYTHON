# 🔒 File Encryption & Decryption Tool
### **A secure file encryption and decryption tool using AES & RSA, with a user-friendly GUI.**

---

## 🌜 Features
👉 **AES Encryption** for secure file protection  
👉 **RSA Key Encryption** to securely store the AES key  
👉 **User-Friendly GUI** with an intuitive interface  
👉 **Dark & Light Mode Toggle**  
👉 **Progress Bar for Encryption/Decryption**  
👉 **Drag & Drop Label (Future Feature)**  

---

## 🚀 Installation & Setup
### 🔹 Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/file-encryptor.git
cd file-encryptor
```

### 🔹 Step 2: Install Required Dependencies
Make sure you have **Python 3.7+** installed. Then, install the required libraries:
```bash
pip install cryptography tk
```

### 🔹 Step 3: Generate RSA Keys
Before encrypting files, generate your **RSA key pair**:
```bash
python generate_keys.py
```
This will create:
- **`private_key.pem`** → Used for **decryption** (Keep it secure)
- **`public_key.pem`** → Used for **encryption**

---

## 🎡 Usage
### 🔹 Run the GUI
```bash
python gui_encryptor.py
```
A window will open with options to encrypt and decrypt files.

### 🔹 Encrypt a File
1. Click **"Encrypt File"**.
2. Select any file (e.g., `.txt`, `.pdf`, `.jpg`, `.mp4`).
3. The tool will:
   - Encrypt the selected file and save it as **`filename.enc`**.
   - Encrypt the AES key and save it as **`aes_key.enc`**.
4. ✅ **Success Message:**  
   `"File Encrypted Successfully!"`

### 🔹 Decrypt a File
1. Click **"Decrypt File"**.
2. Select the encrypted file (`filename.enc`).
3. The tool will:
   - Decrypt the AES key using **`private_key.pem`**.
   - Restore the file to its original state.
4. ✅ **Success Message:**  
   `"File Decrypted Successfully!"`


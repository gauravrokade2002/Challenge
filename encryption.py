import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    try:
        salt = secrets.token_bytes(16)
        key = generate_key(password, salt)

        with open(file_path, "rb") as f:
            data = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted and saved as: {save_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def decrypt_file(encrypted_file_path: str, password: str):
    try:
        with open(encrypted_file_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        iv = content[16:32]
        encrypted_data = content[32:]

        key = generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        save_path = filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
        if not save_path:
            return

        with open(save_path, "wb") as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted and saved as: {save_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = simpledialog.askstring("Password", "Enter a password for encryption", show='*')
        if password:
            encrypt_file(file_path, password)

def select_file_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = simpledialog.askstring("Password", "Enter the password for decryption", show='*')
        if password:
            decrypt_file(file_path, password)

def main():
    root = tk.Tk()
    root.title("File Encryption and Decryption Tool")
    root.geometry("400x200")

    encrypt_button = tk.Button(root, text="Encrypt File", command=select_file_encrypt, width=20, height=2)
    encrypt_button.pack(pady=20)

    decrypt_button = tk.Button(root, text="Decrypt File", command=select_file_decrypt, width=20, height=2)
    decrypt_button.pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    main()

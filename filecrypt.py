import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def encrypt_data(data, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_data)

def decrypt_data(encrypted_data, password):
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def select_file():
    return filedialog.askopenfilename(filetypes=[("All Files", "*.*")])

def save_file(data, file_path):
    with open(file_path, "wb") as file:
        file.write(data)

def on_encrypt_file():
    file_path = select_file()
    if not file_path:
        return
    
    password = password_entry.get()
    if not password:
        messagebox.showerror("Input Error", "Password field cannot be empty.")
        return
    
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = encrypt_data(file_data, password)
        
        # Add .enc suffix to the original file name
        encrypted_file_path = file_path + ".enc"
        save_file(encrypted_data, encrypted_file_path)
        
        password_entry.delete(0, "end")
        messagebox.showinfo("Success", f"File encrypted successfully. Saved as {encrypted_file_path}.")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def on_decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if not file_path:
        return
    
    password = password_entry.get()
    if not password:
        messagebox.showerror("Input Error", "Password field cannot be empty.")
        return
    
    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = decrypt_data(encrypted_data, password)
        
        # Restore the original file extension by removing .enc suffix
        original_file_path = file_path.rsplit(".enc", 1)[0]
        save_file(decrypted_data, original_file_path)
        
        password_entry.delete(0, "end")
        messagebox.showinfo("Success", f"File decrypted successfully. Saved as {original_file_path}.")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def clear_entries():
    password_entry.delete(0, "end")

# Initialize the main window
ctk.set_appearance_mode("dark")  # Set dark mode
ctk.set_default_color_theme("blue")  # Set color theme

root = ctk.CTk()
root.title("File Cryptography GUI")
root.geometry("500x400")  # Resize the window
root.resizable(False, False)

# Create widgets
ctk.CTkLabel(root, text="Enter your password here:", font=("Arial", 16)).pack(pady=(20, 10))
password_entry = ctk.CTkEntry(root, show="*", font=("Arial", 14), width=400)
password_entry.pack(pady=10)

instructions = ctk.CTkLabel(root, text="1. Enter password first.\n2. Click 'Encrypt File' or 'Decrypt File' to select a file.", font=("Arial", 12))
instructions.pack(pady=(10, 20))

button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=20)

encrypt_button = ctk.CTkButton(button_frame, text="Encrypt File", command=on_encrypt_file, width=120)
encrypt_button.pack(side="left", padx=10)

decrypt_button = ctk.CTkButton(button_frame, text="Decrypt File", command=on_decrypt_file, width=120)
decrypt_button.pack(side="left", padx=10)

clear_button = ctk.CTkButton(button_frame, text="Clear", command=clear_entries, width=120)
clear_button.pack(side="left", padx=10)

# Start the main loop
root.mainloop()

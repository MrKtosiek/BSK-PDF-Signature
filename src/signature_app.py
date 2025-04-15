import os
import hashlib
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tkinter import filedialog


def load_private_key_from_pendrive(pendrive_path):
    private_key_file = open(os.path.join(pendrive_path, "private_key.enc"), "rb")
    encrypted_private_key = private_key_file.read()
    private_key_file.close()
    return encrypted_private_key


def decrypt_private_key(pin, encrypted_private_key):
    key = hashlib.sha256(pin.encode()).digest()
    iv = encrypted_private_key[:16]
    ciphertext = encrypted_private_key[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def main():
    """
    @brief Initializes the GUI application for key generation and saving.
    """
    root = ttk.Window(themename="superhero")
    root.title("Podpis Elektroniczny")
    root.geometry("800x400")

    title_1 = ttk.Label(root, text="Podpis elektroniczny", font=("Arial", 20, "bold"), bootstyle=INFO)
    title_2 = ttk.Label(root, text="Generator kluczy🗝️", font=("Arial", 15, "bold"), bootstyle=INFO)
    title_1.pack(pady=(30, 0))
    title_2.pack(pady=(0, 30))

    ttk.Label(root, text="Kod PIN do zaszyfrowania klucza prywatnego:").pack(pady=5)
    pin_entry = ttk.Entry(root, show="*")
    pin_entry.pack(pady=10)

    ttk.Label(root, text="Lokalizacja Pendrive:").pack(pady=5)
    path_entry = ttk.Entry(root, width=40)
    path_entry.pack(pady=5)

    browse_button = ttk.Button(root, text="Przeglądaj", command=lambda: path_entry.insert(0, filedialog.askdirectory()))
    browse_button.pack(pady=5)

    message_label = ttk.Label(root, text="", foreground="red")
    message_label.pack()

    def sign_document():
        """
        @brief Handles the process of signing a PDF with an encrypted private key from a pendrive.
        """
        pin = pin_entry.get()
        pendrive_path = path_entry.get()  # TODO: replace with automatic detection
        if not pin or not pendrive_path:
            message_label.config(text="Wpisz PIN i wybierz lokalizację pendrive!", foreground="red")
            return
        encrypted_private_key = load_private_key_from_pendrive(pendrive_path)
        private_key = decrypt_private_key(pin, encrypted_private_key)
        print(private_key)

    generate_button = ttk.Button(root, text="Podpisz dokument", command=sign_document, bootstyle=SUCCESS)
    generate_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()

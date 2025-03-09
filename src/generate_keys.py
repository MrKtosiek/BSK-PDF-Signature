import os
import hashlib
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from tkinter import filedialog


def generate_rsa_keys():
    """
    @brief Generates a pair of RSA keys (private and public).
    @return Tuple containing private_key and public_key in bytes.
    """
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_private_key_with_pin(private_key, pin):
    """
    @brief Encrypts the private key using AES encryption with a user-defined PIN.
    @param private_key The private RSA key in bytes.
    @param pin The user-defined PIN for encryption.
    @return Encrypted private key with an IV prepended.
    """
    key = hashlib.sha256(pin.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(private_key, AES.block_size))


def save_keys_to_pendrive(encrypted_private_key, public_key, pendrive_path, message_label):
    """
    @brief Saves encrypted private and public keys to a specified pendrive path.
    @param encrypted_private_key The encrypted private key in bytes.
    @param public_key The public key in bytes.
    @param pendrive_path The file path of the USB drive.
    @param message_label The GUI label to display status messages.
    """
    private_key_file = open(os.path.join(pendrive_path, "private_key.enc"), "wb")
    public_key_file = open(os.path.join(pendrive_path, "public_key.pem"), "wb")
    
    private_key_file.write(encrypted_private_key)
    public_key_file.write(public_key)
    message_label.config(text="Klucze zapisane pomyślnie!", foreground="green")

    private_key_file.close()
    public_key_file.close()


def main():
    """
    @brief Initializes the GUI application for key generation and saving.
    """
    root = ttk.Window(themename="superhero")
    root.title("Podpis Elektroniczny - Generator Kluczy")
    root.geometry("800x400")

    title_1 = ttk.Label(root, text="Podpis elektroniczny", font=("Arial", 20, "bold"), bootstyle=INFO)
    title_2 = ttk.Label(root, text="Generator kluczy🗝️", font=("Arial", 15, "bold"), bootstyle=INFO)
    title_1.pack(pady=(30,0))
    title_2.pack(pady=(0,30))

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

    def generate_and_save_keys():
        """
        @brief Handles the process of generating and saving RSA keys.
        """
        pin = pin_entry.get()
        pendrive_path = path_entry.get()
        if not pin or not pendrive_path:
            message_label.config(text="Wpisz PIN i wybierz lokalizację pendrive!", foreground="red")
            return
        private_key, public_key = generate_rsa_keys()
        encrypted_private_key = encrypt_private_key_with_pin(private_key, pin)
        save_keys_to_pendrive(encrypted_private_key, public_key, pendrive_path, message_label)

    generate_button = ttk.Button(root, text="Wygeneruj klucze", command=generate_and_save_keys, bootstyle=SUCCESS)
    generate_button.pack(pady=10)
    
    root.mainloop()


if __name__ == "__main__":
    main()
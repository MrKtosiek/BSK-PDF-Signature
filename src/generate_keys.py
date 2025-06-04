import os
import hashlib
import ttkbootstrap as ttk
import rsa
from ttkbootstrap.constants import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import psutil
from tkinter import filedialog
import threading
import time


def generate_rsa_keys():
    """
    @brief Generates a pair of RSA keys (private and public).
    @return Tuple containing private_key and public_key in bytes.
    """
    (pubkey, privkey) = rsa.newkeys(4096)
    private_key = privkey.save_pkcs1(format='PEM')
    public_key = pubkey.save_pkcs1(format='PEM')
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


def save_keys(encrypted_private_key, public_key, pendrive_path, public_key_path, message_label):
    """
    @brief Saves encrypted private key to pendrive and public key to specified location.
    @param encrypted_private_key The encrypted private key in bytes.
    @param public_key The public key in bytes.
    @param pendrive_path The path to the USB drive for private key.
    @param public_key_path The path to save public key.
    @param message_label The GUI label to display status messages.
    """
    try:
        private_key_file = open(os.path.join(pendrive_path, "private_key.enc"), "wb")
        private_key_file.write(encrypted_private_key)
        private_key_file.close()
        
        public_key_file = open(os.path.join(public_key_path, "public_key.pem"), "wb")
        public_key_file.write(public_key)
        public_key_file.close()
        
        message_label.config(text="Keys saved successfully!", foreground="green")
    except Exception as e:
        message_label.config(text=f"Error saving keys: {str(e)}", foreground="red")


def find_pendrive():
    """
    @brief Finds the first removable drive (pendrive) connected to the system.
    @return Path to the pendrive or None if not found.
    """
    partitions = psutil.disk_partitions()
    for partition in partitions:
        if 'removable' in partition.opts.lower():
            return partition.mountpoint
    return None


def main():
    """
    @brief Initializes the GUI application for key generation and saving.
    """
    root = ttk.Window(themename="superhero")
    root.title("Digital Signature - Key Generator")
    root.geometry("800x500")

    title_1 = ttk.Label(root, text="Digital Signature", font=("Arial", 20, "bold"), bootstyle=INFO)
    title_2 = ttk.Label(root, text="Key Generator 🗝️", font=("Arial", 15, "bold"), bootstyle=INFO)
    title_1.pack(pady=(30,0))
    title_2.pack(pady=(0,30))

    # PIN
    ttk.Label(root, text="PIN to encrypt private key:").pack(pady=5)
    pin_entry = ttk.Entry(root, show="*")
    pin_entry.pack(pady=10)
    
    # Pendrive
    pendrive_frame = ttk.Frame(root)
    pendrive_frame.pack(fill=X, padx=20, pady=5)
    ttk.Label(pendrive_frame, text="USB Drive Status:").pack(side=TOP)
    pendrive_status = ttk.Label(pendrive_frame, text="Checking...", font=("Arial", 10))
    pendrive_status.pack(side=TOP, padx=10)

    # Public Key Location
    public_key_frame = ttk.Frame(root)
    public_key_frame.pack(fill=X, padx=20, pady=5)
    ttk.Label(public_key_frame, text="Public Key Location:").pack(side=TOP)
    public_key_path_entry = ttk.Entry(public_key_frame, width=40)
    public_key_path_entry.pack(side=TOP, padx=5, pady=5)
    browse_public = ttk.Button(public_key_frame, text="Browse", command=lambda: public_key_path_entry.insert(0, filedialog.askdirectory()), bootstyle=INFO)
    browse_public.pack(side=TOP)

    # Message
    message_label = ttk.Label(root, text="", foreground="red")
    message_label.pack(pady=10)

    def check_pendrive():
        """
        @brief Checks for pendrive presence and updates status.
        @return Path to pendrive if found, None otherwise
        """
        pendrive_path = find_pendrive()
        if pendrive_path:
            pendrive_status.config(text=f"Detected: {pendrive_path}", foreground="green")
            return pendrive_path
        else:
            pendrive_status.config(text="Not detected. Please insert USB drive.", foreground="red")
            return None

    def auto_check_pendrive():
        """
        @brief Automatically checks for pendrive every second
        """
        while True:
            check_pendrive()
            time.sleep(1)

    def generate_and_save_keys():
        """
        @brief Handles the process of generating and saving RSA keys.
        """
        pin = pin_entry.get()
        if not pin:
            message_label.config(text="Please enter PIN!", foreground="red")
            return
        
        pendrive_path = check_pendrive()
        if not pendrive_path:
            message_label.config(text="USB drive not detected!", foreground="red")
            return
            
        public_key_path = public_key_path_entry.get()
        if not public_key_path:
            message_label.config(text="Please select public key location!", foreground="red")
            return
            
        try:
            private_key, public_key = generate_rsa_keys()
            encrypted_private_key = encrypt_private_key_with_pin(private_key, pin)
            save_keys(encrypted_private_key, public_key, pendrive_path, public_key_path, message_label)
        except Exception as e:
            message_label.config(text=f"Error: {str(e)}", foreground="red")

    # Buttons
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=10)

    generate_button = ttk.Button(
        button_frame, 
        text="Generate Keys", 
        command=generate_and_save_keys, 
        bootstyle=SUCCESS
    )
    generate_button.pack(side=LEFT, padx=5)
    
    # Pendrive checking
    pendrive_thread = threading.Thread(target=auto_check_pendrive, daemon=True)
    pendrive_thread.start()
    
    root.mainloop()


if __name__ == "__main__":
    main()
import os
import hashlib
import rsa
import time
import threading
import base64
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO
import psutil


def find_pendrive():
    for part in psutil.disk_partitions():
        if 'removable' in part.opts or ('/media' in part.mountpoint or 'usb' in part.device.lower()):
            return part.mountpoint
    return None


def load_private_key_from_pendrive(pendrive_path):
    path = os.path.join(pendrive_path, "private_key.enc")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    return None


def decrypt_private_key(pin, encrypted_private_key):
    key = hashlib.sha256(pin.encode()).digest()
    iv = encrypted_private_key[:16]
    ciphertext = encrypted_private_key[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return rsa.PrivateKey.load_pkcs1(decrypted)


def sign_pdf(file_path, private_key):

    # 1. Wczytanie PDF
    reader = PdfReader(file_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    # 2. Hash i podpis
    pdf_content = b"".join(page.extract_text().encode() for page in reader.pages if page.extract_text())
    signature = rsa.sign(pdf_content, private_key, "SHA-256")
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    # 3. Zapisujemy podpis w metadanych
    metadata = reader.metadata or {}
    updated_metadata = {**metadata, "/DigitalSignature": signature_b64}
    writer.add_metadata(updated_metadata)

    # 4. Zapis pliku
    signed_path = file_path.replace(".pdf", "_signed.pdf")
    with open(signed_path, "wb") as f:
        writer.write(f)

    return signed_path


def check_signature(file_path, key_path):

    # 1. Wczytanie PDF
    reader = PdfReader(file_path)
    metadata = reader.metadata or {}
    pdf_content = b"".join(page.extract_text().encode() for page in reader.pages if page.extract_text())

    # 2. Wczytanie klucza publicznego
    with open(key_path, "rb") as f:
        public_key_data = f.read()
        public_key = rsa.PublicKey.load_pkcs1(public_key_data, format="PEM")

    # 3. Wczytanie i odkodowanie podpisu
    signature_b64 = metadata.get("/DigitalSignature")
    signature = base64.b64decode(signature_b64)

    # 4. Weryfikacja podpisu
    try:
        rsa.verify(pdf_content, signature, public_key)
        return True
    except rsa.VerificationError:
        return False


def main():
    root = ttk.Window(themename="superhero")
    root.title("Digital Signature")
    root.geometry("800x500")

    ttk.Label(root, text="Digital Signature", font=("Arial", 20, "bold"), bootstyle=INFO).pack(pady=(30, 0))
    ttk.Label(root, text="Signing/Veryfing PDF File", font=("Arial", 15, "bold"), bootstyle=INFO).pack(pady=(0, 30))

    ttk.Label(root, text="PIN code to decode private key:").pack()
    pin_entry = ttk.Entry(root, show="*")
    pin_entry.pack(pady=10)

    # Pendrive info
    pendrive_frame = ttk.Frame(root)
    pendrive_frame.pack(fill=X, padx=20, pady=5)
    ttk.Label(pendrive_frame, text="USB Drive Status:").pack(side=TOP)
    pendrive_status = ttk.Label(pendrive_frame, text="Checking...", font=("Arial", 10))
    pendrive_status.pack(side=TOP)

    # Wybór pliku
    pdf_path = ttk.StringVar()
    def choose_pdf():
        path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if path:
            pdf_path.set(path)
            pdf_label.config(text=f"Chosen: {os.path.basename(path)}", foreground="green")

    ttk.Button(root, text="Choose PDF file", command=choose_pdf).pack(pady=5)
    pdf_label = ttk.Label(root, text="File not chosen", foreground="gray")
    pdf_label.pack()

    # Wybór klucza publicznego
    public_key_path = ttk.StringVar()
    def choose_public_key():
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if path:
            public_key_path.set(path)
            public_key_label.config(text=f"Chosen: {os.path.basename(path)}", foreground="green")

    ttk.Button(root, text="Choose public key", command=choose_public_key).pack(pady=5)
    public_key_label = ttk.Label(root, text="File not chosen", foreground="gray")
    public_key_label.pack()

    message_label = ttk.Label(root, text="", foreground="red")
    message_label.pack()

    detected_pendrive = {"path": None}
    def check_pendrive():
        path = find_pendrive()
        if path:
            pendrive_status.config(text=f"Detected: {path}", foreground="green")
            detected_pendrive["path"] = path
        else:
            pendrive_status.config(text="Not detected. Insert USB drive.", foreground="red")
            detected_pendrive["path"] = None

    def auto_check_pendrive():
        while True:
            check_pendrive()
            time.sleep(1)

    def sign_button_action():
        pin = pin_entry.get()
        pendrive_path = detected_pendrive["path"]
        file_path = pdf_path.get()

        if not file_path:
            message_label.config(text="Choose PDF file path!", foreground="red")
            return

        if not pin or not pendrive_path:
            message_label.config(text="Enter PIN and connect pendrive!", foreground="red")
            return

        encrypted_key = load_private_key_from_pendrive(pendrive_path)
        if not encrypted_key:
            message_label.config(text="No file private_key.enc on pendrive!", foreground="red")
            return

        try:
            private_key = decrypt_private_key(pin, encrypted_key)
        except Exception as e:
            message_label.config(text="Wrong PIN code! " + str(e), foreground="red")
            return

        try:
            signed_file = sign_pdf(file_path, private_key)
            message_label.config(text=f"Document has been successfully signed: {os.path.basename(signed_file)}", foreground="green")
        except Exception as e:
            message_label.config(text="Error: " + str(e), foreground="red")

    def check_button_action():
        file_path = pdf_path.get()
        key_path = public_key_path.get()

        if not file_path:
            message_label.config(text="Choose PDF file path!", foreground="red")
            return
        if not key_path:
            message_label.config(text="Choose public key file path!", foreground="red")
            return

        try:
            signature_valid = check_signature(file_path, key_path)
        except:
            message_label.config(text=f"Document signature is invalid: {os.path.basename(file_path)}", foreground="red")
            return

        if signature_valid:
            message_label.config(text=f"Document signature is valid: {os.path.basename(file_path)}", foreground="green")
        else:
            message_label.config(text=f"Document signature is invalid: {os.path.basename(file_path)}", foreground="red")

    ttk.Button(root, text="Sign document", command=sign_button_action, bootstyle=SUCCESS).pack(pady=15)
    ttk.Button(root, text="Check signature", command=check_button_action, bootstyle=SUCCESS).pack(pady=15)

    threading.Thread(target=auto_check_pendrive, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    main()

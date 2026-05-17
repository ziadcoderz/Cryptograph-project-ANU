import tkinter as tk
from tkinter import ttk, messagebox
import base64
import urllib.parse
import hashlib
import os

# استيراد مكتبات التشفير المحترفة
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding


class CryptoToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Toolkit - Team Project")
        self.root.geometry("750x600")

        # متغيرات تخزين مفاتيح RSA لتوليدها واستخدامها
        self.rsa_private_key = None
        self.rsa_public_key = None

        # إنشاء التبويبات (Tabs) لتنظيم التطبيق
        tab_control = ttk.Notebook(root)

        self.tab_sym = ttk.Frame(tab_control)
        self.tab_asym = ttk.Frame(tab_control)
        self.tab_enc = ttk.Frame(tab_control)
        self.tab_hash = ttk.Frame(tab_control)

        tab_control.add(self.tab_sym, text='Symmetric Crypto')
        tab_control.add(self.tab_asym, text='Asymmetric (RSA)')
        tab_control.add(self.tab_enc, text='Encoding/Decoding')
        tab_control.add(self.tab_hash, text='Hashing')

        tab_control.pack(expand=1, fill="both")

        # بناء واجهات التبويبات
        self.build_symmetric_tab()
        self.build_asymmetric_tab()
        self.build_encoding_tab()
        self.build_hashing_tab()

    # --- 1. التشفير المتماثل (AES, DES, 3DES) ---
    def build_symmetric_tab(self):
        frame = ttk.LabelFrame(self.tab_sym, text=" Symmetric Encryption & Decryption ")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="Input Text:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.sym_input = ttk.Entry(frame, width=50)
        self.sym_input.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Algorithm:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.sym_algo = ttk.Combobox(frame, values=["AES", "DES", "3DES"], state="readonly", width=15)
        self.sym_algo.set("AES")
        self.sym_algo.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttk.Label(frame, text="Secret Key (Text):").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.sym_key = ttk.Entry(frame, width=50)
        self.sym_key.grid(row=2, column=1, padx=10, pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=1, pady=10, sticky="w")
        ttk.Button(btn_frame, text="Encrypt", command=self.symmetric_encrypt).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.symmetric_decrypt).pack(side="left", padx=5)

        ttk.Label(frame, text="Output (Base64 / Plain):").grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.sym_output = ttk.Entry(frame, width=50)
        self.sym_output.grid(row=4, column=1, padx=10, pady=10)

    def pad_key(self, key_bytes, size):
        return key_bytes[:size].ljust(size, b'\0')

    def symmetric_encrypt(self):
        try:
            algo = self.sym_algo.get()
            plaintext = self.sym_input.get().encode()
            key_text = self.sym_key.get().encode()

            if not plaintext or not key_text:
                messagebox.showerror("Error", "Input and Key cannot be empty!")
                return

            if algo == "AES":
                key = self.pad_key(key_text, 32)  # 256 bits
                iv = os.urandom(16)
                cipher_algo = algorithms.AES(key)
                block_size = 128
            elif algo == "DES":
                key = self.pad_key(key_text, 8)  # 64 bits
                iv = os.urandom(8)
                cipher_algo = algorithms.DES(key)
                block_size = 64
            elif algo == "3DES":
                key = self.pad_key(key_text, 24)  # 192 bits
                iv = os.urandom(8)
                cipher_algo = algorithms.TripleDES(key)
                block_size = 64

            padder = padding.PKCS7(block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            cipher = Cipher(cipher_algo, modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # دمج الـ IV مع النص المشفر وتشفيرهما بـ Base64 لسهولة العرض
            result = base64.b64encode(iv + ciphertext).decode()
            self.sym_output.delete(0, tk.END)
            self.sym_output.insert(0, result)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def symmetric_decrypt(self):
        try:
            algo = self.sym_algo.get()
            raw_input = self.sym_input.get()
            key_text = self.sym_key.get().encode()

            if not raw_input or not key_text:
                messagebox.showerror("Error", "Input and Key cannot be empty!")
                return

            data = base64.b64decode(raw_input.encode())

            if algo == "AES":
                key = self.pad_key(key_text, 32)
                iv = data[:16]
                ciphertext = data[16:]
                cipher_algo = algorithms.AES(key)
                block_size = 128
            elif algo == "DES":
                key = self.pad_key(key_text, 8)
                iv = data[:8]
                ciphertext = data[8:]
                cipher_algo = algorithms.DES(key)
                block_size = 64
            elif algo == "3DES":
                key = self.pad_key(key_text, 24)
                iv = data[:8]
                ciphertext = data[8:]
                cipher_algo = algorithms.TripleDES(key)
                block_size = 64

            cipher = Cipher(cipher_algo, modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            self.sym_output.delete(0, tk.END)
            self.sym_output.insert(0, plaintext.decode())
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed! Check key or input.")

    # --- 2. التشفير غير المتماثل (RSA) ---
    def build_asymmetric_tab(self):
        frame = ttk.LabelFrame(self.tab_asym, text=" Asymmetric Encryption & Decryption (RSA) ")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Button(frame, text="Generate RSA Keys First", command=self.generate_rsa_keys).grid(row=0, column=1, padx=10,
                                                                                               pady=10, sticky="w")

        ttk.Label(frame, text="Input Text:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.asym_input = ttk.Entry(frame, width=50)
        self.asym_input.grid(row=1, column=1, padx=10, pady=10)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=1, pady=10, sticky="w")
        ttk.Button(btn_frame, text="Encrypt with Public Key", command=self.rsa_encrypt).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt with Private Key", command=self.rsa_decrypt).pack(side="left", padx=5)

        ttk.Label(frame, text="Output:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.asym_output = ttk.Entry(frame, width=50)
        self.asym_output.grid(row=3, column=1, padx=10, pady=10)

    def generate_rsa_keys(self):
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rsa_public_key = self.rsa_private_key.public_key()
        messagebox.showinfo("Success", "RSA 2048-bit Key Pair Generated Successfully!")

    def rsa_encrypt(self):
        if not self.rsa_public_key:
            messagebox.showerror("Error", "Please generate RSA keys first!")
            return
        try:
            plaintext = self.asym_input.get().encode()
            ciphertext = self.rsa_public_key.encrypt(
                plaintext,
                asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                  label=None)
            )
            self.asym_output.delete(0, tk.END)
            self.asym_output.insert(0, base64.b64encode(ciphertext).decode())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def rsa_decrypt(self):
        if not self.rsa_private_key:
            messagebox.showerror("Error", "Please generate RSA keys first!")
            return
        try:
            ciphertext = base64.b64decode(self.asym_input.get().encode())
            plaintext = self.rsa_private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                  label=None)
            )
            self.asym_output.delete(0, tk.END)
            self.asym_output.insert(0, plaintext.decode())
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed!")

    # --- 3. الترميز وفك الترميز (Base64, Hex, URL) ---
    def build_encoding_tab(self):
        frame = ttk.LabelFrame(self.tab_enc, text=" Encoding & Decoding ")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="Input Text:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.enc_input = ttk.Entry(frame, width=50)
        self.enc_input.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Technique:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.enc_tech = ttk.Combobox(frame, values=["Base64", "Hex", "URL Encoding"], state="readonly", width=15)
        self.enc_tech.set("Base64")
        self.enc_tech.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=1, pady=10, sticky="w")
        ttk.Button(btn_frame, text="Encode", command=self.encode_text).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decode", command=self.decode_text).pack(side="left", padx=5)

        ttk.Label(frame, text="Output:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.enc_output = ttk.Entry(frame, width=50)
        self.enc_output.grid(row=3, column=1, padx=10, pady=10)

    def encode_text(self):
        tech = self.enc_tech.get()
        inp = self.enc_input.get()
        res = ""
        try:
            if tech == "Base64":
                res = base64.b64encode(inp.encode()).decode()
            elif tech == "Hex":
                res = inp.encode().hex()
            elif tech == "URL Encoding":
                res = urllib.parse.quote(inp)
            self.enc_output.delete(0, tk.END)
            self.enc_output.insert(0, res)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_text(self):
        tech = self.enc_tech.get()
        inp = self.enc_input.get()
        res = ""
        try:
            if tech == "Base64":
                res = base64.b64decode(inp.encode()).decode()
            elif tech == "Hex":
                res = bytes.fromhex(inp).decode()
            elif tech == "URL Encoding":
                res = urllib.parse.unquote(inp)
            self.enc_output.delete(0, tk.END)
            self.enc_output.insert(0, res)
        except Exception as e:
            messagebox.showerror("Error", "Decoding failed! Check input format.")

    # --- 4. الـ Hashing (SHA-256, SHA-512, Salted Hashing) ---
    def build_hashing_tab(self):
        frame = ttk.LabelFrame(self.tab_hash, text=" Hashing Algorithms ")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="Input Text:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.hash_input = ttk.Entry(frame, width=50)
        self.hash_input.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Algorithm:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.hash_algo = ttk.Combobox(frame, values=["SHA-256", "SHA-512", "Salted Hashing"], state="readonly",
                                      width=15)
        self.hash_algo.set("SHA-256")
        self.hash_algo.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttk.Label(frame, text="Salt (Only for Salted):").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.hash_salt = ttk.Entry(frame, width=50)
        self.hash_salt.grid(row=2, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Generate Hash", command=self.generate_hash).grid(row=3, column=1, pady=10, sticky="w")

        ttk.Label(frame, text="Hash Output:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.hash_output = ttk.Entry(frame, width=50)
        self.hash_output.grid(row=4, column=1, padx=10, pady=10)

    def generate_hash(self):
        algo = self.hash_algo.get()
        inp = self.hash_input.get().encode()
        res = ""

        if algo == "SHA-256":
            res = hashlib.sha256(inp).hexdigest()
        elif algo == "SHA-512":
            res = hashlib.sha512(inp).hexdigest()
        elif algo == "Salted Hashing":
            salt = self.hash_salt.get().encode()
            if not salt:
                messagebox.showwarning("Warning", "Salt is empty! Using default or empty salt.")
            # دمج الملح مع النص ثم التجزئة بـ SHA-256
            res = hashlib.sha256(salt + inp).hexdigest()

        self.hash_output.delete(0, tk.END)
        self.hash_output.insert(0, res)


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoToolkitApp(root)
    root.mainloop()
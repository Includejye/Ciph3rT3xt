import os
import hashlib
import hmac
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# Folders and file paths

BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
OUTPUT_DIR = BASE_DIR / "output"
KEYS_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

PRIVATE_KEY_FILE = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_FILE = KEYS_DIR / "public_key.pem"
HMAC_KEY_FILE = KEYS_DIR / "hmac.key"

# Application color scheme

BG = "#0B1120"
SIDEBAR = "#0F172A"
PANEL = "#111C31"
PANEL2 = "#16233B"
TEXT = "#E5EDF8"
MUTED = "#94A3B8"
CYAN = "#22D3EE"
GREEN = "#34D399"
RED = "#FB7185"


# -Small helper functions

def read_file(path):
    return Path(path).read_bytes()


def write_file(path, data):
    Path(path).write_bytes(data)


def load_private_key():
    # Load the private key saved by the RSA tools
    if not PRIVATE_KEY_FILE.exists():
        raise FileNotFoundError(
            "Please generate an RSA key pair first."
        )

    key_data = read_file(PRIVATE_KEY_FILE)
    return serialization.load_pem_private_key(
        key_data,
        password=None
    )


def load_public_key():
    if not PUBLIC_KEY_FILE.exists():
        raise FileNotFoundError("Generate an RSA key pair first in RSA Tools.")
    return serialization.load_pem_public_key(read_file(PUBLIC_KEY_FILE))


def load_hmac_key():
    # create a random key the first time it is needed
    if not HMAC_KEY_FILE.exists():
        write_file(HMAC_KEY_FILE, os.urandom(32))
    return read_file(HMAC_KEY_FILE)


def oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def make_cipher(algorithm, key):
    if algorithm == "AES-256-GCM":
        return AESGCM(key)
    return ChaCha20Poly1305(key)


# main application

class CipherTextApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("CipherText | Secure File & Message Protection")
        self.geometry("1180x780")
        self.minsize(1000, 680)
        self.configure(fg_color=BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.current_page = "Overview"
        self.nav_buttons = {}
        self.log_items = []

        self.build_sidebar()
        self.build_main_area()
        self.show_page("Overview")
        self.log("Workspace initialized. Local educational environment ready.")

    # laoyout 

    def build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=228, corner_radius=0, fg_color=SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # logo and name
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(25, 30))
        ctk.CTkLabel(brand, text="⬡", text_color=CYAN,
                     font=ctk.CTkFont(size=35, weight="bold")).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(brand, text="CIPHERTEXT", text_color=TEXT,
                     font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(brand, text="SECURITY WORKSPACE", text_color=MUTED,
                     font=ctk.CTkFont(size=9, weight="bold")).pack(anchor="w")

        ctk.CTkLabel(self.sidebar, text="WORKSPACE", text_color="#64748B",
                     font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=22, pady=(0, 10))

        # navigation buttons
        pages = [
            ("Overview", "◈"),
            ("Encrypt / Decrypt", "▣"),
            ("Hash & HMAC", "⌁"),
            ("RSA Tools", "⚿"),
            ("Digital Signatures", "✓"),
            ("Activity Logs", "≡"),
        ]
        for name, icon in pages:
            button = ctk.CTkButton(
                self.sidebar, text=f"{icon}   {name}", anchor="w", height=42,
                corner_radius=10, fg_color="transparent", hover_color=PANEL2,
                text_color=MUTED, font=ctk.CTkFont(size=13),
                command=lambda n=name: self.show_page(n),
            )
            button.pack(fill="x", padx=12, pady=3)
            self.nav_buttons[name] = button

        ctk.CTkFrame(self.sidebar, height=1, fg_color="#26344D").pack(fill="x", padx=20, pady=(22, 16))
        ctk.CTkLabel(self.sidebar, text="LOCAL ENVIRONMENT", text_color=GREEN,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=22)
        ctk.CTkLabel(self.sidebar, text="Keys and output remain\nin this project folder.",
                     text_color=MUTED, justify="left",
                     font=ctk.CTkFont(size=11)).pack(anchor="w", padx=22, pady=(7, 0))
        ctk.CTkLabel(self.sidebar, text="Cryptography Project • Project DEMO", text_color="#64748B",
                     font=ctk.CTkFont(size=9)).pack(side="bottom", pady=18)

    def build_main_area(self):
        self.main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        # top bar with page title
        self.topbar = ctk.CTkFrame(self.main, fg_color=BG, corner_radius=0, height=76)
        self.topbar.grid(row=0, column=0, sticky="ew", padx=28, pady=(18, 8))
        self.topbar.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(self.topbar, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")
        self.page_title = ctk.CTkLabel(title_box, text="Security Workspace", text_color=TEXT,
                                       font=ctk.CTkFont(size=26, weight="bold"))
        self.page_title.pack(anchor="w")
        self.page_subtitle = ctk.CTkLabel(title_box, text="Protect, verify, and manage your files.",
                                          text_color=MUTED, font=ctk.CTkFont(size=12))
        self.page_subtitle.pack(anchor="w", pady=(3, 0))

        badge = ctk.CTkFrame(self.topbar, fg_color=PANEL, corner_radius=18)
        badge.grid(row=0, column=1, sticky="e", padx=(10, 0))
        ctk.CTkLabel(badge, text="●  LOCAL MODE", text_color=GREEN,
                     font=ctk.CTkFont(size=10, weight="bold")).pack(padx=14, pady=9)

        # scrollable area where each page is drawn
        self.content = ctk.CTkScrollableFrame(self.main, fg_color=BG, corner_radius=0)
        self.content.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 10))

        # footer and status bar
        self.footer = ctk.CTkFrame(self.main, fg_color=SIDEBAR, corner_radius=12, height=36)
        self.footer.grid(row=2, column=0, sticky="ew", padx=28, pady=(0, 14))
        self.status_label = ctk.CTkLabel(self.footer, text="Ready", text_color=MUTED,
                                         font=ctk.CTkFont(size=11))
        self.status_label.pack(side="left", padx=13, pady=8)
        ctk.CTkLabel(self.footer, text="AES-256-GCM  •  ChaCha20-Poly1305  •  SHA-256  •  RSA / Developed by one of Coventry University student",
                     text_color="#64748B", font=ctk.CTkFont(size=10)).pack(side="right", padx=13)

    def show_page(self, name):
        self.current_page = name

        # highlight the active button
        for page_name, button in self.nav_buttons.items():
            if page_name == name:
                button.configure(fg_color=PANEL2, text_color=CYAN)
            else:
                button.configure(fg_color="transparent", text_color=MUTED)

        # clear the old page
        for child in self.content.winfo_children():
            child.destroy()

        titles = {
            "Overview": ("Security Workspace", "Protect, verify, and manage your files."),
            "Encrypt / Decrypt": ("File Encryption", "Authenticated encryption with AES-GCM or ChaCha20-Poly1305."),
            "Hash & HMAC": ("Integrity & Authentication", "Generate SHA-256 digests and verify HMAC-SHA256 tags."),
            "RSA Tools": ("RSA Key Management", "Generate key pairs and encrypt small data values with RSA-OAEP."),
            "Digital Signatures": ("Digital Signatures", "Create and verify RSA-PSS signatures for files."),
            "Activity Logs": ("Activity Logs", "Recent operations performed in this session."),
        }
        builders = {
            "Overview": self.page_overview,
            "Encrypt / Decrypt": self.page_encrypt,
            "Hash & HMAC": self.page_hash,
            "RSA Tools": self.page_rsa,
            "Digital Signatures": self.page_sign,
            "Activity Logs": self.page_logs,
        }

        self.page_title.configure(text=titles[name][0])
        self.page_subtitle.configure(text=titles[name][1])
        builders[name]()

    # reusable widgets 

    def card(self, parent, title, desc, accent=CYAN):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                             border_width=1, border_color="#22314B")
        ctk.CTkFrame(frame, width=4, fg_color=accent, corner_radius=4).pack(
            side="left", fill="y", padx=(0, 15), pady=16)

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(side="left", fill="both", expand=True, padx=(0, 14), pady=14)
        ctk.CTkLabel(inner, text=title, text_color=TEXT,
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(inner, text=desc, text_color=MUTED, font=ctk.CTkFont(size=11),
                     justify="left", wraplength=260).pack(anchor="w", pady=(5, 0))
        return frame, inner

    def primary_button(self, parent, text, command, width=180):
        return ctk.CTkButton(
            parent, text=text, command=lambda: self.run_action(command),
            width=width, height=39, corner_radius=9,
            fg_color="#0891B2", hover_color="#0E7490", text_color="#F0FDFF",
            font=ctk.CTkFont(size=12, weight="bold"),
        )

    def secondary_button(self, parent, text, command, width=180):
        return ctk.CTkButton(
            parent, text=text, command=lambda: self.run_action(command),
            width=width, height=39, corner_radius=9,
            fg_color=PANEL2, hover_color="#263A59",
            border_width=1, border_color="#334866", text_color=TEXT,
            font=ctk.CTkFont(size=12),
        )

    def section_title(self, parent, text):
        ctk.CTkLabel(parent, text=text, text_color=TEXT,
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", pady=(18, 10))

    def info_box(self, heading, body, heading_color=CYAN, wrap=780):
        box = ctk.CTkFrame(self.content, fg_color=PANEL, corner_radius=14)
        box.pack(fill="x", pady=4)
        ctk.CTkLabel(box, text=heading, text_color=heading_color,
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(box, text=body, text_color=MUTED, justify="left", wraplength=wrap,
                     font=ctk.CTkFont(size=11)).pack(anchor="w", padx=16, pady=(0, 12))

    # logging and error handling 

    def log(self, message):
        # show first line in the status bar and keep the full text in the log list
        self.status_label.configure(text=message.splitlines()[0][:120])
        self.log_items.append(message)

        if hasattr(self, "log_view") and self.log_view.winfo_exists():
            self.log_view.configure(state="normal")
            self.log_view.insert("end", message + "\n")
            self.log_view.see("end")
            self.log_view.configure(state="disabled")

    def run_action(self, func):
        """Run a button action and show its result or any error in a message box."""
        try:
            result = func()
            if result:
                self.log(result.replace("\n", " | "))
                messagebox.showinfo("CipherText • Result", result, parent=self)
        except (InvalidTag, InvalidSignature):
            msg = "Verification failed: the data, key, nonce, or authentication tag is invalid."
            self.log("SECURITY CHECK: " + msg)
            messagebox.showwarning("Verification failed", msg, parent=self)
        except Exception as error:
            msg = f"{type(error).__name__}: {error}"
            self.log("ERROR: " + msg)
            messagebox.showerror("Operation failed", msg, parent=self)

    def choose_file(self, title, start_dir=None):
        return filedialog.askopenfilename(title=title, initialdir=start_dir, parent=self)

    def save_file_dialog(self, title, filename):
        return filedialog.asksaveasfilename(
            title=title, initialdir=str(OUTPUT_DIR), initialfile=filename, parent=self)

    # overview page

    def page_overview(self):
        hero = ctk.CTkFrame(self.content, fg_color="#10243B", corner_radius=18,
                            border_width=1, border_color="#1E4561")
        hero.pack(fill="x", pady=(2, 18))
        hero.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(hero, fg_color="transparent")
        left.grid(row=0, column=0, sticky="ew", padx=24, pady=24)
        ctk.CTkLabel(left, text="CIPHERTEXT TOOLKIT", text_color=CYAN,
                     font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(left, text="Security, made practical.", text_color=TEXT,
                     font=ctk.CTkFont(size=25, weight="bold")).pack(anchor="w", pady=(8, 5))
        ctk.CTkLabel(left, text="A local workspace for encryption, integrity checks, "
                                "authentication, and digital signatures.",
                     text_color="#B4C6D9", font=ctk.CTkFont(size=12),
                     wraplength=620, justify="left").pack(anchor="w")

        # this button only changes page, so it doesn't go through run_action
        ctk.CTkButton(
            left, text="Open encryption tools  →", width=205, height=39, corner_radius=9,
            fg_color="#0891B2", hover_color="#0E7490", text_color="#F0FDFF",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self.show_page("Encrypt / Decrypt"),
        ).pack(anchor="w", pady=(18, 0))

        self.section_title(self.content, "Cryptographic modules")
        grid = ctk.CTkFrame(self.content, fg_color="transparent")
        grid.pack(fill="x")
        grid.grid_columnconfigure((0, 1), weight=1, uniform="cards")

        modules = [
            ("AES-256-GCM", "Authenticated file encryption with a 256-bit key.", CYAN, "Encrypt / Decrypt"),
            ("ChaCha20-Poly1305", "Modern authenticated encryption alternative.", GREEN, "Encrypt / Decrypt"),
            ("SHA-256 & HMAC", "Hash files and verify data using a shared secret.", "#A78BFA", "Hash & HMAC"),
            ("RSA-OAEP / RSA-PSS", "Public-key encryption and digital signatures.", "#FBBF24", "RSA Tools"),
        ]
        for i, (title, desc, color, page) in enumerate(modules):
            card, _ = self.card(grid, title, desc, color)
            row, col = divmod(i, 2)
            left_pad = 0 if col == 0 else 7
            right_pad = 7 if col == 0 else 0
            card.grid(row=row, column=col, sticky="ew", padx=(left_pad, right_pad), pady=6)
            card.bind("<Button-1>", lambda event, p=page: self.show_page(p))

        self.section_title(self.content, "Security notes")
        notes = ctk.CTkFrame(self.content, fg_color=PANEL, corner_radius=14)
        notes.pack(fill="x")
        lines = [
            "• Keep symmetric keys and RSA private keys confidential.",
            "• Never reuse a nonce with the same AES-GCM or ChaCha20-Poly1305 key.",
            "• RSA-OAEP is for small values, not large files.",
            "• This application is an educational prototype, not production software.",
        ]
        for line in lines:
            ctk.CTkLabel(notes, text=line, text_color=MUTED, font=ctk.CTkFont(size=11),
                         anchor="w").pack(fill="x", padx=18, pady=5)

    # -encryption and decryption page

    def page_encrypt(self):
        card, inner = self.card(
            self.content, "Authenticated file encryption",
            "Select a file and algorithm. The encrypted output contains a 12-byte "
            "nonce followed by authenticated ciphertext.")
        card.pack(fill="x", pady=(2, 15))

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(anchor="w", pady=(12, 0))
        ctk.CTkLabel(row, text="Algorithm", text_color=MUTED).pack(side="left", padx=(0, 10))
        self.alg = ctk.StringVar(value="AES-256-GCM")
        ctk.CTkComboBox(row, variable=self.alg, values=["AES-256-GCM", "ChaCha20-Poly1305"],
                        width=220, state="readonly").pack(side="left")

        buttons = ctk.CTkFrame(self.content, fg_color="transparent")
        buttons.pack(anchor="w", pady=5)
        self.primary_button(buttons, "Encrypt file", self.encrypt_file, 155).pack(side="left", padx=(0, 10))
        self.secondary_button(buttons, "Decrypt file", self.decrypt_file, 155).pack(side="left")

        warning = ctk.CTkFrame(self.content, fg_color="#2A1D24", corner_radius=12)
        warning.pack(fill="x", pady=18)
        ctk.CTkLabel(warning, text="KEY HANDLING", text_color="#FDA4AF",
                     font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            warning,
            text="For coursework convenience, a separate .key file is created beside the "
                 "encrypted output. Anyone with both files can decrypt the content. "
                 "Store the key separately for a real security workflow.",
            text_color="#FBCAD2", wraplength=760, justify="left",
            font=ctk.CTkFont(size=11)).pack(anchor="w", padx=16, pady=(0, 12))

    def encrypt_file(self):
        source = self.choose_file("Choose a file to encrypt")
        if not source:
            return "Encryption cancelled."

        data = read_file(source)
        key = os.urandom(32)
        nonce = os.urandom(12)
        algorithm = self.alg.get()

        cipher = make_cipher(algorithm, key)
        packed = nonce + cipher.encrypt(nonce, data, None)

        extension = ".aesgcm.enc" if algorithm == "AES-256-GCM" else ".chacha.enc"
        dest = self.save_file_dialog("Save encrypted file", Path(source).name + extension)
        if not dest:
            return "Encryption cancelled before saving."

        write_file(dest, packed)
        key_path = dest + ".key"
        write_file(key_path, key)

        return (f"{algorithm} encryption completed.\n"
                f"Encrypted output: {dest}\n"
                f"Key file: {key_path}\n"
                f"Keep the key file private and separate.")

    def decrypt_file(self):
        source = self.choose_file("Choose encrypted file")
        if not source:
            return "Decryption cancelled."

        key_path = self.choose_file("Choose matching .key file", str(OUTPUT_DIR))
        if not key_path:
            return "Decryption cancelled: no key selected."

        packed = read_file(source)
        if len(packed) < 13:
            raise ValueError("Encrypted file is too short or invalid.")

        key = read_file(key_path)
        if len(key) != 32:
            raise ValueError("The selected key must be 32 bytes.")

        # first 12 bytes are the nonce, the rest is the ciphertext + tag
        nonce = packed[:12]
        ciphertext = packed[12:]
        cipher = make_cipher(self.alg.get(), key)
        plain = cipher.decrypt(nonce, ciphertext, None)

        dest = self.save_file_dialog("Save recovered file", Path(source).name + ".decrypted")
        if not dest:
            return "Decryption cancelled before saving."

        write_file(dest, plain)
        return f"Decryption completed using {self.alg.get()}.\nRecovered output: {dest}"

    # hash and HMAC page 

    def page_hash(self):
        card, inner = self.card(
            self.content, "SHA-256 & HMAC-SHA256",
            "A digest helps compare data; HMAC adds authentication using a shared secret.",
            "#A78BFA")
        card.pack(fill="x", pady=(2, 15))

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(anchor="w", pady=(14, 0))
        self.primary_button(row, "Calculate SHA-256", self.hash_file, 165).pack(side="left", padx=(0, 8))
        self.secondary_button(row, "Generate HMAC", self.make_hmac, 145).pack(side="left", padx=(0, 8))
        self.secondary_button(row, "Verify HMAC", self.check_hmac, 135).pack(side="left")

        self.info_box(
            "KEY INFORMATION",
            f"HMAC key location: {HMAC_KEY_FILE}\n"
            "Do not share this key with untrusted users. Verification succeeds "
            "only when the expected HMAC matches.")

    def hash_file(self):
        path = self.choose_file("Choose file to hash")
        if not path:
            return "Hash cancelled."

        digest = hashlib.sha256(read_file(path)).hexdigest()
        return (f"SHA-256 digest for {path}:\n\n{digest}\n\n"
                f"Digest length: 256 bits (64 hexadecimal characters).")

    def make_hmac(self):
        path = self.choose_file("Choose file for HMAC")
        if not path:
            return "HMAC generation cancelled."

        tag = hmac.new(load_hmac_key(), read_file(path), hashlib.sha256).hexdigest()
        dest = self.save_file_dialog("Save HMAC text file", Path(path).name + ".hmac.txt")
        if not dest:
            return "HMAC calculated but not saved."

        write_file(dest, tag.encode("ascii"))
        return f"HMAC-SHA256 generated.\nTag file: {dest}\nTag: {tag}"

    def check_hmac(self):
        path = self.choose_file("Choose original file")
        if not path:
            return "Verification cancelled."

        tag_path = self.choose_file("Choose HMAC tag file", str(OUTPUT_DIR))
        if not tag_path:
            return "Verification cancelled: no tag selected."

        expected = hmac.new(load_hmac_key(), read_file(path), hashlib.sha256).hexdigest()
        received = read_file(tag_path).decode("ascii").strip()

        # compare_digest avoids timing leaks
        if hmac.compare_digest(expected, received):
            return "HMAC verification: VALID — message integrity and authentication check passed."

        self.status_label.configure(text="HMAC verification: INVALID", text_color=RED)
        return "HMAC verification: INVALID — file or tag may have been modified, or the wrong key was used."

    # -RSA page

    def page_rsa(self):
        card, inner = self.card(
            self.content, "RSA-2048 key pair & RSA-OAEP",
            "Generate public/private keys, then encrypt small data such as a symmetric key.",
            "#FBBF24")
        card.pack(fill="x", pady=(2, 15))

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(anchor="w", pady=(14, 0))
        self.primary_button(row, "Generate RSA key pair", self.generate_rsa, 190).pack(side="left", padx=(0, 8))
        self.secondary_button(row, "RSA-OAEP encrypt", self.rsa_encrypt, 165).pack(side="left", padx=(0, 8))
        self.secondary_button(row, "RSA-OAEP decrypt", self.rsa_decrypt, 165).pack(side="left")

        self.info_box(
            "KEY FILES",
            f"Private key: {PRIVATE_KEY_FILE}\nPublic key: {PUBLIC_KEY_FILE}\n"
            "The private key is currently stored unencrypted for this coursework demo. "
            "Restrict access to it.")

    def generate_rsa(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        write_file(PRIVATE_KEY_FILE, private_pem)
        write_file(PUBLIC_KEY_FILE, public_pem)

        return (f"RSA-2048 key pair generated.\n"
                f"Private key: {PRIVATE_KEY_FILE}\n"
                f"Public key: {PUBLIC_KEY_FILE}\n"
                f"Protect the private key.")

    def rsa_encrypt(self):
        path = self.choose_file("Choose a small file or key to encrypt")
        if not path:
            return "RSA encryption cancelled."

        encrypted = load_public_key().encrypt(read_file(path), oaep_padding())
        dest = self.save_file_dialog("Save RSA encrypted output", Path(path).name + ".rsa.enc")
        if not dest:
            return "RSA encryption cancelled before saving."

        write_file(dest, encrypted)
        return (f"RSA-OAEP encryption completed.\nOutput: {dest}\n"
                f"Note: RSA is intended for small values, not large files.")

    def rsa_decrypt(self):
        path = self.choose_file("Choose RSA encrypted file")
        if not path:
            return "RSA decryption cancelled."

        decrypted = load_private_key().decrypt(read_file(path), oaep_padding())
        dest = self.save_file_dialog("Save RSA decrypted output", Path(path).name + ".decrypted")
        if not dest:
            return "RSA decryption cancelled before saving."

        write_file(dest, decrypted)
        return f"RSA-OAEP decryption completed.\nRecovered output: {dest}"

    #  digital signature page

    def page_sign(self):
        card, inner = self.card(
            self.content, "RSA-PSS digital signatures",
            "Sign a file with the private key and verify the signature using the matching public key.",
            GREEN)
        card.pack(fill="x", pady=(2, 15))

        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(anchor="w", pady=(14, 0))
        self.primary_button(row, "Create file signature", self.sign_file, 175).pack(side="left", padx=(0, 8))
        self.secondary_button(row, "Verify signature", self.verify_file, 155).pack(side="left")

        self.info_box(
            "HOW VERIFICATION WORKS",
            "The signature is tied to the exact file contents. If the file changes after "
            "signing, verification should fail. Generate an RSA key pair first in RSA Tools.")

    def sign_file(self):
        path = self.choose_file("Choose file to sign")
        if not path:
            return "Signing cancelled."

        signature = load_private_key().sign(read_file(path), pss_padding(), hashes.SHA256())
        dest = self.save_file_dialog("Save signature file", Path(path).name + ".sig")
        if not dest:
            return "Signature created but not saved."

        write_file(dest, signature)
        return f"RSA-PSS signature created.\nSignature file: {dest}"

    def verify_file(self):
        path = self.choose_file("Choose original file")
        if not path:
            return "Verification cancelled."

        sig_path = self.choose_file("Choose signature file", str(OUTPUT_DIR))
        if not sig_path:
            return "Verification cancelled: no signature selected."

        try:
            load_public_key().verify(read_file(sig_path), read_file(path),
                                     pss_padding(), hashes.SHA256())
            return "RSA-PSS signature verification: VALID — file matches the signed content."
        except InvalidSignature:
            self.status_label.configure(text="Signature verification: INVALID", text_color=RED)
            return "RSA-PSS signature verification: INVALID — the file or signature may have changed."

    #  activity log page 

    def page_logs(self):
        self.log_view = ctk.CTkTextbox(
            self.content, fg_color=PANEL, text_color=TEXT, corner_radius=14,
            font=ctk.CTkFont(family="Consolas", size=11), height=400)
        self.log_view.pack(fill="both", expand=True, pady=(2, 12))

        for item in self.log_items:
            self.log_view.insert("end", item + "\n")
        self.log_view.configure(state="disabled")

        self.secondary_button(self.content, "Clear visible logs", self.clear_logs, 160).pack(anchor="w")

    def clear_logs(self):
        self.log_items = []
        if hasattr(self, "log_view") and self.log_view.winfo_exists():
            self.log_view.configure(state="normal")
            self.log_view.delete("1.0", "end")
            self.log_view.configure(state="disabled")
        return "Visible activity logs cleared."


if __name__ == "__main__":
    app = CipherTextApp()
    app.mainloop()

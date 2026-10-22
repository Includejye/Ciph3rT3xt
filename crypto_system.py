import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


KEY_DIR = Path("keys")
OUTPUT_DIR = Path("output")

PRIVATE_KEY_FILE = KEY_DIR / "private_key.pem"
PUBLIC_KEY_FILE = KEY_DIR / "public_key.pem"

# Create required directories if they do not exist
KEY_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

#Sha256 

def sha256_file(filename):
    data = Path(filename).read_bytes()

    digest = hashlib.sha256(data).hexdigest()

    print("\nSHA-256:")
    print(digest)

    return digest

#AES-256-GCM


def aes_encrypt(filename):
    data = Path(filename).read_bytes()

    # AES-256 requires a 32-byte (256-bit) key
    key = AESGCM.generate_key(bit_length=256)

    # GCM commonly uses a 12-byte nonce
    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        data,
        None
    )

    # Store nonce together with ciphertext
    (OUTPUT_DIR / "aes_encrypted.bin").write_bytes(
        nonce + ciphertext
    )

    # Save AES key for coursework demonstration
    (OUTPUT_DIR / "aes_key.bin").write_bytes(key)

    print("\n[+] AES-256-GCM encryption completed successfully.")
    print("[+] Encrypted file: output/aes_encrypted.bin")

    return key


def aes_decrypt():
    key = (OUTPUT_DIR / "aes_key.bin").read_bytes()
    encrypted_data = (OUTPUT_DIR / "aes_encrypted.bin").read_bytes()

    # Extract nonce and ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aes = AESGCM(key)

    try:
        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        (OUTPUT_DIR / "aes_decrypted.txt").write_bytes(
            plaintext
        )

        print("\n[+] AES authentication completed successfully.")
        print("[+] File decrypted successfully.")

    except InvalidTag:
        print("\n[-] AES authentication failed.")
        print("[-] The encrypted data may have been modified.")

# ChaCha-Poly1305
def chacha_encryption(filename):
    data = Path(filename).read_bytes()

    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)

    cipher = ChaCha20Poly1305(key)

    ciphertext = cipher.encrypt(
        nonce,
        data,
        None
    )
    # Store nonce together with ciphertext

    (OUTPUT_DIR / "chacha_encrypted.bin").write_bytes(
        nonce + ciphertext

    )
        # Save key for coursework demonstration
    (OUTPUT_DIR / "chacha_key.bin").write_bytes(key)

    print("\n[+] ChaCha20-Poly1305 encryption is successfully completed.")

    return key

def chacha_decrypt():
    key = Path("output/chacha_key.bin").read_bytes()
    encrypted_data = Path("output/chacha_encrypted.bin").read_bytes()

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    cipher = ChaCha20Poly1305(key)

    try:
        plaintext = cipher.decrypt(
            nonce,
            ciphertext,
            None
        )

        Path("output/chacha_decrypted.txt").write_bytes(plaintext)

        print("\n[+] ChaCha20-Poly1305 decryption is successfully completed.")
        print("[+] File decrypted is successfully.")
    except InvalidTag:
        print("\n[-] ChaCha20 authentication is failed.")

#HMAC-SHA256


def create_hmac(filename):
    data = Path(filename).read_bytes()

    key = os.urandom(32)

    mac = hmac.new(
        key,
        data,
        hashlib.sha256
    ).digest()

    Path("output/hmac_key.bin").write_bytes(key)
    Path("output/hmac.bin").write_bytes(mac)

    print("\n[+] HMAC-SHA256 is successfully created.")

    return mac

def verify_hmac(filename):
    key = Path("output/hmac_key.bin").read_bytes()
    mac = Path("output/hmac.bin").read_bytes()
    data = Path(filename).read_bytes()

    new_mac = hmac.new(
        key,
        data,
        hashlib.sha256
    ).digest()

    if hmac.compare_digest(mac, new_mac):
        print("\n[+] HMAC-SHA256 verification is successfully completed.")
        print("[+] Message integrity is confirmed.")
    else:
        print("\n[-] HMAC-SHA256 verification is failed.")
        print("[-] Message may have been modified.")


# RSA KEY LOADING

def load_private_key():
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_FILE.read_bytes(),
        password=None
    )

    return private_key

def load_public_key():
    public_key = serialization.load_pem_public_key(
        PUBLIC_KEY_FILE.read_bytes()
    )

    return public_key


#RSA OAEP

def rsa_aes_key():
    public_key = load_public_key()

    aes_key = Path("output/aes_key.bin").read_bytes()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    Path("output/encrypted_aes_key.bin").write_bytes(
        encrypted_key
    )

    print("\n[+] AES key is protected using RSA-OAEP.")


def rsa_decrypt_aes_key():
    private_key = load_private_key()

    encrypted_key = Path(
        "output/encrypted_aes_key.bin"
    ).read_bytes()

    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print("\n[+] AES key is decryption is successfully completed.")

    original = Path("output/aes_key.bin").read_bytes()

    if decrypted_key == original:
        print("[+] Recovered AES key matches original key.")
    else:
        print("[-] AES key does not match.")

    return decrypted_key

#Digital Signature

def sign_file(filename):
    private_key = load_private_key()

    data = Path(filename).read_bytes()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    Path("output/signature.bin").write_bytes(signature)

    print("\n[+] Digital signature is successfully created.")

def verify_signature(filename):
    public_key = load_public_key()

    data = Path(filename).read_bytes()
    signature = Path("output/signature.bin").read_bytes()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("\n[+] Digital signature is valid.")
        print("[+] Integrity and authenticity confirmed.")
    
    except InvalidSignature:
        print("\n[-] Digital signature Invalid.")
        print("[-] Message may have been modified.")







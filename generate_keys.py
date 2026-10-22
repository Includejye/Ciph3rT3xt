#We will generate a key private key and publix key
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = Path("Keys")
PRIVATE_KEY_FILE = KEY_DIR / "private_key.pem"
PUBLIC_KEY_FILE  = KEY_DIR / "public_key.pem"

def generate_rsa_keys():
    KEY_DIR.mkdir(exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent= 65537,
        key_size = 2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()

    )

    public_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo

    )

    PRIVATE_KEY_FILE.write_bytes(private_pem)
    PUBLIC_KEY_FILE.write_bytes(public_pem)

    print("[+] RSA-2048 key pair generated is successfully.")
    print(f"[+] Private key: {PRIVATE_KEY_FILE}")
    print(f"[+] Public key: {PUBLIC_KEY_FILE}")


if __name__ == "__main__":
    generate_rsa_keys()






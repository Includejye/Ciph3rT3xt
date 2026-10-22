import crypto_system

TEST_FILE = "files/message.txt"

print("=" * 60)
print("PSB500IT CRYPTOGRAPHY COURSEWORK 2 TEST")
print("=" * 60)


# 1. SHA-256
print("\n[1] Testing SHA-256")
crypto_system.sha256_file(TEST_FILE)


# 2. AES-256-GCM
print("\n[2] Testing AES-256-GCM")
crypto_system.aes_encrypt(TEST_FILE)
crypto_system.aes_decrypt()


# 3. ChaCha20-Poly1305
print("\n[3] Testing ChaCha20-Poly1305")
crypto_system.chacha_encryption(TEST_FILE)
crypto_system.chacha_decrypt()


# 4. HMAC-SHA256
print("\n[4] Testing HMAC-SHA256")
crypto_system.create_hmac(TEST_FILE)
crypto_system.verify_hmac(TEST_FILE)


# 5. RSA-OAEP
print("\n[5] Testing RSA-OAEP")
crypto_system.rsa_aes_key()
crypto_system.rsa_decrypt_aes_key()


# 6. Digital Signature
print("\n[6] Testing Digital Signature")
crypto_system.sign_file(TEST_FILE)
crypto_system.verify_signature(TEST_FILE)


print("\n" + "=" * 60)
print("ALL CRYPTOGRAPHIC TESTS COMPLETED")
print("=" * 60)
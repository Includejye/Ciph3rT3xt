from crypto_system import (
    sha256_file,
    aes_encrypt,
    aes_decrypt,
    chacha_encryption,
    chacha_decrypt,
    create_hmac,
    verify_hmac,
    rsa_aes_key,
    rsa_decrypt_aes_key,
    sign_file,
    verify_signature,
)

from generate_keys import generate_rsa_keys


TEST_FILE = "files/message.txt"


def menu():

    while True:
        print("""

        PSB500IT SECURE CRYPTOGRAPHY SYSTEM
-----------------------------------------------

1. Generate RSA Key Pair
2. Calculate SHA-256 Hash
3. AES-256-GCM Encrypt File
4. AES-256-GCM Decrypt File
5. ChaCha20-Poly1305 Encrypt File
6. ChaCha20-Poly1305 Decrypt File
7. Generate HMAC-SHA256
8. Verify HMAC-SHA256
9. RSA Encrypt AES Key
10. RSA Decrypt AES Key
11. Create Digital Signature
12. Verify Digital Signature
0. Exit

--------------------------------------------------
""")

        choice = input("Select an option: ")

        try:

            if choice == "1":
                generate_rsa_keys()

            elif choice == "2":
                sha256_file(TEST_FILE)

            elif choice == "3":
                aes_encrypt(TEST_FILE)

            elif choice == "4":
                aes_decrypt()

            elif choice == "5":
                chacha_encryption(TEST_FILE)

            elif choice == "6":
                chacha_decrypt()

            elif choice == "7":
                create_hmac(TEST_FILE)

            elif choice == "8":
                verify_hmac(TEST_FILE)

            elif choice == "9":
                rsa_aes_key()

            elif choice == "10":
                rsa_decrypt_aes_key()

            elif choice == "11":
                sign_file(TEST_FILE)

            elif choice == "12":
                verify_signature(TEST_FILE)

            elif choice == "0":
                print("\nProgram closed.")
                break

            else:
                print("\nInvalid option.")

        except FileNotFoundError as error:
            print("\n[-] Required file was not found.")
            print(error)

        except Exception as error:
            print("\n[-] An error occurred:")
            print(error)


if __name__ == "__main__":
    menu()
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_FILE = "ChaCha20Poly1305.key"


def generate_key():
    key = os.urandom(32)
    with open(KEY_FILE, "wb") as keyfile:
        keyfile.write(key)


def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()

    with open(KEY_FILE, "rb") as keyfile:
        key = keyfile.read()
    return key


def encrypt_password(password):
    key = load_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    encrypted_password = chacha.encrypt(nonce, password.encode(), None)
    return base64.b64encode(nonce + encrypted_password).decode("utf-8")


def decrypt_password(encrypted_password):
    key = load_key()
    chacha = ChaCha20Poly1305(key)
    encrypted_password = base64.b64decode(encrypted_password.encode("utf-8"))
    nonce = encrypted_password[:12]
    encrypted_password = encrypted_password[12:]
    decrypted_password = chacha.decrypt(nonce, encrypted_password, None)
    return decrypted_password.decode("utf-8")


if __name__ == "__main__":
    action = input("Choose an action (generate, encrypt, decrypt): ").lower()
    if action == "generar":
        generate_key()
        print("Clave generada y guardada en 'KEY_FILE'")
    elif action in ("cifrar", "descifrar"):

        password = input("Ingrese la contraseña: ")
        if action == "cifrar":
            encrypted_password = encrypt_password(password)
            print(f"Encrypted password: {encrypted_password}")

        else:
            decrypted_password = decrypt_password(password)
            print(f"Decrypted password: {decrypted_password}")
else:
    print("Invalid action. Please choose 'generate', 'encrypt' or 'decrypt'.")

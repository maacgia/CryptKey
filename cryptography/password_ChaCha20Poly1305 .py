import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


KEY_FILE = "ChaCha20Poly1305.key"
folder_name = "key"
file_name = os.path.join(folder_name, KEY_FILE)


def generate_key():
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    key = os.urandom(32)
    with open(file_name, "wb") as keyfile:
        keyfile.write(key)


def load_key():
    # en caso de que no exista la key la genera automáticamente
    if not os.path.exists(file_name):
        generate_key()

    with open(file_name, "rb") as keyfile:
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
    action = input("Elija una acción (generar, cifrar, descifrar): ").lower()
    if action == "generar":
        generate_key()
        print("Clave generada y guardada en 'KEY_FILE'")
    elif action in ("cifrar", "descifrar"):
        password = input("Ingrese la contraseña: ")

        if action == "cifrar":
            encrypted_password = encrypt_password(password)
            print(f"Contraseña cifrada: {encrypted_password}")
        else:
            decrypted_password = decrypt_password(password)
            print(f"Contraseña descifrada: {decrypted_password}")
    else:
        print("Acción no válida. Por favor, elija 'generar', 'cifrar' o 'descifrar'.")

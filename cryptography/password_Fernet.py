from cryptography.fernet import Fernet
import sys
import os

KEY_FILE = "fernet.key"
folder_name = "key"
file_name = os.path.join(folder_name, KEY_FILE)


def generate_key():
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    key = Fernet.generate_key()
    with open(file_name, "wb") as key_file:
        key_file.write(key)


def load_key():
    try:
        with open(file_name, "rb") as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        print(f"No se encontró el archivo '{KEY_FILE}'. Asegúrate de generar una clave primero.")
        sys.exit()


def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password


def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password


if __name__ == "__main__":
    action = input("Elija una acción (generar, cifrar, descifrar): ").lower()

    if action == "generar":
        generate_key()
        print("Clave generada y guardada en 'KEY_FILE'")
    elif action in ("cifrar", "descifrar"):
        key = load_key()
        password = input("Ingrese la contraseña: ")

        if action == "cifrar":
            encrypted_password = encrypt_password(password, key)
            print("Contraseña cifrada:", encrypted_password.decode())
        else:
            decrypted_password = decrypt_password(password.encode(), key)
            print("Contraseña descifrada:", decrypted_password)
    else:
        print("Acción no válida. Por favor, elija 'generar', 'cifrar' o 'descifrar'.")

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets
import base64
import getpass
import argparse
import os


class KeyManager:
    def __init__(self, salt_file="salt.salt", salt_size=16):
        self.salt_file = salt_file
        self.salt_size = salt_size

    def generate_salt(self):
        return secrets.token_bytes(self.salt_size)

    def load_salt(self):
        return open(self.salt_file, "rb").read()

    def derive_key(self, password):
        salt = self.load_salt() if os.path.exists(self.salt_file) else self.generate_salt()
        if not os.path.exists(self.salt_file):
            with open(self.salt_file, "wb") as salt_file:
                salt_file.write(salt)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        derived_key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(derived_key)


class FileEncryptor:
    def __init__(self, key):
        self.f = Fernet(key)

    def encrypt(self, filename):
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = self.f.encrypt(file_data)
        self._write_file(filename, encrypted_data)

    def decrypt(self, filename):
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        try:
            decrypted_data = self.f.decrypt(encrypted_data)
        except cryptography.fernet.InvalidToken:
            print("Недопустимый токен.")
            return
        self._write_file(filename, decrypted_data)
        print("Файл успешно расшифрован")

    @staticmethod
    def _write_file(filename, data):
        with open(filename, "wb") as file:
            file.write(data)


def main():
    parser = argparse.ArgumentParser(description="Скрипт для шифрования/дешифрования файлов с паролем")
    parser.add_argument("file", help="Файл для шифрования/дешифрования")
    parser.add_argument("-s", "--salt-size", type=int, help="Размер соли (по умолчанию 16 байт)", default=16)
    parser.add_argument("-e", "--encrypt", action="store_true", help="Зашифровать файл")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Расшифровать файл")

    args = parser.parse_args()
    file = args.file
    password = getpass.getpass("Введите пароль: ")

    key_manager = KeyManager(salt_size=args.salt_size)
    key = key_manager.derive_key(password)

    file_encryptor = FileEncryptor(key)

    if args.encrypt:
        file_encryptor.encrypt(file)
    elif args.decrypt:
        file_encryptor.decrypt(file)
    else:
        raise ValueError("Пожалуйста, укажите, хотите ли вы зашифровать или расшифровать файл.")


if __name__ == "__main__":
    main()

import os
from cryptography.fernet import Fernet

# Racine du projet : la clé est stockée au même endroit quel que soit le dossier courant.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CryptoVault:
    def __init__(self, key_file=None):
        self.key_file = key_file or os.path.join(BASE_DIR, "secret.key")
        self._key = None

    @property
    def key(self):
        """Clé Fernet, chargée depuis le disque ou générée au premier usage."""
        if self._key is None:
            if not os.path.exists(self.key_file):
                self.generate_key()
            self._key = self.load_key()
        return self._key

    def generate_key(self):
        """Génère une clé de chiffrement et l'enregistre dans un fichier (lisible par le seul propriétaire)."""
        key = Fernet.generate_key()
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(key)
        self._key = key
        print("[+] Clé de chiffrement générée avec succès.")

    def load_key(self):
        """Charge la clé depuis le fichier local."""
        with open(self.key_file, "rb") as key_file:
            return key_file.read()

    def encrypt_file(self, filename):
        """Chiffre un fichier pour le rendre illisible."""
        f = Fernet(self.key)
        with open(filename, "rb") as file:
            file_data = file.read()
        with open(filename, "wb") as file:
            file.write(f.encrypt(file_data))
        print(f"[*] Le fichier {filename} a été sécurisé (chiffré).")

    def decrypt_file(self, filename):
        """Déchiffre un fichier pour retrouver les données originales."""
        f = Fernet(self.key)
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        with open(filename, "wb") as file:
            file.write(f.decrypt(encrypted_data))
        print(f"[+] Le fichier {filename} a été restauré (déchiffré).")

from cryptography.fernet import Fernet
import os

class CryptoVault:
    def __init__(self):
        self.key_file = "secret.key"

    def generate_key(self):
        """Génère une clé de chiffrement et l'enregistre dans un fichier."""
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as key_file:
            key_file.write(key)
        print("[+] Clé de chiffrement générée avec succès.")

    def load_key(self):
        """Charge la clé depuis le fichier local."""
        return open(self.key_file, "rb").read()

    def encrypt_file(self, filename):
        """Chiffre un fichier pour le rendre illisible."""
        key = self.load_key()
        f = Fernet(key)
        
        with open(filename, "rb") as file:
            file_data = file.read()
            
        encrypted_data = f.encrypt(file_data)
        
        with open(filename, "wb") as file:
            file.write(encrypted_data)
        print(f"[*] Le fichier {filename} a été sécurisé (chiffré).")

    def decrypt_file(self, filename):
        """Déchiffre un fichier pour retrouver les données originales."""
        key = self.load_key()
        f = Fernet(key)
        
        with open(filename, "rb") as file:
            encrypted_data = file.read()
            
        decrypted_data = f.decrypt(encrypted_data)
        
        with open(filename, "wb") as file:
            file.write(decrypted_data)
        print(f"[+] Le fichier {filename} a été restauré (déchiffré).")
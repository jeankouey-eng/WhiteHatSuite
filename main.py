import threading
import os
import sys
from core.network import NetworkTools 
from core.scanner import SystemScanner
from serveur.app import run_server
from core.crypto_vault import CryptoVault

def display_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\033[92m" + r"""
    __      __.__                      ___ ___         __   
    /  \    /  \  |__ _____  __ ____   /   |   \_____ _/  |_ 
    \   \/\/   /  |  \\__  \ \  \/  \ /    ~    \__  \\   __\\
     \        /|   Y  \/ __ \ >    <  \    Y    // __ \|  |  
      \__/\  / |___|  (____  /__/\_ \  \___|_  /(____  /__|  
           \/       \/     \/      \/        \/      \/      
    """ + "\033[0m")
    print("    [ VERSION 1.0 - MODE PROFESSIONNEL ]\n")

def main():
    display_banner()

    # 1. Démarrage de l'interface Dashboard en tâche de fond (Thread)
    print("[*] Lancement du serveur Web...")
    web_thread = threading.Thread(target=run_server, daemon=True)
    web_thread.start()

    # 2. Initialisation des outils
    sys_scanner = SystemScanner()
    net = NetworkTools()

    while True:
        try:
            print("\n\033[94m[ MENU ]\033[0m")
            print("1. Scanner la persistance (Registre)")
            print("2. Lancer un test réseau")
            print("3. Quitter")
            
            choix = input("\nAction > ")

            if choix == "1":
                print("[*] Analyse des clés de démarrage...")
                results = sys_scanner.check_persistence()
                for item in results:
                    print(f"  [!] Trouvé ({item['hive']}) : {item['name']}")

            elif choix == "2":
                target = input("IP à scanner :")
                if net.ping_scan(target):
                    print(f"[+] {target} est EN LIGNE.")
                    # On lance le scan de ports si la machine répond
                    found = net.port_scan(target)
                    if found:
                        print(f"    [!] Ports ouverts trouvés : {found}")
                        # identification des services
                        for p in found:
                            service = "Web" if p in [80, 443] else "Fichier/SMB" if p == 445 else "Remote Desktop" if p == 3389 else "Inconnu"
                            print(f"        -> Port {p} : {service}")
                    else:
                        print("    [-] Aucun port commun ouvert trouvé.")
                else:
                    print(f"[-] {target} ne répond pas.")

            elif choix == "3":
                print("[*] Fermeture du programme...")
                break

            else:
                print("[!] Choix invalide, veuillez sélectionner 1, 2 ou 3.")

        except KeyboardInterrupt:
            print("\n[*] Arrêt demandé par l'utilisateur.")
            break


if __name__ == "__main__":
    main()
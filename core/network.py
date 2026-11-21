import ipaddress
import platform
import socket
import subprocess

import requests

DEFAULT_PORTS = (21, 22, 80, 443, 445, 3389)

class NetworkManager:
    """Regroupe les outils de scan technique et d'intelligence OSINT."""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        # Base de données pour la Threat Intelligence
        self.abuse_url = "https://api.abuseipdb.com/api/v2/check"
        # Credentials par défaut pour l'audit de vulnérabilité
        self.default_creds = {
            445: "admin/admin (SMB)",
            3389: "administrator/password123 (RDP)",
            80: "admin/password (HTTP)"
        }

    # --- PARTIE 1 : SCANNER TECHNIQUE ---

    @staticmethod
    def is_valid_ip(target_ip):
        try:
            ipaddress.ip_address(target_ip)
            return True
        except ValueError:
            return False

    def ping_scan(self, target_ip, timeout=2):
        """Vérifie si l'hôte répond (ICMP via la commande ping, puis repli TCP)."""
        if not self.is_valid_ip(target_ip):
            print(f"[!] Adresse IP invalide : {target_ip}")
            return False

        count_flag = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", count_flag, "1", target_ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1,
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Repli : l'ICMP est souvent filtré, on tente une connexion TCP rapide.
        return bool(self.port_scan(target_ip, ports=(80, 443, 22, 445), verbose=False))

    def port_scan(self, target_ip, ports=DEFAULT_PORTS, verbose=True):
        """Scanne les ports ouverts pour identifier la surface d'attaque."""
        open_ports = []
        if verbose:
            print(f"[*] Scan technique en cours sur {target_ip}...")

        family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
        for port in ports:
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)  # Timeout rapide pour l'efficacité
                    # connect_ex renvoie 0 si le port est ouvert
                    if sock.connect_ex((target_ip, port)) == 0:
                        open_ports.append(port)
            except OSError as e:
                if verbose:
                    print(f"[!] Erreur sur le port {port}: {e}")
                
        return open_ports

    # --- PARTIE 2 : THREAT INTELLIGENCE (OSINT) ---

    def get_ip_reputation(self, ip_address):
        """Interroge la réputation d'une IP pour évaluer le risque."""
        print(f"[*] Analyse de réputation OSINT pour : {ip_address}...")

        if not self.api_key:
            print("[!] Clé API non configurée. Retour de la simulation locale.")
            return {
                "ip": ip_address,
                "is_malicious": True if not ip_address.startswith("192.") else False,
                "abuse_score": 85 if not ip_address.startswith("192.") else 0,
                "country": "Inconnu" if not ip_address.startswith("192.") else "Local Network",
                "usage_type": "Data Center / VPN"
            }

        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address
        }

        try:
            response = requests.get(self.abuse_url, headers=headers, params=params, timeout=5)
            response.raise_for_status()
            result = response.json().get("data", {})

            return {
                "ip": ip_address,
                "is_malicious": result.get("abuseConfidenceScore", 0) > 50,
                "abuse_score": result.get("abuseConfidenceScore", 0),
                "country": result.get("countryCode", "Inconnu"),
                "usage_type": result.get("usageType", "Inconnu"),
                "last_reported_at": result.get("lastReportedAt")
            }
        except requests.RequestException as e:
            print(f"[!] Erreur API Threat Intelligence: {e}")
            return {
                "ip": ip_address,
                "is_malicious": False,
                "abuse_score": 0,
                "country": "Inconnu",
                "usage_type": "Inconnu"
            }

    def analyze_target(self, target_ip):
        """Fusionne le scan et la réputation pour un rapport complet."""
        reputation = self.get_ip_reputation(target_ip)
        ports = self.port_scan(target_ip)
        
        report = {
            "target": target_ip,
            "risk_score": reputation["abuse_score"],
            "open_ports": ports,
            "status": "DANGEREUX" if reputation["abuse_score"] > 50 else "SÛR"
        }
        return report
    


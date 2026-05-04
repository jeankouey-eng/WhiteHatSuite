import socket
import subprocess
import platform
from datetime import datetime

class NetworkTools:
    def __init__(self):
        # Dictionnaire des credentials par défaut à tester
        self.default_creds = {
            445: "admin/admin",
            3389: "administrator/password123",
            80: "admin/password"
        }

    def port_scan(self, target_ip, ports=[21, 22, 80, 443, 445, 3389]):
        """Scanne une liste de ports spécifiques sur une IP cible"""
        open_ports = []
        passwords = {445: "smb_pass", 3389: "rdp_pass"}
        print(f"[*] Scan des ports sur {target_ip}...")
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            
        return open_ports
    


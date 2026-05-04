#  WhiteHatSuite - Cyber Analysis Tool

**WhiteHatSuite** est un outil pédagogique développé en Python, conçu pour l'analyse réseau et l'OSINT (Open Source Intelligence). Il permet aux administrateurs et aux passionnés de cybersécurité d'auditer leur propre surface d'exposition.

## Fonctionnalités
- **Recherche d'IP :** Localisation et analyse de la réputation d'une adresse IP (OSINT).
- **Audit Réseau :** Identification des ports ouverts et détection de services vulnérables.
- **Analyse de Connexions :** Surveillance des états TCP (ESTABLISHED, LISTEN) pour détecter des connexions suspectes.
- **Sécurité Wi-Fi :** Vérification du type de chiffrement et des vulnérabilités courantes.

##  Installation & Utilisation
### Prérequis
 Python 3.x
 Bibliothèques : `requests`, `scapy`, `colorama`

### Installation
```bash
git clone https://github.com/jeankouey-eng/WhiteHatSuite.git
cd WhiteHatSuite
pip install -r requirements.txt
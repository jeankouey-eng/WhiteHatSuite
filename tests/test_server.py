import json
import threading

from cryptography.fernet import Fernet


def read_log(srv):
    """Lit le log indépendamment du code serveur : une ligne chiffrée par entrée."""
    f = Fernet(srv.vault.key)
    with open(srv.LOG_FILE, "rb") as fh:
        return [json.loads(f.decrypt(line)) for line in fh if line.strip()]


# --- Authentification ---

def test_dashboard_requires_login(client):
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_bad_password_rejected(client):
    client.post("/login", data={"username": "admin", "password": "mauvais"})
    assert client.get("/").status_code == 302


def test_missing_fields_rejected(client):
    assert client.post("/login", data={}).status_code == 200
    assert client.get("/").status_code == 302


def test_login_then_dashboard(logged_client):
    assert logged_client.get("/").status_code == 200


def test_old_hardcoded_password_no_longer_works(client):
    client.post("/login", data={"username": "admin", "password": "WhiteHat2026!"})
    assert client.get("/").status_code == 302


# --- Dashboard ---

def test_dashboard_empty_log(logged_client):
    r = logged_client.get("/")
    assert r.status_code == 200
    assert b"0.0.0.0" in r.data


def test_dashboard_shows_newest_first(srv, logged_client):
    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
        srv.save_secure_capture({"type": "T", "contenu": {"ip_origine": ip, "navigateur": "UA"}})
    html = logged_client.get("/").get_data(as_text=True)
    assert html.index("10.0.0.3") < html.index("10.0.0.1")


def test_dashboard_escapes_html(srv, logged_client):
    srv.save_secure_capture({"type": "T", "contenu": {"ip_origine": "1.1.1.1", "navigateur": "<script>alert(1)</script>"}})
    html = logged_client.get("/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_dashboard_survives_corrupt_log(srv, logged_client):
    with open(srv.LOG_FILE, "wb") as f:
        f.write(b"pas du tout chiffre")
    assert logged_client.get("/").status_code == 200


# --- Capture ---

def test_capture_is_stored_encrypted(srv, client):
    r = client.post("/capture_pong", json={"navigateur": "UA-test"})
    assert r.status_code == 204
    raw = open(srv.LOG_FILE, "rb").read()
    assert b"UA-test" not in raw  # pas en clair sur le disque
    entries = read_log(srv)
    assert entries[0]["contenu"]["navigateur"] == "UA-test"
    assert entries[0]["timestamp"]


def test_capture_non_json_body(srv, client):
    assert client.post("/capture_pong", data="n'importe quoi").status_code == 204
    assert len(read_log(srv)) == 1


def test_capture_json_list_body_does_not_crash(srv, client):
    assert client.post("/capture_pong", json=[1, 2, 3]).status_code == 204


def test_oversized_request_rejected(srv, client):
    big = {"x": "A" * (2 * 1024 * 1024)}
    assert client.post("/capture_pong", json=big).status_code == 413


def test_unreadable_lines_are_kept_and_skipped(srv, client, logged_client):
    """Une ligne illisible (clé changée, fichier abîmé) ne doit ni être effacée ni tout bloquer."""
    with open(srv.LOG_FILE, "wb") as f:
        f.write(b"ligne chiffree avec une autre cle\n")
    client.post("/capture_pong", json={"navigateur": "UA-ok"})
    raw = open(srv.LOG_FILE, "rb").read()
    assert raw.startswith(b"ligne chiffree avec une autre cle")  # rien d'effacé
    html = logged_client.get("/").get_data(as_text=True)
    assert "UA-ok" in html


def test_reads_old_single_block_format(srv, logged_client):
    """Les logs créés par l'ancienne version (une seule liste chiffrée) restent lisibles."""
    old = [{"type": "T", "timestamp": "2026-01-01 00:00:00", "contenu": {"ip_origine": "10.9.9.9", "navigateur": "ancien"}}]
    with open(srv.LOG_FILE, "wb") as f:
        f.write(Fernet(srv.vault.key).encrypt(json.dumps(old).encode()))
    srv.save_secure_capture({"type": "T", "contenu": {"ip_origine": "10.1.1.1", "navigateur": "nouveau"}})
    captures, total = srv.read_captures()
    assert total == 2
    assert [c["contenu"]["navigateur"] for c in captures] == ["nouveau", "ancien"]


def test_capture_cost_does_not_grow_with_log_size(srv):
    """Avec un gros log, ajouter une capture doit rester instantané."""
    import time
    token = Fernet(srv.vault.key).encrypt(json.dumps({"type": "T", "contenu": {}}).encode())
    with open(srv.LOG_FILE, "wb") as f:
        f.write((token + b"\n") * 50_000)
    start = time.perf_counter()
    for _ in range(20):
        srv.save_secure_capture({"type": "T", "contenu": {"navigateur": "x"}})
    assert (time.perf_counter() - start) / 20 < 0.05


def test_dashboard_limits_rows_but_counts_all(srv, logged_client, monkeypatch):
    monkeypatch.setattr(srv, "DASHBOARD_LIMIT", 5)
    for i in range(12):
        srv.save_secure_capture({"type": "T", "contenu": {"ip_origine": f"10.0.0.{i}", "navigateur": "UA"}})
    html = logged_client.get("/").get_data(as_text=True)
    assert ">12<" in html.replace(" ", "").replace("\n", "")
    assert "10.0.0.11" in html and "10.0.0.6" not in html.split("Flux d")[1]


def test_concurrent_captures_are_all_kept(srv):
    """Le serveur Flask est multi-thread : aucune capture ne doit être perdue."""
    n_threads, per_thread = 8, 15

    def worker(i):
        c = srv.app.test_client()
        for j in range(per_thread):
            c.post("/capture_pong", json={"navigateur": f"t{i}-{j}"})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(read_log(srv)) == n_threads * per_thread


def test_log_survives_restart(srv, client, tmp_path):
    from core.crypto_vault import CryptoVault
    client.post("/capture_pong", json={"navigateur": "avant"})
    srv.vault = CryptoVault(key_file=str(tmp_path / "test.key"))  # nouvelle instance = redémarrage
    client.post("/capture_pong", json={"navigateur": "apres"})
    assert [e["contenu"]["navigateur"] for e in read_log(srv)] == ["avant", "apres"]

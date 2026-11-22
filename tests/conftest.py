import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("WHS_ADMIN_PASSWORD", "test-password")
os.environ.setdefault("WHS_SECRET_KEY", "test-secret")


@pytest.fixture
def srv(tmp_path, monkeypatch):
    """Module serveur isolé : clé et log dans un dossier temporaire."""
    from core.crypto_vault import CryptoVault
    from serveur import app as srv_module

    monkeypatch.setattr(srv_module, "vault", CryptoVault(key_file=str(tmp_path / "test.key")))
    monkeypatch.setattr(srv_module, "LOG_FILE", str(tmp_path / "captures.json"))
    srv_module.app.config["TESTING"] = True
    return srv_module


@pytest.fixture
def client(srv):
    return srv.app.test_client()


@pytest.fixture
def logged_client(client):
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client

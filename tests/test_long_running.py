"""Tests du programme réel lancé en arrière-plan (comme sur ton ordinateur)."""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

import pytest
from cryptography.fernet import Fernet

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_server(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            NO_PROXY_OPENER.open(f"http://127.0.0.1:{port}/login", timeout=1)
            return True
        except OSError:
            time.sleep(0.2)
    return False


def post_capture(port, payload):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/capture_pong",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return NO_PROXY_OPENER.open(req, timeout=10).status


@pytest.fixture
def launch(tmp_path):
    procs = []

    def _launch(*args):
        port = free_port()
        env = dict(os.environ, WHS_PORT=str(port), WHS_ADMIN_PASSWORD="pw",
                   WHS_LOG_FILE=str(tmp_path / "captures.json"),
                   WHS_KEY_FILE=str(tmp_path / "test.key"), PYTHONUNBUFFERED="1")
        out = open(tmp_path / f"sortie-{port}.log", "wb")  # un tuyau non lu finirait par bloquer le serveur
        p = subprocess.Popen([sys.executable, os.path.join(ROOT, "main.py"), *args],
                             cwd=str(tmp_path), env=env, stdin=subprocess.DEVNULL,
                             stdout=out, stderr=subprocess.STDOUT)
        procs.append(p)
        return p, port

    yield _launch
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def test_server_mode_stays_up(launch):
    p, port = launch("--serveur")
    assert wait_for_server(port)
    time.sleep(3)
    assert p.poll() is None, "le serveur s'est arrêté tout seul"
    assert post_capture(port, {"navigateur": "test"}) == 204


def test_menu_mode_without_console_keeps_server(launch):
    """Lancé sans console (raccourci, tâche planifiée) : le serveur ne doit pas mourir."""
    p, port = launch()
    assert wait_for_server(port)
    time.sleep(3)
    assert p.poll() is None, "le programme a planté sans console"


@pytest.mark.endurance
def test_endurance_concurrent_load(launch, tmp_path):
    """Charge soutenue et parallèle sur le vrai serveur : rien ne doit être perdu."""
    duration = float(os.environ.get("WHS_ENDURANCE_SECONDS", "30"))
    p, port = launch("--serveur")
    assert wait_for_server(port)

    sent, errors = [0], []
    lock = threading.Lock()
    stop = time.time() + duration

    def worker(i):
        n = 0
        while time.time() < stop:
            try:
                assert post_capture(port, {"navigateur": f"w{i}-{n}"}) == 204
                with lock:
                    sent[0] += 1
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
            n += 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert p.poll() is None, "le serveur a planté pendant la charge"
    assert not errors, errors[:5]
    key = (tmp_path / "test.key").read_bytes()
    f = Fernet(key)
    entries = [json.loads(f.decrypt(l)) for l in (tmp_path / "captures.json").read_bytes().splitlines() if l]
    assert len(entries) == sent[0], f"{sent[0] - len(entries)} captures perdues"
    print(f"\n[endurance] {sent[0]} captures en {duration:.0f}s, 0 perte, 0 erreur")

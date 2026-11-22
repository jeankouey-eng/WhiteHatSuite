import socket
import threading

import pytest

from core.network import NetworkManager


@pytest.fixture
def listening_port():
    """Ouvre un vrai port TCP local pour tester le scan."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    yield port
    stop.set()
    t.join()
    srv.close()


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.10", "::1"])
def test_valid_ips(ip):
    assert NetworkManager.is_valid_ip(ip)


@pytest.mark.parametrize("ip", ["", "abc", "127.0.0.1; rm -rf /", "999.1.1.1", "-c 1000 8.8.8.8"])
def test_invalid_ips_rejected_without_running_ping(ip, monkeypatch):
    import subprocess
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
    assert NetworkManager().ping_scan(ip) is False
    assert called == []  # aucune commande lancée avec une entrée invalide


def test_port_scan_finds_open_port(listening_port):
    assert NetworkManager().port_scan("127.0.0.1", ports=(listening_port,)) == [listening_port]


def test_port_scan_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # port libéré, donc fermé
    assert NetworkManager().port_scan("127.0.0.1", ports=(port,)) == []


def test_port_scan_does_not_leak_sockets(listening_port):
    """Des milliers de scans ne doivent pas épuiser les descripteurs de fichiers."""
    net = NetworkManager()
    for _ in range(2000):
        net.port_scan("127.0.0.1", ports=(listening_port,), verbose=False)


def test_ping_scan_falls_back_to_tcp(monkeypatch):
    import subprocess

    def no_ping(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", no_ping)
    net = NetworkManager()
    monkeypatch.setattr(net, "port_scan", lambda ip, ports, verbose: [80])
    assert net.ping_scan("127.0.0.1") is True


def test_reputation_simulation_without_api_key():
    net = NetworkManager()
    assert net.get_ip_reputation("192.168.1.1")["abuse_score"] == 0
    assert net.get_ip_reputation("8.8.8.8")["is_malicious"] is True


def test_reputation_api_error_is_handled(monkeypatch):
    import requests
    net = NetworkManager(api_key="dummy")

    def boom(*a, **k):
        raise requests.ConnectionError("réseau coupé")

    monkeypatch.setattr(requests, "get", boom)
    result = net.get_ip_reputation("8.8.8.8")
    assert result["abuse_score"] == 0

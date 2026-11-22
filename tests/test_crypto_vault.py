import os
import stat

import pytest
from cryptography.fernet import InvalidToken

from core.crypto_vault import CryptoVault


def test_key_generated_once_and_reused(tmp_path):
    path = tmp_path / "k.key"
    k1 = CryptoVault(key_file=str(path)).key
    k2 = CryptoVault(key_file=str(path)).key  # simule un redémarrage
    assert k1 == k2
    assert path.exists()


@pytest.mark.skipif(os.name == "nt", reason="permissions POSIX")
def test_key_file_is_private(tmp_path):
    path = tmp_path / "k.key"
    CryptoVault(key_file=str(path)).key
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_encrypt_decrypt_roundtrip(tmp_path):
    vault = CryptoVault(key_file=str(tmp_path / "k.key"))
    f = tmp_path / "data.txt"
    f.write_bytes(b"donnees sensibles")
    vault.encrypt_file(str(f))
    assert f.read_bytes() != b"donnees sensibles"
    vault.decrypt_file(str(f))
    assert f.read_bytes() == b"donnees sensibles"


def test_wrong_key_cannot_decrypt(tmp_path):
    f = tmp_path / "data.txt"
    f.write_bytes(b"secret")
    CryptoVault(key_file=str(tmp_path / "a.key")).encrypt_file(str(f))
    with pytest.raises(InvalidToken):
        CryptoVault(key_file=str(tmp_path / "b.key")).decrypt_file(str(f))


def test_first_start_concurrent_access_single_key(tmp_path):
    """Au premier démarrage, des accès simultanés doivent tous obtenir la même clé."""
    import threading
    vault = CryptoVault(key_file=str(tmp_path / "k.key"))
    keys, barrier = [], threading.Barrier(16)

    def grab():
        barrier.wait()
        keys.append(vault.key)

    threads = [threading.Thread(target=grab) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(keys)) == 1
    assert (tmp_path / "k.key").read_bytes() == keys[0]

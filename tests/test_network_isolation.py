"""Verify that privault never makes any outbound network connections.

If any code in the test suite attempts to open a socket, this test fails.
This is the AI-resistance guarantee: vault data never leaves your machine.
"""

import socket

import pytest

from privault.crypto import decrypt, derive_key, encrypt, generate_salt
from privault.models import PasswordEntry
from privault.vault import VaultSession


def _network_forbidden(*args, **kwargs):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "NETWORK ACCESS DETECTED — privault must never make network calls. "
        "This is a security violation."
    )


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch socket to fail if any code opens a network connection."""
    monkeypatch.setattr(socket, "create_connection", _network_forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", _network_forbidden)


def test_crypto_no_network() -> None:
    salt = generate_salt()
    key = derive_key("password", salt)
    ct = encrypt(key, b"hello")
    assert decrypt(key, ct) == b"hello"


def test_models_no_network() -> None:
    e = PasswordEntry(site="x", username="u", password="p")
    assert e.to_dict()["site"] == "x"


def test_vault_init_no_network(tmp_path) -> None:  # type: ignore[no-untyped-def]
    vault_path = tmp_path / "vault.db"
    session = VaultSession.init(vault_path, "test-pass")
    session.lock()


def test_vault_unlock_no_network(tmp_path) -> None:  # type: ignore[no-untyped-def]
    vault_path = tmp_path / "vault.db"
    VaultSession.init(vault_path, "test-pass").lock()
    session = VaultSession.unlock(vault_path, "test-pass")
    session.lock()

"""Tests for privault.vault module."""

from pathlib import Path

import pytest

from privault.vault import (
    VaultNotFoundError,
    VaultSession,
    WrongPasswordError,
    get_default_vault_path,
)


def test_init_creates_vault_file(tmp_vault_path: Path, master_password: str) -> None:
    session = VaultSession.init(tmp_vault_path, master_password)
    assert tmp_vault_path.exists()
    session.lock()


def test_init_sets_file_permissions(tmp_vault_path: Path, master_password: str) -> None:
    session = VaultSession.init(tmp_vault_path, master_password)
    mode = oct(tmp_vault_path.stat().st_mode)[-3:]
    assert mode == "600"
    session.lock()


def test_init_raises_if_vault_exists(
    tmp_vault_path: Path, master_password: str
) -> None:
    VaultSession.init(tmp_vault_path, master_password).lock()
    with pytest.raises(FileExistsError):
        VaultSession.init(tmp_vault_path, master_password)


def test_unlock_correct_password(tmp_vault_path: Path, master_password: str) -> None:
    VaultSession.init(tmp_vault_path, master_password).lock()
    session = VaultSession.unlock(tmp_vault_path, master_password)
    assert session is not None
    session.lock()


def test_unlock_wrong_password_raises(
    tmp_vault_path: Path, master_password: str
) -> None:
    VaultSession.init(tmp_vault_path, master_password).lock()
    with pytest.raises(WrongPasswordError):
        VaultSession.unlock(tmp_vault_path, "wrong-password")


def test_unlock_missing_vault_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent.db"
    with pytest.raises(VaultNotFoundError):
        VaultSession.unlock(missing, "any-password")


def test_lock_zeros_key(tmp_vault_path: Path, master_password: str) -> None:
    session = VaultSession.init(tmp_vault_path, master_password)
    session.lock()
    assert all(b == 0 for b in session._key)


def test_write_and_read_through_session(
    tmp_vault_path: Path, master_password: str
) -> None:
    session = VaultSession.init(tmp_vault_path, master_password)
    session.storage.write_entry("e1", "password", {"password": "topsecret"})
    session.lock()

    session2 = VaultSession.unlock(tmp_vault_path, master_password)
    data = session2.storage.read_entry("e1")
    assert data["password"] == "topsecret"
    session2.lock()


def test_audit_key_is_derived(tmp_vault_path: Path, master_password: str) -> None:
    session = VaultSession.init(tmp_vault_path, master_password)
    audit_key = session.audit_key()
    assert len(audit_key) == 32
    assert audit_key != bytes(session._key)
    session.lock()


def test_get_default_vault_path() -> None:
    path = get_default_vault_path()
    assert path.name == "vault.db"
    assert path.parent.name == ".privault"

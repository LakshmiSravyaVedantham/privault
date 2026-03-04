"""Tests for privault.storage module."""

import sqlite3

import pytest

from privault.storage import EntryNotFoundError, VaultStorage


@pytest.fixture
def storage(tmp_vault_path, session_key) -> VaultStorage:  # type: ignore[no-untyped-def]
    s = VaultStorage(tmp_vault_path, session_key)
    s.init_db()
    return s


def test_write_and_read_roundtrip(storage: VaultStorage) -> None:
    data = {"site": "github.com", "username": "sravya", "password": "s3cr3t!"}
    storage.write_entry("entry-1", "password", data)
    result = storage.read_entry("entry-1")
    assert result == data


def test_ciphertext_on_disk(tmp_vault_path, session_key) -> None:  # type: ignore[no-untyped-def]
    """Raw SQLite blob must NOT contain the plaintext password."""
    s = VaultStorage(tmp_vault_path, session_key)
    s.init_db()
    data = {"password": "super-secret-password-12345"}
    s.write_entry("entry-x", "password", data)
    s.close()

    # Read raw bytes from SQLite — no decryption
    conn = sqlite3.connect(str(tmp_vault_path))
    row = conn.execute(
        "SELECT encrypted_data FROM entries WHERE id = 'entry-x'"
    ).fetchone()
    conn.close()
    raw_blob = bytes(row[0])
    assert b"super-secret-password-12345" not in raw_blob


def test_read_wrong_key_raises(tmp_vault_path, session_key) -> None:  # type: ignore[no-untyped-def]
    s = VaultStorage(tmp_vault_path, session_key)
    s.init_db()
    s.write_entry("entry-1", "password", {"secret": "value"})
    s.close()

    wrong_key = b"1" * 32
    s2 = VaultStorage(tmp_vault_path, wrong_key)
    with pytest.raises(ValueError):
        s2.read_entry("entry-1")


def test_read_missing_entry_raises(storage: VaultStorage) -> None:
    with pytest.raises(EntryNotFoundError):
        storage.read_entry("does-not-exist")


def test_list_entries_no_category(storage: VaultStorage) -> None:
    storage.write_entry("e1", "password", {"site": "github"})
    storage.write_entry("e2", "health", {"provider": "Dr Smith"})
    entries = storage.list_entries()
    ids = [e["id"] for e in entries]
    assert "e1" in ids
    assert "e2" in ids


def test_list_entries_filtered_by_category(storage: VaultStorage) -> None:
    storage.write_entry("e1", "password", {"site": "github"})
    storage.write_entry("e2", "health", {"provider": "Dr Smith"})
    password_entries = storage.list_entries(category="password")
    assert all(e["category"] == "password" for e in password_entries)
    assert len(password_entries) == 1


def test_list_entries_no_secrets(storage: VaultStorage) -> None:
    """list_entries must not return any encrypted data fields."""
    storage.write_entry("e1", "password", {"password": "topsecret"})
    entries = storage.list_entries()
    assert len(entries) == 1
    assert "password" not in entries[0]
    assert set(entries[0].keys()) == {"id", "category", "created_at"}


def test_delete_entry(storage: VaultStorage) -> None:
    storage.write_entry("e1", "password", {"site": "github"})
    storage.delete_entry("e1")
    with pytest.raises(EntryNotFoundError):
        storage.read_entry("e1")


def test_search_entries(storage: VaultStorage) -> None:
    storage.write_entry(
        "e1", "password", {"site": "github.com", "username": "sravya", "password": "x"}
    )
    storage.write_entry(
        "e2", "password", {"site": "gitlab.com", "username": "sravya", "password": "y"}
    )
    results = storage.search_entries("github")
    assert len(results) == 1
    assert results[0]["id"] == "e1"


def test_search_case_insensitive(storage: VaultStorage) -> None:
    storage.write_entry(
        "e1", "password", {"site": "GitHub.COM", "username": "u", "password": "p"}
    )
    results = storage.search_entries("github")
    assert len(results) == 1

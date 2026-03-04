"""Shared pytest fixtures for privault tests."""

from pathlib import Path

import pytest


@pytest.fixture
def tmp_vault_path(tmp_path: Path) -> Path:
    """Return a temporary path for a vault file."""
    return tmp_path / "test_vault.db"


@pytest.fixture
def tmp_audit_path(tmp_path: Path) -> Path:
    """Return a temporary path for an audit log."""
    return tmp_path / "audit.log"


@pytest.fixture
def master_password() -> str:
    return "TestMasterPassword!99"


@pytest.fixture
def session_key() -> bytes:
    """A fixed 32-byte test key."""
    return b"0" * 32

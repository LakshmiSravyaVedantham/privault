"""Tests for privault CLI commands."""

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from privault.cli import app
from privault.vault import VaultSession

runner = CliRunner()

MASTER_PASSWORD = "TestPass!99"


@pytest.fixture
def initialized_vault(tmp_vault_path: Path) -> Path:
    """Create an initialized vault and return its path."""
    VaultSession.init(tmp_vault_path, MASTER_PASSWORD).lock()
    return tmp_vault_path


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_init_creates_vault(tmp_vault_path: Path) -> None:
    result = runner.invoke(
        app,
        ["init", "--vault", str(tmp_vault_path)],
        input=f"{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert tmp_vault_path.exists()
    assert "Vault created" in result.output


def test_init_fails_if_vault_exists(tmp_vault_path: Path) -> None:
    runner.invoke(
        app,
        ["init", "--vault", str(tmp_vault_path)],
        input=f"{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n",
    )
    result = runner.invoke(
        app,
        ["init", "--vault", str(tmp_vault_path)],
        input=f"{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n",
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# add password
# ---------------------------------------------------------------------------


def test_add_password(initialized_vault: Path) -> None:
    with patch("privault.cli.copy_with_autoclean"):
        result = runner.invoke(
            app,
            ["add", "password", "--vault", str(initialized_vault)],
            input=f"{MASTER_PASSWORD}\ngithub.com\nsravya\npassword123\n\n\n",
        )
    assert result.exit_code == 0
    assert "github.com" in result.output


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


def test_get_password_entry(initialized_vault: Path) -> None:
    # Add an entry first
    with patch("privault.cli.copy_with_autoclean"):
        runner.invoke(
            app,
            ["add", "password", "--vault", str(initialized_vault)],
            input=f"{MASTER_PASSWORD}\ngitlab.com\nuser1\nmypass\n\n\n",
        )
        result = runner.invoke(
            app,
            ["get", "gitlab", "--vault", str(initialized_vault)],
            input=f"{MASTER_PASSWORD}\n",
        )
    assert result.exit_code == 0
    assert "gitlab.com" in result.output


def test_get_missing_entry(initialized_vault: Path) -> None:
    result = runner.invoke(
        app,
        ["get", "nonexistent", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\n",
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_empty_vault(initialized_vault: Path) -> None:
    result = runner.invoke(
        app,
        ["list", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert "No entries" in result.output


def test_list_shows_entries(initialized_vault: Path) -> None:
    with patch("privault.cli.copy_with_autoclean"):
        runner.invoke(
            app,
            ["add", "password", "--vault", str(initialized_vault)],
            input=f"{MASTER_PASSWORD}\nfacebook.com\nuser\npass\n\n\n",
        )
    result = runner.invoke(
        app,
        ["list", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert "password" in result.output


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


def test_search_finds_entry(initialized_vault: Path) -> None:
    with patch("privault.cli.copy_with_autoclean"):
        runner.invoke(
            app,
            ["add", "password", "--vault", str(initialized_vault)],
            input=f"{MASTER_PASSWORD}\namazon.com\nuser\npass\n\n\n",
        )
    result = runner.invoke(
        app,
        ["search", "amazon", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert "amazon" in result.output


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


def test_generate_password() -> None:
    with patch("privault.cli.copy_with_autoclean"):
        result = runner.invoke(app, ["generate", "--length", "20"])
    assert result.exit_code == 0
    assert "Generated:" in result.output


def test_generate_no_symbols() -> None:
    with patch("privault.cli.copy_with_autoclean"):
        result = runner.invoke(app, ["generate", "--no-symbols", "--length", "16"])
    assert result.exit_code == 0
    generated = result.output.split("Generated: ")[-1].strip()
    assert all(c.isalnum() for c in generated)


# ---------------------------------------------------------------------------
# lock
# ---------------------------------------------------------------------------


def test_lock_command() -> None:
    result = runner.invoke(app, ["lock"])
    assert result.exit_code == 0
    assert "encrypted" in result.output


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def test_export_creates_backup(initialized_vault: Path, tmp_path: Path) -> None:
    backup_path = tmp_path / "backup.enc"
    result = runner.invoke(
        app,
        ["export", "--out", str(backup_path), "--vault", str(initialized_vault)],
    )
    assert result.exit_code == 0
    assert backup_path.exists()
    assert "backup saved" in result.output


def test_export_fails_if_no_vault(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "export",
            "--out",
            str(tmp_path / "b.enc"),
            "--vault",
            str(tmp_path / "missing.db"),
        ],
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# add health / bank / note
# ---------------------------------------------------------------------------


def test_add_health(initialized_vault: Path) -> None:
    result = runner.invoke(
        app,
        ["add", "health", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\nDr Jones\ndoctor\nblood_type_A+\nnotes here\n",
    )
    assert result.exit_code == 0
    assert "Dr Jones" in result.output


def test_add_bank(initialized_vault: Path) -> None:
    result = runner.invoke(
        app,
        ["add", "bank", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\nChase\nchecking\n123456\n021000021\n\n",
    )
    assert result.exit_code == 0
    assert "Chase" in result.output


def test_add_note(initialized_vault: Path) -> None:
    result = runner.invoke(
        app,
        ["add", "note", "--vault", str(initialized_vault)],
        input=f"{MASTER_PASSWORD}\nSecret Plan\nThis is my secret note.\npersonal,work\n",
    )
    assert result.exit_code == 0
    assert "Secret Plan" in result.output


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_audit_shows_entries(tmp_vault_path: Path) -> None:
    # Init via CLI so INIT action is logged
    runner.invoke(
        app,
        ["init", "--vault", str(tmp_vault_path)],
        input=f"{MASTER_PASSWORD}\n{MASTER_PASSWORD}\n",
    )
    result = runner.invoke(
        app,
        ["audit", "--vault", str(tmp_vault_path)],
        input=f"{MASTER_PASSWORD}\n",
    )
    assert result.exit_code == 0
    assert "INIT" in result.output


# ---------------------------------------------------------------------------
# wrong password
# ---------------------------------------------------------------------------


def test_wrong_password_exits_nonzero(initialized_vault: Path) -> None:
    result = runner.invoke(
        app,
        ["list", "--vault", str(initialized_vault)],
        input="wrong-password\n",
    )
    assert result.exit_code != 0

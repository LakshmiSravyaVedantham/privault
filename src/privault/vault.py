"""Vault session management: init, unlock, lock."""

import hashlib
import sqlite3
import stat
from pathlib import Path

from privault.crypto import derive_key, generate_salt
from privault.storage import VaultStorage

# The canary is a known plaintext entry used to verify the master password.
_CANARY_ID = "__vault_canary__"
_CANARY_VALUE = "privault_v1_ok"


class VaultNotFoundError(Exception):
    """Raised when the vault file does not exist."""


class WrongPasswordError(Exception):
    """Raised when the master password is incorrect."""


class VaultSession:
    """Manages an active vault session with an in-memory session key.

    The master password is never stored. The derived session key lives
    only in RAM and is zeroed when lock() is called.
    """

    def __init__(
        self,
        vault_path: Path,
        session_key: bytearray,
        storage: VaultStorage,
    ) -> None:
        self.vault_path = vault_path
        self._key = session_key
        self._storage = storage

    @property
    def storage(self) -> VaultStorage:
        return self._storage

    def audit_key(self) -> bytes:
        """Derive a separate HMAC key for the audit log from the session key."""
        return hashlib.sha256(bytes(self._key) + b":audit").digest()

    @classmethod
    def init(cls, vault_path: Path, master_password: str) -> "VaultSession":
        """Create a new vault. Raises FileExistsError if vault already exists."""
        if vault_path.exists():
            raise FileExistsError(f"Vault already exists at {vault_path}")
        vault_path.parent.mkdir(parents=True, exist_ok=True)

        salt = generate_salt()
        key = derive_key(master_password, salt)
        storage = VaultStorage(vault_path, key)
        storage.init_db()

        # Store salt in vault_meta (not secret — needed to derive key on unlock)
        conn = sqlite3.connect(str(vault_path))
        conn.execute(
            "INSERT INTO vault_meta (key, value) VALUES ('salt', ?)", (salt.hex(),)
        )
        conn.execute("INSERT INTO vault_meta (key, value) VALUES ('version', '1')")
        conn.commit()
        conn.close()

        # Write canary entry — used to verify master password on unlock
        storage.write_entry(_CANARY_ID, "__meta__", {"canary": _CANARY_VALUE})

        # Restrict file permissions to owner read/write only
        vault_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

        return cls(vault_path, bytearray(key), storage)

    @classmethod
    def unlock(cls, vault_path: Path, master_password: str) -> "VaultSession":
        """Unlock an existing vault. Raises VaultNotFoundError or WrongPasswordError."""
        if not vault_path.exists():
            raise VaultNotFoundError(f"Vault not found at {vault_path}")

        conn = sqlite3.connect(str(vault_path))
        row = conn.execute("SELECT value FROM vault_meta WHERE key = 'salt'").fetchone()
        conn.close()

        if row is None:
            raise VaultNotFoundError("Vault is corrupted: no salt found")

        salt = bytes.fromhex(row[0])
        key = derive_key(master_password, salt)
        storage = VaultStorage(vault_path, key)

        # Validate key by reading canary
        try:
            data = storage.read_entry(_CANARY_ID)
            if data.get("canary") != _CANARY_VALUE:
                raise WrongPasswordError("Wrong master password")
        except (ValueError, KeyError):
            raise WrongPasswordError("Wrong master password")

        return cls(vault_path, bytearray(key), storage)

    def lock(self) -> None:
        """Zero the session key in memory and close storage."""
        for i in range(len(self._key)):
            self._key[i] = 0
        self._storage.close()


def get_default_vault_path() -> Path:
    """Return the default vault location: ~/.privault/vault.db"""
    return Path.home() / ".privault" / "vault.db"

"""Encrypted SQLite storage layer for privault."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from privault.crypto import decrypt, encrypt


class EntryNotFoundError(KeyError):
    """Raised when a requested entry does not exist."""


class VaultStorage:
    """Stores encrypted entry blobs in a SQLite database.

    All field values are encrypted with AES-256-GCM before storage.
    Only entry ID, category, and timestamps are stored in plaintext.
    """

    def __init__(self, vault_path: Path, session_key: bytes) -> None:
        self.vault_path = vault_path
        self._key = session_key
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.vault_path))
        return self._conn

    def init_db(self) -> None:
        """Create tables if they do not exist."""
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """)
        conn.commit()

    def write_entry(
        self, entry_id: str, category: str, data: dict[str, object]
    ) -> None:
        """Encrypt and store an entry. Inserts or replaces."""
        now = datetime.now(timezone.utc).isoformat()
        plaintext = json.dumps(data).encode("utf-8")
        blob = encrypt(self._key, plaintext)
        conn = self._connect()
        conn.execute(
            """
            INSERT OR REPLACE INTO entries
                (id, category, encrypted_data, created_at, updated_at)
            VALUES (
                ?,
                ?,
                ?,
                COALESCE(
                    (SELECT created_at FROM entries WHERE id = ?),
                    ?
                ),
                ?
            )
            """,
            (entry_id, category, blob, entry_id, now, now),
        )
        conn.commit()

    def read_entry(self, entry_id: str) -> dict:  # type: ignore[type-arg]
        """Decrypt and return an entry's data dict.

        Raises:
            EntryNotFoundError: if entry_id does not exist.
            ValueError: if decryption fails (wrong key or tampered data).
        """
        conn = self._connect()
        row = conn.execute(
            "SELECT encrypted_data FROM entries WHERE id = ?", (entry_id,)
        ).fetchone()
        if row is None:
            raise EntryNotFoundError(f"Entry not found: {entry_id}")
        plaintext = decrypt(self._key, bytes(row[0]))
        result: dict = json.loads(plaintext)  # type: ignore[type-arg]
        return result

    def list_entries(self, category: Optional[str] = None) -> list[dict]:  # type: ignore[type-arg]
        """List entries without decrypting. Returns id, category, created_at only."""
        conn = self._connect()
        if category:
            rows = conn.execute(
                "SELECT id, category, created_at FROM entries "
                "WHERE category = ? AND category != '__meta__' ORDER BY created_at DESC",
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, category, created_at FROM entries "
                "WHERE category != '__meta__' ORDER BY created_at DESC"
            ).fetchall()
        return [{"id": r[0], "category": r[1], "created_at": r[2]} for r in rows]

    def search_entries(self, query: str) -> list[dict]:  # type: ignore[type-arg]
        """Decrypt all entries and search site/title/provider/institution/tags.

        Returns list of dicts with: id, category, name, data (full decrypted dict).
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, category, encrypted_data FROM entries "
            "WHERE category != '__meta__' ORDER BY created_at DESC"
        ).fetchall()
        q = query.lower()
        results = []
        for row in rows:
            entry_id, category, blob = row[0], row[1], bytes(row[2])
            try:
                data = json.loads(decrypt(self._key, blob))
            except ValueError:
                continue
            # Search across name fields
            searchable = " ".join(
                str(v)
                for k, v in data.items()
                if k in ("site", "title", "provider", "institution", "tags", "username")
            ).lower()
            if q in searchable:
                name = (
                    data.get("site")
                    or data.get("title")
                    or data.get("provider")
                    or data.get("institution")
                    or entry_id
                )
                results.append(
                    {"id": entry_id, "category": category, "name": name, "data": data}
                )
        return results

    def delete_entry(self, entry_id: str) -> None:
        """Delete an entry by ID."""
        conn = self._connect()
        conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

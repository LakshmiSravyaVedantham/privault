"""HMAC-signed append-only local audit log."""

import hashlib
import hmac
import time
from pathlib import Path
from typing import Any


class AuditTampered(Exception):
    """Raised when audit log HMAC verification fails."""


class AuditLog:
    """Append-only log where each line is signed with HMAC-SHA256.

    The HMAC key is derived from the vault session key, so only the vault
    owner can verify log integrity.
    """

    def __init__(self, log_path: Path, hmac_key: bytes) -> None:
        self.log_path = log_path
        self._key = hmac_key

    def _compute_hmac(self, line_content: str) -> str:
        return hmac.new(
            self._key, line_content.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def log(self, action: str, entry_id: str = "", category: str = "") -> None:
        """Append a signed log entry."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        content = f"{timestamp}|{action}|{entry_id}|{category}"
        mac = self._compute_hmac(content)
        line = f"{content}|{mac}\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def read(self) -> list[dict[str, Any]]:
        """Read and verify all log entries.

        Raises:
            AuditTampered: if any line fails HMAC verification.
        """
        if not self.log_path.exists():
            return []

        entries = []
        with open(self.log_path, encoding="utf-8") as f:
            for line_num, raw_line in enumerate(f, 1):
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) != 5:
                    raise AuditTampered(f"Line {line_num}: unexpected format")
                timestamp, action, entry_id, category, mac = parts
                content = f"{timestamp}|{action}|{entry_id}|{category}"
                expected = self._compute_hmac(content)
                if not hmac.compare_digest(mac, expected):
                    raise AuditTampered(
                        f"Line {line_num}: HMAC mismatch — log may have been tampered with"
                    )
                entries.append(
                    {
                        "timestamp": timestamp,
                        "action": action,
                        "entry_id": entry_id,
                        "category": category,
                    }
                )
        return entries

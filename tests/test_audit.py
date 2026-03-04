"""Tests for privault.audit module."""

from pathlib import Path

import pytest

from privault.audit import AuditLog, AuditTampered


@pytest.fixture
def audit_log(tmp_audit_path: Path) -> AuditLog:
    key = b"test-hmac-key-32-bytes-padding!!"
    return AuditLog(tmp_audit_path, key)


def test_log_and_read_roundtrip(audit_log: AuditLog) -> None:
    audit_log.log("UNLOCK")
    audit_log.log("READ", entry_id="abc123", category="password")
    entries = audit_log.read()
    assert len(entries) == 2
    assert entries[0]["action"] == "UNLOCK"
    assert entries[1]["action"] == "READ"
    assert entries[1]["entry_id"] == "abc123"
    assert entries[1]["category"] == "password"


def test_read_empty_log_returns_empty_list(tmp_audit_path: Path) -> None:
    key = b"a" * 32
    audit_log = AuditLog(tmp_audit_path, key)
    assert audit_log.read() == []


def test_read_nonexistent_log_returns_empty_list(tmp_path: Path) -> None:
    key = b"a" * 32
    audit_log = AuditLog(tmp_path / "missing.log", key)
    assert audit_log.read() == []


def test_tampered_line_raises(audit_log: AuditLog) -> None:
    audit_log.log("UNLOCK")
    audit_log.log("READ", entry_id="e1", category="password")

    # Tamper with the log file
    content = audit_log.log_path.read_text()
    lines = content.splitlines()
    # Flip one character in the first line's action field
    lines[0] = lines[0].replace("|UNLOCK|", "|HACKED|")
    audit_log.log_path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditTampered, match="HMAC mismatch"):
        audit_log.read()


def test_malformed_line_raises(tmp_audit_path: Path) -> None:
    key = b"a" * 32
    audit_log = AuditLog(tmp_audit_path, key)
    tmp_audit_path.write_text("bad|line\n")
    with pytest.raises(AuditTampered, match="unexpected format"):
        audit_log.read()


def test_log_entries_have_timestamps(audit_log: AuditLog) -> None:
    audit_log.log("INIT")
    entries = audit_log.read()
    assert "T" in entries[0]["timestamp"]  # ISO format contains T

"""Tests for privault.models module."""

import pytest
from pydantic import ValidationError

from privault.models import BankEntry, HealthEntry, NoteEntry, PasswordEntry


def test_password_entry_roundtrip() -> None:
    e = PasswordEntry(site="github.com", username="sravya", password="s3cr3t")
    d = e.to_dict()
    e2 = PasswordEntry.from_dict(d)
    assert e == e2


def test_password_entry_defaults() -> None:
    e = PasswordEntry(site="x.com", username="u", password="p")
    assert e.url == ""
    assert e.notes == ""


def test_password_entry_missing_required() -> None:
    with pytest.raises(ValidationError):
        PasswordEntry(site="x.com", username="u")  # type: ignore[call-arg]


def test_health_entry_roundtrip() -> None:
    e = HealthEntry(provider="Dr Smith", entry_type="doctor", value="blood_type_O+")
    d = e.to_dict()
    e2 = HealthEntry.from_dict(d)
    assert e == e2


def test_bank_entry_roundtrip() -> None:
    e = BankEntry(
        institution="Chase", account_type="checking", account_number="123456789"
    )
    d = e.to_dict()
    e2 = BankEntry.from_dict(d)
    assert e == e2


def test_bank_entry_defaults() -> None:
    e = BankEntry(institution="Chase", account_type="savings", account_number="999")
    assert e.routing_number == ""
    assert e.notes == ""


def test_note_entry_roundtrip() -> None:
    e = NoteEntry(
        title="My Note", body="Some secret text", tags=["personal", "important"]
    )
    d = e.to_dict()
    e2 = NoteEntry.from_dict(d)
    assert e == e2


def test_note_entry_default_tags() -> None:
    e = NoteEntry(title="t", body="b")
    assert e.tags == []


def test_to_dict_contains_all_fields() -> None:
    e = PasswordEntry(
        site="x", username="u", password="p", url="https://x.com", notes="hi"
    )
    d = e.to_dict()
    assert d == {
        "site": "x",
        "username": "u",
        "password": "p",
        "url": "https://x.com",
        "notes": "hi",
    }

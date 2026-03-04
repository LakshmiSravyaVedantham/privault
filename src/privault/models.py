"""Pydantic data models for all vault entry types."""

from typing import Any

from pydantic import BaseModel


class PasswordEntry(BaseModel):
    site: str
    username: str
    password: str
    url: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PasswordEntry":
        return cls(**d)


class HealthEntry(BaseModel):
    provider: str
    entry_type: str
    value: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HealthEntry":
        return cls(**d)


class BankEntry(BaseModel):
    institution: str
    account_type: str
    account_number: str
    routing_number: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BankEntry":
        return cls(**d)


class NoteEntry(BaseModel):
    title: str
    body: str
    tags: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NoteEntry":
        return cls(**d)

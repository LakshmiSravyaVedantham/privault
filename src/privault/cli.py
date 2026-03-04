"""privault CLI — all commands."""

import secrets as secrets_module
import shutil
import string
import uuid
from pathlib import Path
from typing import Optional

import typer

from privault.audit import AuditLog, AuditTampered
from privault.clipboard import copy_with_autoclean
from privault.models import BankEntry, HealthEntry, NoteEntry, PasswordEntry
from privault.vault import (
    VaultNotFoundError,
    VaultSession,
    WrongPasswordError,
    get_default_vault_path,
)

app = typer.Typer(
    name="privault",
    help="Local-only encrypted personal vault. Zero cloud, zero telemetry.",
    no_args_is_help=True,
)
add_app = typer.Typer(help="Add a new entry to the vault.")
app.add_typer(add_app, name="add")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vault_path_option() -> Path:
    return get_default_vault_path()


def _unlock(vault_path: Path) -> VaultSession:
    """Prompt for master password and unlock the vault."""
    try:
        password = typer.prompt("Master password", hide_input=True)
        return VaultSession.unlock(vault_path, password)
    except VaultNotFoundError:
        typer.echo(
            f"No vault found at {vault_path}. Run 'privault init' first.", err=True
        )
        raise typer.Exit(1)
    except WrongPasswordError:
        typer.echo("Wrong master password.", err=True)
        raise typer.Exit(1)


def _audit_log(session: VaultSession) -> AuditLog:
    log_path = session.vault_path.parent / "audit.log"
    return AuditLog(log_path, session.audit_key())


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@app.command()
def init(
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Create a new vault and set the master password."""
    vault_path = vault or _vault_path_option()
    password = typer.prompt(
        "Choose a master password",
        hide_input=True,
        confirmation_prompt=True,
    )
    try:
        session = VaultSession.init(vault_path, password)
        audit = _audit_log(session)
        audit.log("INIT")
        session.lock()
        typer.echo(f"Vault created at {vault_path}")
    except FileExistsError:
        typer.echo(
            f"Vault already exists at {vault_path}. Use 'privault get' to access it.",
            err=True,
        )
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# add password
# ---------------------------------------------------------------------------


@add_app.command("password")
def add_password(
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Add a password entry."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        site = typer.prompt("Site (e.g. github.com)")
        username = typer.prompt("Username")
        password = typer.prompt("Password", hide_input=True)
        url = typer.prompt("URL (optional, press Enter to skip)", default="")
        notes = typer.prompt("Notes (optional, press Enter to skip)", default="")

        entry = PasswordEntry(
            site=site, username=username, password=password, url=url, notes=notes
        )
        entry_id = str(uuid.uuid4())
        session.storage.write_entry(entry_id, "password", entry.to_dict())
        _audit_log(session).log("ADD", entry_id=entry_id, category="password")
        typer.echo(f"Password for '{site}' saved.")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# add health
# ---------------------------------------------------------------------------


@add_app.command("health")
def add_health(
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Add a health record."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        provider = typer.prompt("Provider (e.g. Dr Smith, BlueCross)")
        entry_type = typer.prompt(
            "Type (e.g. doctor, insurance, prescription, condition)"
        )
        value = typer.prompt("Value (the sensitive data)", hide_input=True)
        notes = typer.prompt("Notes (optional)", default="")

        entry = HealthEntry(
            provider=provider, entry_type=entry_type, value=value, notes=notes
        )
        entry_id = str(uuid.uuid4())
        session.storage.write_entry(entry_id, "health", entry.to_dict())
        _audit_log(session).log("ADD", entry_id=entry_id, category="health")
        typer.echo(f"Health record for '{provider}' saved.")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# add bank
# ---------------------------------------------------------------------------


@add_app.command("bank")
def add_bank(
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Add a banking record."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        institution = typer.prompt("Institution (e.g. Chase, Wells Fargo)")
        account_type = typer.prompt("Account type (e.g. checking, savings, credit)")
        account_number = typer.prompt("Account number", hide_input=True)
        routing_number = typer.prompt("Routing number (optional)", default="")
        notes = typer.prompt("Notes (optional)", default="")

        entry = BankEntry(
            institution=institution,
            account_type=account_type,
            account_number=account_number,
            routing_number=routing_number,
            notes=notes,
        )
        entry_id = str(uuid.uuid4())
        session.storage.write_entry(entry_id, "bank", entry.to_dict())
        _audit_log(session).log("ADD", entry_id=entry_id, category="bank")
        typer.echo(f"Banking record for '{institution}' saved.")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# add note
# ---------------------------------------------------------------------------


@add_app.command("note")
def add_note(
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Add a secure note."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        title = typer.prompt("Title")
        body = typer.prompt("Body (your note text)")
        tags_raw = typer.prompt("Tags (comma-separated, optional)", default="")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        entry = NoteEntry(title=title, body=body, tags=tags)
        entry_id = str(uuid.uuid4())
        session.storage.write_entry(entry_id, "note", entry.to_dict())
        _audit_log(session).log("ADD", entry_id=entry_id, category="note")
        typer.echo(f"Note '{title}' saved.")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


@app.command()
def get(
    name: str = typer.Argument(help="Site, title, provider, or institution to look up"),
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Retrieve an entry. Passwords are copied to clipboard (30s auto-clear)."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        results = session.storage.search_entries(name)
        if not results:
            typer.echo(f"No entries matching '{name}'.", err=True)
            raise typer.Exit(1)

        # If multiple matches, let user choose
        if len(results) > 1:
            typer.echo(f"Found {len(results)} matches:")
            for i, r in enumerate(results, 1):
                typer.echo(f"  {i}. [{r['category']}] {r['name']}")
            choice = typer.prompt("Choose number", type=int)
            if choice < 1 or choice > len(results):
                typer.echo("Invalid choice.", err=True)
                raise typer.Exit(1)
            entry_data = results[choice - 1]
        else:
            entry_data = results[0]

        _audit_log(session).log(
            "GET", entry_id=entry_data["id"], category=entry_data["category"]
        )

        data = entry_data["data"]
        category = entry_data["category"]

        if category == "password":
            typer.echo(f"Site:     {data.get('site', '')}")
            typer.echo(f"Username: {data.get('username', '')}")
            if data.get("url"):
                typer.echo(f"URL:      {data['url']}")
            if data.get("notes"):
                typer.echo(f"Notes:    {data['notes']}")
            copy_with_autoclean(data["password"])
        else:
            # Print all fields for non-password entries
            for k, v in data.items():
                if v:
                    typer.echo(f"{k.capitalize():15} {v}")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@app.command("list")
def list_entries(
    category: Optional[str] = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category: password, health, bank, note",
    ),
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """List entries in the vault. Secrets are never displayed."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        entries = session.storage.list_entries(category=category)
        if not entries:
            typer.echo("No entries found.")
            return
        typer.echo(f"{'ID':10}  {'Category':10}  {'Created':25}")
        typer.echo("-" * 50)
        for e in entries:
            short_id = e["id"][:8]
            typer.echo(f"{short_id:10}  {e['category']:10}  {e['created_at'][:19]}")
        _audit_log(session).log("LIST", category=category or "")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


@app.command()
def search(
    query: str = typer.Argument(help="Search term (case-insensitive)"),
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Search entries by name, site, tag, or provider."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        results = session.storage.search_entries(query)
        if not results:
            typer.echo(f"No results for '{query}'.")
            return
        typer.echo(f"{'ID':10}  {'Category':10}  {'Name'}")
        typer.echo("-" * 50)
        for r in results:
            typer.echo(f"{r['id'][:8]:10}  {r['category']:10}  {r['name']}")
        _audit_log(session).log("SEARCH")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


@app.command()
def generate(
    length: int = typer.Option(24, "--length", "-l", help="Password length"),
    no_symbols: bool = typer.Option(False, "--no-symbols", help="Alphanumeric only"),
) -> None:
    """Generate a cryptographically random password."""
    alphabet = string.ascii_letters + string.digits
    if not no_symbols:
        alphabet += string.punctuation
    password = "".join(secrets_module.choice(alphabet) for _ in range(length))
    typer.echo(f"Generated: {password}")
    copy_with_autoclean(password)


# ---------------------------------------------------------------------------
# lock
# ---------------------------------------------------------------------------


@app.command()
def lock() -> None:
    """Clear session state. Reminder: vault data is always encrypted at rest."""
    typer.echo("Session cleared. Vault data remains encrypted at rest.")
    typer.echo(
        "Tip: if you just pasted a secret, the clipboard auto-clears in 30 seconds."
    )


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@app.command("audit")
def audit_cmd(
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """View the local vault access log."""
    vault_path = vault or _vault_path_option()
    session = _unlock(vault_path)
    try:
        alog = _audit_log(session)
        try:
            entries = alog.read()
        except AuditTampered as e:
            typer.echo(f"WARNING: Audit log tampered! {e}", err=True)
            raise typer.Exit(2)

        if not entries:
            typer.echo("No audit log entries.")
            return
        typer.echo(f"{'Timestamp':22}  {'Action':10}  {'Category':10}  {'Entry ID'}")
        typer.echo("-" * 70)
        for entry in entries:
            ts = entry["timestamp"]
            act = entry["action"]
            cat = entry["category"]
            eid = entry["entry_id"][:12]
            typer.echo(f"{ts:22}  {act:10}  {cat:10}  {eid}")
    finally:
        session.lock()


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@app.command()
def export(
    out: Path = typer.Option(..., "--out", "-o", help="Destination path for backup"),
    vault: Optional[Path] = typer.Option(None, help="Path to vault file"),
) -> None:
    """Export an encrypted backup of the vault (the file is already encrypted)."""
    vault_path = vault or _vault_path_option()
    if not vault_path.exists():
        typer.echo(f"No vault found at {vault_path}.", err=True)
        raise typer.Exit(1)
    shutil.copy2(vault_path, out)
    typer.echo(f"Encrypted backup saved to {out}")
    typer.echo("Import with: privault init (then replace vault.db with this file)")

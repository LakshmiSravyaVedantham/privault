# privault — Design Document
**Date:** 2026-03-04
**Author:** Sravya Vedantham
**Status:** Approved

---

## Problem Statement

Personal data — passwords, health records, banking information — is scattered across systems
that are increasingly accessible to AI tools, browser extensions, and cloud services. Recent
incidents (Grok privacy leaks, OpenAI data retrieval, MCP-enabled AI snooping on employee
credentials) demonstrate that no external system can be trusted with sensitive personal data.

The solution: a local-only, fully encrypted personal vault where even a locally-running AI
with full filesystem access sees only ciphertext.

---

## What It Is

`privault` is a Python CLI tool that stores passwords, health records, banking info, and
secure notes in an AES-256-GCM encrypted SQLite database on your local machine. No cloud.
No sync. No telemetry. No accounts.

Install with `pip install privault`. Unlock with your master password. Done.

---

## Architecture

### Storage

```
~/.privault/
├── vault.db       # encrypted SQLite — pure ciphertext without master password
└── audit.log      # HMAC-signed local access log
```

`vault.db` uses AES-256-GCM encryption at the application layer. Each record is encrypted
individually. The vault header stores: salt (random, not secret), vault version, creation
timestamp — all plaintext. Everything else is ciphertext.

### Encryption Chain

```
Master Password (never stored)
    ↓
Argon2id KDF
  - memory: 64 MB
  - iterations: 3
  - parallelism: 4
  - salt: 32 random bytes (stored in vault header)
    ↓
32-byte session key (held in RAM only, zeroed on lock/exit)
    ↓
AES-256-GCM per entry
  - 12-byte random nonce per encryption
  - 16-byte authentication tag
  - Encrypted: all field values
  - Plaintext: entry ID, category, created_at
    ↓
Encrypted blob stored in SQLite
```

### Entry Types

| Category | Fields |
|---|---|
| Password | site, username, password, url, notes |
| Health | provider, type (doctor/insurance/rx), value, notes |
| Banking | institution, account_type, account_number, routing_number, notes |
| Note | title, body, tags |

### Key Components

```
src/privault/
├── cli.py          # Typer-based CLI — all user-facing commands
├── vault.py        # Session management: init, unlock, lock
├── crypto.py       # Argon2id + AES-256-GCM primitives
├── storage.py      # SQLite read/write with encryption layer
├── models.py       # Pydantic dataclasses for each entry type
├── clipboard.py    # pyperclip wrapper + 30s auto-clear thread
└── audit.py        # HMAC-signed append-only access log
```

### CLI Surface

```bash
privault init                     # Create new vault, set master password
privault unlock                   # Unlock vault (prompts for master password)
privault lock                     # Wipe session key from memory

privault add password             # Interactive: site, username, password, notes
privault add health               # Interactive: provider, type, value, notes
privault add bank                 # Interactive: institution, account details
privault add note                 # Interactive: title, body, tags

privault get <name>               # Find entry, copy secret to clipboard (30s)
privault list [--category <cat>]  # List all entries or by category
privault search <query>           # Search by name/site/tag
privault generate [--length N]    # Generate cryptographically random password

privault audit                    # View local access log
privault export --out backup.enc  # Export encrypted backup
```

---

## AI Resistance Model

| Threat | Mitigation |
|---|---|
| AI reads vault.db from filesystem | Pure ciphertext without master password |
| AI reads clipboard | 30-second auto-clear; after that, nothing to read |
| AI reads environment variables | No secrets ever stored in env vars |
| AI calls network to exfiltrate | Zero network calls; CI test verifies no connections |
| AI reads process memory | Session key zeroed on lock; short session lifetime |
| AI reads audit.log | Log is HMAC-signed; tampering is detectable |
| Brute force master password | Argon2id makes this computationally infeasible |

---

## Security Properties

- **Confidentiality:** AES-256-GCM with Argon2id-derived key
- **Integrity:** GCM authentication tag per entry; HMAC audit log
- **Availability:** Local-only; no external dependencies after install
- **Non-repudiation:** Audit log records every access with timestamp

---

## Non-Goals (v1)

- GUI or web interface
- Cloud backup or sync
- Multi-user support
- Hardware security key (YubiKey/FIDO2) — planned for v2
- Browser extension — planned for v2
- Mobile app — planned for v3

---

## Tech Stack

| Component | Library | Reason |
|---|---|---|
| CLI | typer | Sravya's style; clean help text |
| Encryption | cryptography (PyCA) | Industry standard; audited |
| KDF | argon2-cffi | Argon2id; OWASP recommended |
| Storage | sqlite3 (stdlib) | No extra deps; reliable |
| Clipboard | pyperclip | Cross-platform; simple |
| Models | pydantic | Type safety; validation |
| Testing | pytest | Consistent with all Sravya's projects |

---

## Open Source Plan

1. GitHub repo: `LakshmiSravyaVedantham/privault`
2. License: MIT
3. CI: GitHub Actions — lint, typecheck, test (Python 3.10/3.11/3.12)
4. CI also runs: network isolation check (no outbound calls during tests)
5. Publish to PyPI: `pip install privault`
6. Dev.to post: problem → design → demo
7. Twitter/X: share after Dev.to post is live

---

## Success Criteria

- `pip install privault` works on a fresh Python 3.10+ environment
- All vault data is ciphertext on disk — verified by test that reads raw SQLite
- Zero network calls — verified by test with socket patching
- 90%+ test coverage on `crypto.py`, `storage.py`, `vault.py`
- `mypy --strict` passes
- CI passes on Python 3.10, 3.11, 3.12

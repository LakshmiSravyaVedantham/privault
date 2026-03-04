# privault

[![CI](https://github.com/LakshmiSravyaVedantham/privault/actions/workflows/ci.yml/badge.svg)](https://github.com/LakshmiSravyaVedantham/privault/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Local-only encrypted personal vault. Zero cloud. Zero telemetry. AI-resistant.**

Your passwords, health records, and banking info — encrypted with AES-256-GCM and stored only on your machine. No accounts. No sync. Nothing leaves your device, ever.

## The Problem

Your personal data is scattered across systems that leak:

- Browser autofill → any extension can read it
- Notes app, Google Docs → cloud-synced, not encrypted
- AI tools (local or cloud) with MCP access → can read your filesystem
- "Smart" password managers → cloud-dependent, breach-prone

Even locally-installed AI (Claude Desktop, Copilot, etc.) can read clipboard contents, environment variables, and files if given broad access.

**privault keeps all sensitive data as ciphertext on disk. Even an AI with full filesystem access sees only random bytes.**

## Threat Model

| Threat | Mitigation |
|---|---|
| AI reads vault.db from filesystem | Pure AES-256-GCM ciphertext — useless without master password |
| AI intercepts clipboard | 30-second auto-clear after every paste |
| AI reads environment variables | No secrets ever stored in env vars |
| AI makes network calls to exfiltrate | Zero network code — CI verifies no socket connections |
| Brute force master password | Argon2id: even 1B guesses/sec = centuries per attempt |
| Tampered audit log | HMAC-SHA256 per line — tampering is detected |
| Someone steals vault.db file | Useless without master password; Argon2id makes cracking infeasible |

## Quickstart

```bash
pip install privault

# Create your vault
privault init

# Add a password
privault add password

# Look it up (copies to clipboard, clears in 30s)
privault get github.com

# Add a health record
privault add health

# Add banking info
privault add bank

# Add a secure note
privault add note
```

## Commands

```bash
privault init                     # Create new vault
privault add password             # Add a password entry
privault add health               # Add a health record
privault add bank                 # Add banking info
privault add note                 # Add a secure note
privault get <name>               # Retrieve entry (password → clipboard)
privault list [--category <cat>]  # List entries (no secrets shown)
privault search <query>           # Search by name/site/tag
privault generate [--length N]    # Generate a random password
privault audit                    # View tamper-evident access log
privault export --out backup.enc  # Export encrypted backup
privault lock                     # Clear session state reminder
```

## How It Works

### Encryption Chain

```
Your master password  (never stored anywhere)
    ↓
Argon2id
  - 64 MB memory cost
  - 3 iterations
  - 4 parallel threads
  → 32-byte session key (RAM only, zeroed on lock)
    ↓
AES-256-GCM per entry
  - 12-byte random nonce per encryption
  - 16-byte authentication tag
  → Encrypted blob stored in ~/.privault/vault.db
```

Every field of every entry is encrypted before hitting disk. SQLite stores only: entry ID, category, timestamps, and the encrypted blob. No plaintext secrets anywhere.

### Vault Location

```
~/.privault/
├── vault.db       # encrypted SQLite (chmod 600 — owner only)
└── audit.log      # HMAC-signed access log
```

### Why Argon2id?

Argon2id is the OWASP-recommended password hashing algorithm for 2024. With 64MB memory and 3 iterations, a dedicated GPU cluster attempting 1 billion guesses per second would take thousands of years to crack a 12-character password.

### Network Isolation

privault contains zero network code. The CI suite verifies this by patching `socket.socket` — any attempt to make a network connection causes an immediate test failure.

## Non-Goals (v1)

- GUI or web interface (v2)
- Browser extension (v2)
- Hardware security key / YubiKey (v2)
- Cloud backup / sync (never — by design)
- Multi-user support (v3)

## Development

```bash
git clone https://github.com/LakshmiSravyaVedantham/privault
cd privault
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT

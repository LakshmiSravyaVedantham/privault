# I Built a Privacy Vault That Even AI Can't Read

Last week I watched the news about Grok leaking user data. A few days before that, someone showed how an AI agent with MCP access could read employee passwords from a company's internal system.

I got frustrated. And I built something.

**privault** — a local-only encrypted personal vault for passwords, health records, and banking info. Zero cloud. Zero AI access. Zero telemetry. Not even a network request.

---

## The Problem

Your sensitive data is everywhere it shouldn't be:

- Passwords in Notes or Google Docs (cloud-synced, not encrypted)
- Health records in email threads
- Banking info in screenshots
- AI tools (local or cloud) that can read your clipboard, files, and environment variables via MCP

Even a locally installed AI like Claude Desktop can, with the right MCP server configuration, read your filesystem. If your passwords are in plaintext anywhere, they're accessible.

The scary part: most password managers are cloud-dependent. They're convenient until they're breached.

---

## What privault does

```bash
pip install privault

privault init              # create your vault
privault add password      # store a password
privault get github.com    # retrieve it (copies to clipboard, clears in 30s)
privault add health        # store health records
privault add bank          # store banking info
privault add note          # store secure notes
privault audit             # see who accessed what, when
```

Everything is encrypted **before it hits disk**. The vault file is pure ciphertext. Even if an AI reads `~/.privault/vault.db`, it gets random bytes.

---

## The Encryption Chain

```
Your master password  (never stored, never logged)
    ↓
Argon2id
  - 64 MB memory cost
  - 3 iterations
  - 4 parallel threads
  → 32-byte session key (RAM only, zeroed on lock)
    ↓
AES-256-GCM per entry
  - Random 12-byte nonce per encryption
  - 16-byte authentication tag
  → Encrypted blob in ~/.privault/vault.db
```

**Argon2id** is the OWASP-recommended password hashing algorithm. With these parameters, even a dedicated GPU cluster attempting 1 billion guesses per second would need thousands of years to crack a 12-character password.

**AES-256-GCM** is authenticated encryption — it detects tampering. If anyone modifies the vault file, decryption fails.

---

## The Threat Model

| Threat | Mitigation |
|---|---|
| AI reads vault.db from filesystem | Pure ciphertext — useless without master password |
| AI intercepts clipboard | 30-second auto-clear after every paste |
| AI reads environment variables | No secrets ever stored in env vars |
| AI makes network calls to exfiltrate | Zero network code — CI verifies this |
| Brute force master password | Argon2id: computationally infeasible |
| Tampered audit log | HMAC-SHA256 per line — tampering is detected |

That last one is important. Every vault access — init, add, get, list — is written to a local audit log where each line is signed with HMAC-SHA256. If someone (or something) modifies the log, `privault audit` will tell you.

---

## The AI Resistance Proof

Here's the thing I'm most proud of:

```python
# tests/test_network_isolation.py
def _network_forbidden(*args, **kwargs):
    raise RuntimeError("NETWORK ACCESS DETECTED — security violation")

@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", _network_forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", _network_forbidden)
```

Every test run patches the socket layer. If any code anywhere tries to open a network connection, the test fails immediately. This is enforced in CI on every push.

And the ciphertext test:

```python
def test_ciphertext_on_disk(tmp_vault_path, session_key):
    s = VaultStorage(tmp_vault_path, session_key)
    s.init_db()
    s.write_entry("e1", "password", {"password": "super-secret-password-12345"})
    s.close()

    # Read raw bytes — no decryption
    conn = sqlite3.connect(str(tmp_vault_path))
    row = conn.execute("SELECT encrypted_data FROM entries WHERE id = 'e1'").fetchone()
    raw_blob = bytes(row[0])

    assert b"super-secret-password-12345" not in raw_blob  # PASSES
```

The plaintext password is never in the file. That's the guarantee.

---

## What I Learned Building This

**1. Argon2id is non-negotiable for password-derived keys.** bcrypt and PBKDF2 are too fast on modern hardware. Argon2id's memory hardness makes GPU attacks expensive.

**2. Test your threat model, not just your code.** The network isolation test and ciphertext-on-disk test aren't testing functionality — they're testing the security promise. That distinction matters.

**3. The canary pattern for password verification.** On init, I write a known plaintext entry encrypted with the derived key. On unlock, I decrypt it. If decryption succeeds and the value matches — correct password. If not — wrong password. The master password itself is never stored or compared directly.

**4. Memory zeroing is hard in Python.** Using `bytearray` instead of `bytes` allows in-place zeroing of the session key. `bytes` is immutable and can't be wiped. Small detail, real security difference.

---

## Stack

- Python 3.10+
- `cryptography` (PyCA) — AES-256-GCM
- `argon2-cffi` — Argon2id KDF
- `typer` — CLI
- `pydantic` — data validation
- `pyperclip` — clipboard with auto-clear
- `pytest` — 72 tests, 93.6% coverage
- `mypy --strict` — full type checking

---

## Try It

```bash
pip install privault
privault init
privault add password
privault get <site>
```

GitHub: [LakshmiSravyaVedantham/privault](https://github.com/LakshmiSravyaVedantham/privault)

It's MIT licensed. Use it, fork it, improve it.

---

*Your health data should be yours. Your banking info should be yours. Your passwords should be yours. Nobody else — not a cloud service, not an AI — should have access without your explicit consent.*

*privault is one small step toward that.*

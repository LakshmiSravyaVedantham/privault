"""Cryptographic primitives for privault: Argon2id KDF + AES-256-GCM."""

import secrets

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_KEY_LEN = 32
_SALT_LEN = 32


def generate_salt() -> bytes:
    """Generate 32 cryptographically random bytes for use as a KDF salt."""
    return secrets.token_bytes(_SALT_LEN)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a password using Argon2id.

    Parameters match OWASP recommended minimums for interactive use:
    - memory_cost: 64 MB
    - time_cost: 3 iterations
    - parallelism: 4 threads
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Returns: nonce (12 bytes) + ciphertext + auth tag (16 bytes).
    Each call uses a fresh random nonce — same plaintext produces different output.
    """
    nonce = secrets.token_bytes(_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Raises:
        ValueError: if authentication fails (wrong key or tampered data).
    """
    if len(ciphertext) < _NONCE_LEN + 16:
        raise ValueError("Ciphertext too short to be valid")
    nonce = ciphertext[:_NONCE_LEN]
    data = ciphertext[_NONCE_LEN:]
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, data, None)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong key or tampered data") from exc

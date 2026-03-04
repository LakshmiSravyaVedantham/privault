"""Tests for privault.crypto module."""

import pytest

from privault.crypto import decrypt, derive_key, encrypt, generate_salt


def test_generate_salt_length() -> None:
    salt = generate_salt()
    assert len(salt) == 32


def test_generate_salt_is_random() -> None:
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert salt1 != salt2


def test_derive_key_length() -> None:
    salt = generate_salt()
    key = derive_key("password", salt)
    assert len(key) == 32


def test_derive_key_deterministic() -> None:
    salt = generate_salt()
    key1 = derive_key("password", salt)
    key2 = derive_key("password", salt)
    assert key1 == key2


def test_derive_key_different_passwords() -> None:
    salt = generate_salt()
    key1 = derive_key("password1", salt)
    key2 = derive_key("password2", salt)
    assert key1 != key2


def test_derive_key_different_salts() -> None:
    key1 = derive_key("password", generate_salt())
    key2 = derive_key("password", generate_salt())
    assert key1 != key2


def test_encrypt_decrypt_roundtrip() -> None:
    key = derive_key("test-pass", generate_salt())
    plaintext = b"hello, privault!"
    ciphertext = encrypt(key, plaintext)
    assert decrypt(key, ciphertext) == plaintext


def test_encrypt_produces_different_ciphertext_each_time() -> None:
    """Same plaintext must produce different ciphertext (random nonce per call)."""
    key = derive_key("test-pass", generate_salt())
    plaintext = b"same message"
    ct1 = encrypt(key, plaintext)
    ct2 = encrypt(key, plaintext)
    assert ct1 != ct2


def test_decrypt_wrong_key_raises() -> None:
    key1 = derive_key("correct", generate_salt())
    key2 = derive_key("wrong", generate_salt())
    ciphertext = encrypt(key1, b"secret data")
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt(key2, ciphertext)


def test_decrypt_tampered_data_raises() -> None:
    key = derive_key("test-pass", generate_salt())
    ciphertext = bytearray(encrypt(key, b"important data"))
    ciphertext[-1] ^= 0xFF  # flip last byte
    with pytest.raises(ValueError):
        decrypt(key, bytes(ciphertext))


def test_decrypt_too_short_raises() -> None:
    key = derive_key("test-pass", generate_salt())
    with pytest.raises(ValueError, match="too short"):
        decrypt(key, b"short")

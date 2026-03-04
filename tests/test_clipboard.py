"""Tests for privault.clipboard module."""

import time
from unittest.mock import MagicMock, patch

from privault.clipboard import copy_with_autoclean


def test_copy_calls_pyperclip(capsys) -> None:  # type: ignore[no-untyped-def]
    mock_pyperclip = MagicMock()
    mock_pyperclip.paste.return_value = "my-secret"
    with patch.dict("sys.modules", {"pyperclip": mock_pyperclip}):
        copy_with_autoclean("my-secret", timeout=60)
    mock_pyperclip.copy.assert_called_once_with("my-secret")


def test_stderr_message(capsys) -> None:  # type: ignore[no-untyped-def]
    mock_pyperclip = MagicMock()
    mock_pyperclip.paste.return_value = "s"
    with patch.dict("sys.modules", {"pyperclip": mock_pyperclip}):
        copy_with_autoclean("s", timeout=5)
    captured = capsys.readouterr()
    assert "Will clear in 5 seconds" in captured.err


def test_autoclean_clears_after_timeout(capsys) -> None:  # type: ignore[no-untyped-def]
    """After timeout, clipboard should be cleared if contents still match."""
    cleared = []
    paste_value = ["secret-data"]

    def mock_copy(val: str) -> None:
        if val == "":
            cleared.append(True)

    def mock_paste() -> str:
        return paste_value[0]

    mock_pyperclip = MagicMock()
    mock_pyperclip.copy.side_effect = mock_copy
    mock_pyperclip.paste.side_effect = mock_paste

    with patch.dict("sys.modules", {"pyperclip": mock_pyperclip}):
        copy_with_autoclean("secret-data", timeout=1)

    time.sleep(1.5)  # wait for daemon thread
    assert cleared, "Clipboard was not cleared after timeout"


def test_pyperclip_unavailable_falls_back(capsys) -> None:  # type: ignore[no-untyped-def]
    """If pyperclip raises, secret is printed to stdout as fallback."""
    import builtins

    original_import = builtins.__import__

    def mock_import(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "pyperclip":
            raise ImportError("No clipboard")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        copy_with_autoclean("fallback-secret", timeout=30)

    captured = capsys.readouterr()
    assert "fallback-secret" in captured.out or "Clipboard unavailable" in captured.err

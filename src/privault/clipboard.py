"""Secure clipboard copy with automatic timed clearing."""

import sys
import threading
import time


def copy_with_autoclean(secret: str, timeout: int = 30) -> None:
    """Copy a secret to clipboard and clear it after timeout seconds.

    The clear thread is a daemon — it won't block process exit.
    If the clipboard contents change before the timeout, nothing is cleared
    (we only clear if the value still matches what we put there).
    """
    try:
        import pyperclip

        pyperclip.copy(secret)
        print(
            f"Copied to clipboard. Will clear in {timeout} seconds.",
            file=sys.stderr,
        )

        def _clear() -> None:
            time.sleep(timeout)
            try:
                if pyperclip.paste() == secret:
                    pyperclip.copy("")
            except Exception:
                pass

        t = threading.Thread(target=_clear, daemon=True)
        t.start()

    except Exception as exc:
        print(f"Clipboard unavailable: {exc}", file=sys.stderr)
        print(f"Secret: {secret}")

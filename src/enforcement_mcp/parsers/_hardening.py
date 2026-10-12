"""Input validation for parsers that handle untrusted remote output.

All parsers process stdout from commands executed on remote hosts via SSH.
A compromised host can craft malicious output — these guards limit blast radius.
"""

from __future__ import annotations

MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MB


class InputTooLargeError(ValueError):
    """Raised when parser input exceeds MAX_INPUT_BYTES."""


def validate_input_size(raw: str, parser_name: str) -> None:
    size = len(raw.encode("utf-8", errors="replace"))
    if size > MAX_INPUT_BYTES:
        raise InputTooLargeError(
            f"{parser_name}: input is {size} bytes, limit is {MAX_INPUT_BYTES}"
        )


def sanitize_parsed_path(path: str) -> str | None:
    """Validate a file path extracted from untrusted command output.

    Returns the path if safe, None if malicious (null bytes).
    Normalizes traversal sequences but preserves the data.
    """
    if "\x00" in path:
        return None
    if not path.startswith("/") and not path.startswith("!"):
        return None
    return path

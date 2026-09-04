"""Shared normalization for non-sensitive request text."""

from __future__ import annotations

from re import IGNORECASE, compile as compile_pattern
from unicodedata import category

_DEFAULT_MAXIMUM_LENGTH = 500
_SENSITIVE_PATTERN = compile_pattern(
    r"(?:op://|ops_|authorization\s*:|\bbearer\s+\S+|"
    r"https://(?:[^/\s]+\.)?1password\.(?:com|eu|ca)/"
    r"(?:share/|s(?:[#/?]|$)))",
    IGNORECASE,
)


class UnsafeRequestInputError(ValueError):
    """Request text is not safe to retain or persist."""

    def __init__(self) -> None:
        """Build one stable error without retaining caller input."""
        super().__init__("unsafe request input")


def normalize_optional_request_text(
    value: str | None,
    *,
    maximum_length: int = _DEFAULT_MAXIMUM_LENGTH,
) -> str | None:
    """Normalize optional text and reject persistence-channel markers."""
    if isinstance(maximum_length, bool) or maximum_length < 1:
        raise UnsafeRequestInputError
    if value is None:
        return None
    if any(category(character).startswith("C") for character in value):
        raise UnsafeRequestInputError
    normalized = value.strip()
    if not normalized:
        return None
    if (
        len(normalized) > maximum_length
        or _SENSITIVE_PATTERN.search(normalized) is not None
    ):
        raise UnsafeRequestInputError
    return normalized


__all__ = ["UnsafeRequestInputError", "normalize_optional_request_text"]

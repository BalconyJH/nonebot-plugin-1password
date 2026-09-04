"""Structured logging limited to explicitly safe identifiers and categories."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")


@dataclass(frozen=True, slots=True)
class SafeFailureLog:
    """Allow-listed structured failure labels with untrusted values reduced."""

    error_category: str
    correlation_id: str
    resource_alias: str | None
    action_name: str | None
    result_code: str | None

    @classmethod
    def build(
        cls,
        *,
        error_category: str,
        correlation_id: str,
        resource_alias: str | None = None,
        action_name: str | None = None,
        result_code: str | None = None,
    ) -> SafeFailureLog:
        """Normalize every field into the closed safe-label grammar."""
        return cls(
            error_category=_safe_label(error_category),
            correlation_id=_safe_label(correlation_id),
            resource_alias=_optional_safe_label(resource_alias),
            action_name=_optional_safe_label(action_name),
            result_code=_optional_safe_label(result_code),
        )


def log_safe_failure(logger: logging.Logger, event: SafeFailureLog) -> None:
    """Emit one constant message with only a validated structured payload."""
    logger.error(
        "1Password workflow operation failed",
        extra={"nb1p": asdict(event)},
    )


def _safe_label(value: str) -> str:
    return value if _SAFE_LABEL.fullmatch(value) else "redacted"


def _optional_safe_label(value: str | None) -> str | None:
    return None if value is None else _safe_label(value)


__all__ = ["SafeFailureLog", "log_safe_failure"]

"""Security checks for structured log value reduction."""

from __future__ import annotations

import logging

from typing_extensions import override

from nonebot_plugin_1password.integrations.observability import (
    SafeFailureLog,
    log_safe_failure,
)


class _Handler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_structured_failure_log_rejects_untrusted_values() -> None:
    """Ensure raw untrusted labels never reach message or structured fields."""
    token = "op_service_account_secret value"
    logger = logging.getLogger("nb1p-test-redaction")
    logger.propagate = False
    logger.setLevel(logging.ERROR)
    handler = _Handler()
    logger.addHandler(handler)
    try:
        event = SafeFailureLog.build(
            error_category=token,
            correlation_id="correlation-1",
            resource_alias="grafana-prod",
            action_name="healthcheck",
            result_code="failed",
        )
        log_safe_failure(logger, event)
    finally:
        logger.removeHandler(handler)

    assert len(handler.records) == 1
    record = handler.records[0]
    assert token not in record.getMessage()
    assert token not in repr(record.__dict__)
    assert record.__dict__["nb1p"]["error_category"] == "redacted"

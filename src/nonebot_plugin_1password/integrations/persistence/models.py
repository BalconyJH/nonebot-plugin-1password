"""ORM rows for the unified request, evidence, and delivery schema."""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar, TypeAlias

from nonebot_plugin_orm import Model
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql.schema import SchemaItem

# NoneBot ORM resolves mapped annotations at class creation time.
DatabaseDateTime: TypeAlias = datetime
TableArguments: TypeAlias = tuple[SchemaItem, ...]


class AccessRequestRow(Model):
    """Persist one request and its immutable identity and policy evidence."""

    __tablename__ = "nb1p_access_request"
    __bind_key__: ClassVar[str] = "nonebot_plugin_1password"
    __table_args__: TableArguments = (
        UniqueConstraint("public_id", name="uq_nb1p_access_request_public_id"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'executing', 'succeeded', "
            "'failed', 'rejected', 'cancelled', 'expired')",
            name="access_request_status",
        ),
        CheckConstraint("version >= 0", name="access_request_version"),
        CheckConstraint(
            "is_private IN (0, 1)",
            name="access_request_private_boolean",
        ),
        CheckConstraint("expires_at > created_at", name="access_request_expiry"),
        CheckConstraint(
            "updated_at >= created_at",
            name="access_request_time_order",
        ),
        Index(
            "ix_nb1p_access_request_principal_created",
            "principal_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_nb1p_access_request_principal_status",
            "principal_id",
            "status",
            "created_at",
            "id",
        ),
        Index("ix_nb1p_access_request_expiry", "status", "expires_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    public_id: Mapped[str] = mapped_column(String(64), nullable=False)
    principal_id: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    self_id: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str] = mapped_column(Text, nullable=False)
    scene_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    scene_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_scene_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform_role: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, nullable=False)
    principal_groups: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    resource_alias: Mapped[str] = mapped_column(String(128), nullable=False)
    action_name: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    incident_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    policy_snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    grant_snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    evaluation_evidence: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
    )
    created_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    updated_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)


class ApprovalVoteRow(Model):
    """Persist one unique approver-principal decision per request."""

    __tablename__ = "nb1p_approval_vote"
    __bind_key__: ClassVar[str] = "nonebot_plugin_1password"
    __table_args__: TableArguments = (
        UniqueConstraint(
            "request_id",
            "approver_principal_id",
            name="uq_nb1p_approval_vote_request_principal",
        ),
        CheckConstraint(
            "decision IN ('approve', 'reject')",
            name="approval_vote_decision",
        ),
        Index("ix_nb1p_approval_vote_request_decision", "request_id", "decision"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[int] = mapped_column(
        ForeignKey("nb1p_access_request.id", ondelete="CASCADE"),
        nullable=False,
    )
    approver_principal_id: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class ExecutionAttemptRow(Model):
    """Persist one independently idempotent execution attempt."""

    __tablename__ = "nb1p_execution_attempt"
    __bind_key__: ClassVar[str] = "nonebot_plugin_1password"
    __table_args__: TableArguments = (
        UniqueConstraint("public_id", name="uq_nb1p_execution_attempt_public_id"),
        UniqueConstraint(
            "idempotency_key",
            name="uq_nb1p_execution_attempt_idempotency_key",
        ),
        UniqueConstraint(
            "request_id",
            "attempt_number",
            name="uq_nb1p_execution_attempt_request_number",
        ),
        CheckConstraint("attempt_number >= 1", name="execution_attempt_number"),
        CheckConstraint(
            "outcome IN ('running', 'succeeded', 'failed')",
            name="execution_attempt_outcome",
        ),
        CheckConstraint(
            "(outcome = 'running' AND finished_at IS NULL "
            "AND result_code IS NULL AND safe_summary IS NULL "
            "AND failure_code IS NULL) OR "
            "(outcome = 'succeeded' AND finished_at IS NOT NULL "
            "AND result_code IS NOT NULL AND safe_summary IS NOT NULL "
            "AND failure_code IS NULL) OR "
            "(outcome = 'failed' AND finished_at IS NOT NULL "
            "AND result_code IS NULL AND safe_summary IS NULL "
            "AND failure_code IS NOT NULL)",
            name="execution_attempt_result",
        ),
        Index("ix_nb1p_execution_attempt_request", "request_id", "attempt_number"),
        Index(
            "ix_nb1p_execution_attempt_recovery",
            "outcome",
            "started_at",
            "id",
        ),
        Index(
            "uq_nb1p_execution_attempt_running_request",
            "request_id",
            unique=True,
            sqlite_where=text("outcome = 'running'"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    public_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[int] = mapped_column(
        ForeignKey("nb1p_access_request.id", ondelete="CASCADE"),
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(String(160), nullable=False)
    approval_attestation: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    finished_at: Mapped[DatabaseDateTime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    result_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    safe_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuditEventRow(Model):
    """Persist typed request evidence, including denied pre-request evaluations."""

    __tablename__ = "nb1p_audit_event"
    __bind_key__: ClassVar[str] = "nonebot_plugin_1password"
    __table_args__: TableArguments = (
        UniqueConstraint("event_id", name="uq_nb1p_audit_event_event_id"),
        CheckConstraint(
            "event_type IN ('policy_evaluated', 'request_created', "
            "'approval_requested', 'request_status_changed', 'approval_recorded', "
            "'execution_attempt_started', 'execution_attempt_finished')",
            name="audit_event_type",
        ),
        CheckConstraint(
            "request_public_id IS NOT NULL OR event_type = 'policy_evaluated'",
            name="audit_event_request_scope",
        ),
        Index(
            "ix_nb1p_audit_event_request",
            "request_public_id",
            "occurred_at",
            "id",
        ),
        Index(
            "ix_nb1p_audit_event_correlation",
            "correlation_id",
            "occurred_at",
            "id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_public_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_principal_id: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class OutboxRow(Model):
    """Persist one idempotent notification and its current delivery lease."""

    __tablename__ = "nb1p_outbox"
    __bind_key__: ClassVar[str] = "nonebot_plugin_1password"
    __table_args__: TableArguments = (
        UniqueConstraint("event_id", name="uq_nb1p_outbox_event_id"),
        UniqueConstraint("lease_token", name="uq_nb1p_outbox_lease_token"),
        CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed')",
            name="outbox_status",
        ),
        CheckConstraint("attempt_count >= 0", name="outbox_attempt_count"),
        CheckConstraint("updated_at >= created_at", name="outbox_time_order"),
        CheckConstraint(
            "(status = 'processing' AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL) OR "
            "(status != 'processing' AND lease_token IS NULL "
            "AND lease_expires_at IS NULL)",
            name="outbox_processing_lease",
        ),
        Index("ix_nb1p_outbox_due", "status", "next_attempt_at"),
        Index("ix_nb1p_outbox_lease", "status", "lease_expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("nb1p_audit_event.event_id", ondelete="RESTRICT"),
        nullable=False,
    )
    target: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    message_text: Mapped[str] = mapped_column(Text, nullable=False)
    message_actions: Mapped[list[dict[str, object]]] = mapped_column(
        JSON,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_expires_at: Mapped[DatabaseDateTime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_attempt_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    created_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    updated_at: Mapped[DatabaseDateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


__all__ = [
    "AccessRequestRow",
    "ApprovalVoteRow",
    "AuditEventRow",
    "ExecutionAttemptRow",
    "OutboxRow",
]

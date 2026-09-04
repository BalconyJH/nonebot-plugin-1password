"""Create the unpublished unified request workflow schema.

Revision ID: nb1p_0001
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "nb1p_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = ("nonebot_plugin_1password",)
depends_on: str | Sequence[str] | None = None


def upgrade(name: str = "") -> None:
    """Create request, approval, execution, audit, and outbox tables."""
    del name
    op.create_table(
        "nb1p_access_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("public_id", sa.String(length=64), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("self_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("scene_id", sa.Text(), nullable=True),
        sa.Column("scene_type", sa.Text(), nullable=True),
        sa.Column("parent_scene_id", sa.Text(), nullable=True),
        sa.Column("platform_role", sa.Text(), nullable=True),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("principal_groups", sa.JSON(), nullable=False),
        sa.Column("resource_alias", sa.String(length=128), nullable=False),
        sa.Column("action_name", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("incident_id", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("grant_snapshot", sa.JSON(), nullable=False),
        sa.Column("evaluation_evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "expires_at > created_at",
            name=op.f("ck_nb1p_access_request_access_request_expiry"),
        ),
        sa.CheckConstraint(
            "is_private IN (0, 1)",
            name=op.f("ck_nb1p_access_request_access_request_private_boolean"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'executing', 'succeeded', "
            "'failed', 'rejected', 'cancelled', 'expired')",
            name=op.f("ck_nb1p_access_request_access_request_status"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f("ck_nb1p_access_request_access_request_time_order"),
        ),
        sa.CheckConstraint(
            "version >= 0",
            name=op.f("ck_nb1p_access_request_access_request_version"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nb1p_access_request")),
        sa.UniqueConstraint(
            "public_id",
            name=op.f("uq_nb1p_access_request_public_id"),
        ),
    )
    op.create_index(
        "ix_nb1p_access_request_principal_created",
        "nb1p_access_request",
        ["principal_id", "created_at", "id"],
    )
    op.create_index(
        "ix_nb1p_access_request_principal_status",
        "nb1p_access_request",
        ["principal_id", "status", "created_at", "id"],
    )
    op.create_index(
        "ix_nb1p_access_request_expiry",
        "nb1p_access_request",
        ["status", "expires_at", "id"],
    )

    op.create_table(
        "nb1p_approval_vote",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("request_id", sa.Integer(), nullable=False),
        sa.Column("approver_principal_id", sa.Text(), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('approve', 'reject')",
            name=op.f("ck_nb1p_approval_vote_approval_vote_decision"),
        ),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["nb1p_access_request.id"],
            name=op.f("fk_nb1p_approval_vote_request_id_nb1p_access_request"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nb1p_approval_vote")),
        sa.UniqueConstraint(
            "request_id",
            "approver_principal_id",
            name=op.f("uq_nb1p_approval_vote_request_principal"),
        ),
    )
    op.create_index(
        "ix_nb1p_approval_vote_request_decision",
        "nb1p_approval_vote",
        ["request_id", "decision"],
    )

    op.create_table(
        "nb1p_execution_attempt",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("public_id", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=160), nullable=False),
        sa.Column("approval_attestation", sa.JSON(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_code", sa.String(length=64), nullable=True),
        sa.Column("safe_summary", sa.Text(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "attempt_number >= 1",
            name=op.f("ck_nb1p_execution_attempt_execution_attempt_number"),
        ),
        sa.CheckConstraint(
            "outcome IN ('running', 'succeeded', 'failed')",
            name=op.f("ck_nb1p_execution_attempt_execution_attempt_outcome"),
        ),
        sa.CheckConstraint(
            "(outcome = 'running' AND finished_at IS NULL "
            "AND result_code IS NULL AND safe_summary IS NULL "
            "AND failure_code IS NULL) OR "
            "(outcome = 'succeeded' AND finished_at IS NOT NULL "
            "AND result_code IS NOT NULL AND safe_summary IS NOT NULL "
            "AND failure_code IS NULL) OR "
            "(outcome = 'failed' AND finished_at IS NOT NULL "
            "AND result_code IS NULL AND safe_summary IS NULL "
            "AND failure_code IS NOT NULL)",
            name=op.f("ck_nb1p_execution_attempt_execution_attempt_result"),
        ),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["nb1p_access_request.id"],
            name=op.f("fk_nb1p_execution_attempt_request_id_nb1p_access_request"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nb1p_execution_attempt")),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_nb1p_execution_attempt_idempotency_key"),
        ),
        sa.UniqueConstraint(
            "public_id",
            name=op.f("uq_nb1p_execution_attempt_public_id"),
        ),
        sa.UniqueConstraint(
            "request_id",
            "attempt_number",
            name=op.f("uq_nb1p_execution_attempt_request_number"),
        ),
    )
    op.create_index(
        "ix_nb1p_execution_attempt_recovery",
        "nb1p_execution_attempt",
        ["outcome", "started_at", "id"],
    )
    op.create_index(
        "ix_nb1p_execution_attempt_request",
        "nb1p_execution_attempt",
        ["request_id", "attempt_number"],
    )
    op.create_index(
        "uq_nb1p_execution_attempt_running_request",
        "nb1p_execution_attempt",
        ["request_id"],
        unique=True,
        sqlite_where=sa.text("outcome = 'running'"),
    )

    op.create_table(
        "nb1p_audit_event",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("request_public_id", sa.String(length=64), nullable=True),
        sa.Column("actor_principal_id", sa.Text(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('policy_evaluated', 'request_created', "
            "'approval_requested', 'request_status_changed', 'approval_recorded', "
            "'execution_attempt_started', 'execution_attempt_finished')",
            name=op.f("ck_nb1p_audit_event_audit_event_type"),
        ),
        sa.CheckConstraint(
            "request_public_id IS NOT NULL OR event_type = 'policy_evaluated'",
            name=op.f("ck_nb1p_audit_event_audit_event_request_scope"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nb1p_audit_event")),
        sa.UniqueConstraint(
            "event_id",
            name=op.f("uq_nb1p_audit_event_event_id"),
        ),
    )
    op.create_index(
        "ix_nb1p_audit_event_correlation",
        "nb1p_audit_event",
        ["correlation_id", "occurred_at", "id"],
    )
    op.create_index(
        "ix_nb1p_audit_event_request",
        "nb1p_audit_event",
        ["request_public_id", "occurred_at", "id"],
    )

    op.create_table(
        "nb1p_outbox",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("target", sa.JSON(), nullable=False),
        sa.Column("message_text", sa.Text(), nullable=False),
        sa.Column("message_actions", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name=op.f("ck_nb1p_outbox_outbox_attempt_count"),
        ),
        sa.CheckConstraint(
            "(status = 'processing' AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL) OR "
            "(status != 'processing' AND lease_token IS NULL "
            "AND lease_expires_at IS NULL)",
            name=op.f("ck_nb1p_outbox_outbox_processing_lease"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'delivered', 'failed')",
            name=op.f("ck_nb1p_outbox_outbox_status"),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f("ck_nb1p_outbox_outbox_time_order"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["nb1p_audit_event.event_id"],
            name=op.f("fk_nb1p_outbox_event_id_nb1p_audit_event"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nb1p_outbox")),
        sa.UniqueConstraint("event_id", name=op.f("uq_nb1p_outbox_event_id")),
        sa.UniqueConstraint(
            "lease_token",
            name=op.f("uq_nb1p_outbox_lease_token"),
        ),
    )
    op.create_index(
        "ix_nb1p_outbox_due",
        "nb1p_outbox",
        ["status", "next_attempt_at"],
    )
    op.create_index(
        "ix_nb1p_outbox_lease",
        "nb1p_outbox",
        ["status", "lease_expires_at"],
    )


def downgrade(name: str = "") -> None:
    """Drop every table created by this unpublished revision."""
    del name
    op.drop_index("ix_nb1p_outbox_lease", table_name="nb1p_outbox")
    op.drop_index("ix_nb1p_outbox_due", table_name="nb1p_outbox")
    op.drop_table("nb1p_outbox")
    op.drop_index("ix_nb1p_audit_event_request", table_name="nb1p_audit_event")
    op.drop_index("ix_nb1p_audit_event_correlation", table_name="nb1p_audit_event")
    op.drop_table("nb1p_audit_event")
    op.drop_index(
        "uq_nb1p_execution_attempt_running_request",
        table_name="nb1p_execution_attempt",
    )
    op.drop_index(
        "ix_nb1p_execution_attempt_request",
        table_name="nb1p_execution_attempt",
    )
    op.drop_index(
        "ix_nb1p_execution_attempt_recovery",
        table_name="nb1p_execution_attempt",
    )
    op.drop_table("nb1p_execution_attempt")
    op.drop_index(
        "ix_nb1p_approval_vote_request_decision",
        table_name="nb1p_approval_vote",
    )
    op.drop_table("nb1p_approval_vote")
    op.drop_index("ix_nb1p_access_request_expiry", table_name="nb1p_access_request")
    op.drop_index(
        "ix_nb1p_access_request_principal_status",
        table_name="nb1p_access_request",
    )
    op.drop_index(
        "ix_nb1p_access_request_principal_created",
        table_name="nb1p_access_request",
    )
    op.drop_table("nb1p_access_request")

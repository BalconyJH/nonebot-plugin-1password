"""Exercise the unpublished persistence revision against a real SQLite file."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Protocol, cast

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    UniqueConstraint,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from nonebot_plugin_1password.integrations.persistence.models import (
    AccessRequestRow,
    ApprovalVoteRow,
    AuditEventRow,
    ExecutionAttemptRow,
    OutboxRow,
)
from nonebot_plugin_1password.integrations.persistence.repositories import (
    SqlAlchemyUnitOfWorkFactory,
)
from nonebot_plugin_1password.integrations.persistence.sqlite import (
    install_sqlite_pragmas,
)

from .persistence_support import approval_requested_audit, policy_audit, request

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sqlalchemy.engine import Connection, Dialect

_BIND_NAME = "nonebot_plugin_1password"
_EXPECTED_TABLE_NAMES = frozenset(
    {
        "nb1p_access_request",
        "nb1p_approval_vote",
        "nb1p_audit_event",
        "nb1p_execution_attempt",
        "nb1p_outbox",
    }
)


class _MigrationRevision(Protocol):
    """The callable surface exposed by one Alembic revision module."""

    def upgrade(self, name: str = "") -> None:
        """Apply the revision for one named bind."""

    def downgrade(self, name: str = "") -> None:
        """Revert the revision for one named bind."""


_REVISION = cast(
    "_MigrationRevision",
    import_module(
        "nonebot_plugin_1password.integrations.persistence.migrations.0001_initial"
    ),
)


@dataclass(frozen=True, slots=True)
class _ColumnSignature:
    """Comparable column properties preserved by SQLite reflection."""

    name: str
    type_sql: str
    nullable: bool
    primary_key: bool


@dataclass(frozen=True, slots=True)
class _IndexSignature:
    """Comparable index properties, including a partial-index predicate."""

    name: str
    columns: tuple[str, ...]
    unique: bool
    sqlite_where: str | None


@dataclass(frozen=True, slots=True)
class _ForeignKeySignature:
    """Comparable foreign-key properties."""

    name: str
    columns: tuple[str, ...]
    targets: tuple[str, ...]
    ondelete: str | None


@dataclass(frozen=True, slots=True)
class _TableSignature:
    """Schema properties that must not drift from the ORM model metadata."""

    columns: tuple[_ColumnSignature, ...]
    primary_key: tuple[str, tuple[str, ...]]
    unique_constraints: frozenset[tuple[str, tuple[str, ...]]]
    check_constraints: frozenset[tuple[str, str]]
    foreign_keys: frozenset[_ForeignKeySignature]
    indexes: frozenset[_IndexSignature]


def _database_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


def _run_migration(
    connection: Connection,
    migration: Callable[[str], None],
) -> None:
    context = MigrationContext.configure(connection)
    with Operations.context(context):
        migration(_BIND_NAME)


async def _migrate(
    engine: AsyncEngine,
    migration: Callable[[str], None],
) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(_run_migration, migration)


def _reflect(connection: Connection) -> MetaData:
    metadata = MetaData()
    metadata.reflect(bind=connection)
    return metadata


def _normalize_sql(value: object) -> str:
    return " ".join(str(value).split())


def _constraint_name(constraint: object) -> str:
    name = getattr(constraint, "name", None)
    assert isinstance(name, str)
    return name


def _column_nullable(*, value: bool | None) -> bool:
    assert value is not None
    return value


def _table_signature(table: Table, dialect: Dialect) -> _TableSignature:
    columns = tuple(
        _ColumnSignature(
            name=column.name,
            type_sql=column.type.compile(dialect=dialect),
            nullable=_column_nullable(value=column.nullable),
            primary_key=column.primary_key,
        )
        for column in table.columns
    )
    primary_key_constraint = next(
        constraint
        for constraint in table.constraints
        if isinstance(constraint, PrimaryKeyConstraint)
    )
    primary_key = (
        _constraint_name(primary_key_constraint),
        tuple(column.name for column in primary_key_constraint.columns),
    )
    unique_constraints = frozenset(
        (
            _constraint_name(constraint),
            tuple(column.name for column in constraint.columns),
        )
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    check_constraints = frozenset(
        (
            _constraint_name(constraint),
            _normalize_sql(constraint.sqltext),
        )
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    )
    foreign_keys = frozenset(
        _ForeignKeySignature(
            name=_constraint_name(constraint),
            columns=tuple(column.name for column in constraint.columns),
            targets=tuple(element.target_fullname for element in constraint.elements),
            ondelete=constraint.ondelete,
        )
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint)
    )
    indexes = frozenset(
        _IndexSignature(
            name=_constraint_name(index),
            columns=tuple(column.name for column in index.columns),
            unique=index.unique,
            sqlite_where=(
                _normalize_sql(index.dialect_options["sqlite"]["where"])
                if index.dialect_options["sqlite"]["where"] is not None
                else None
            ),
        )
        for index in table.indexes
    )
    return _TableSignature(
        columns=columns,
        primary_key=primary_key,
        unique_constraints=unique_constraints,
        check_constraints=check_constraints,
        foreign_keys=foreign_keys,
        indexes=indexes,
    )


@pytest.mark.asyncio
async def test_revision_supports_named_bind_upgrade_and_downgrade(
    tmp_path: Path,
) -> None:
    """The revision creates and removes only its five owned tables."""
    engine = create_async_engine(_database_url(tmp_path / "revision.sqlite3"))
    try:
        await _migrate(engine, _REVISION.upgrade)
        async with engine.connect() as connection:
            reflected = await connection.run_sync(_reflect)

        assert frozenset(reflected.tables) == _EXPECTED_TABLE_NAMES
        assert "action_execution" not in reflected.tables
        assert "execution_status" not in reflected.tables
        assert "safe_payload" not in reflected.tables
        assert "safe_parameters" not in reflected.tables

        await _migrate(engine, _REVISION.downgrade)
        async with engine.connect() as connection:
            reflected_after_downgrade = await connection.run_sync(_reflect)

        assert reflected_after_downgrade.tables == {}
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_migrated_schema_matches_orm_model_metadata(tmp_path: Path) -> None:
    """Columns, constraints, and indexes cannot silently diverge from models."""
    engine = create_async_engine(_database_url(tmp_path / "metadata.sqlite3"))
    try:
        await _migrate(engine, _REVISION.upgrade)
        async with engine.connect() as connection:
            reflected = await connection.run_sync(_reflect)
            dialect = connection.dialect

        model_tables = {
            model.__table__.name: model.__table__
            for model in (
                AccessRequestRow,
                ApprovalVoteRow,
                AuditEventRow,
                ExecutionAttemptRow,
                OutboxRow,
            )
        }
        assert frozenset(model_tables) == _EXPECTED_TABLE_NAMES
        assert frozenset(reflected.tables) == _EXPECTED_TABLE_NAMES

        for table_name, model_table in model_tables.items():
            assert _table_signature(
                reflected.tables[table_name],
                dialect,
            ) == _table_signature(model_table, dialect)

        running_index = next(
            index
            for index in reflected.tables["nb1p_execution_attempt"].indexes
            if index.name == "uq_nb1p_execution_attempt_running_request"
        )
        assert running_index.unique
        assert (
            _normalize_sql(running_index.dialect_options["sqlite"]["where"])
            == "outcome = 'running'"
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_clean_migration_persists_current_policy_time_evidence(
    tmp_path: Path,
) -> None:
    """Round-trip the closed policy and evidence JSON after a clean upgrade."""
    engine = create_async_engine(_database_url(tmp_path / "clean-policy.sqlite3"))
    install_sqlite_pragmas(engine)
    try:
        await _migrate(engine, _REVISION.upgrade)
        factory = SqlAlchemyUnitOfWorkFactory(
            async_sessionmaker(
                engine,
                expire_on_commit=False,
                autoflush=False,
            )
        )
        expected = request()
        event = policy_audit()
        approval_event = approval_requested_audit()

        async with factory() as unit:
            await unit.requests.add(expected)
            await unit.audits.add(event)
            await unit.audits.add(approval_event)
            await unit.commit()
        async with factory() as unit:
            restored = await unit.requests.get(expected.id)
            events = await unit.audits.list_for_request(expected.id, limit=10)

        assert restored == expected
        assert restored is not None
        assert restored.policy.allowed_utc_weekdays == frozenset({6})
        assert restored.policy.allowed_utc_hours == frozenset({8})
        assert restored.evaluation_evidence.time_satisfied
        assert events == (event, approval_event)
    finally:
        await engine.dispose()

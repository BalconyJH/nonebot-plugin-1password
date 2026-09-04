"""SQLite-backed transactional persistence adapters."""

from .converters import PersistenceDataError
from .repositories import (
    AsyncSessionFactory,
    InvalidOutboxClaimError,
    InvalidRepositoryUpdateError,
    SqlAlchemyApprovalRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyExecutionAttemptRepository,
    SqlAlchemyOutboxRepository,
    SqlAlchemyRequestRepository,
    SqlAlchemyUnitOfWork,
    SqlAlchemyUnitOfWorkFactory,
    UnitOfWorkStateError,
    UnsupportedPersistenceDialectError,
    orm_unit_of_work_factory,
)
from .sqlite import (
    SQLiteConfigurationError,
    SQLiteRuntimeSettings,
    inspect_sqlite_runtime,
    install_sqlite_pragmas,
    remove_sqlite_pragmas,
)

__all__ = [
    "AsyncSessionFactory",
    "InvalidOutboxClaimError",
    "InvalidRepositoryUpdateError",
    "PersistenceDataError",
    "SQLiteConfigurationError",
    "SQLiteRuntimeSettings",
    "SqlAlchemyApprovalRepository",
    "SqlAlchemyAuditRepository",
    "SqlAlchemyExecutionAttemptRepository",
    "SqlAlchemyOutboxRepository",
    "SqlAlchemyRequestRepository",
    "SqlAlchemyUnitOfWork",
    "SqlAlchemyUnitOfWorkFactory",
    "UnitOfWorkStateError",
    "UnsupportedPersistenceDialectError",
    "inspect_sqlite_runtime",
    "install_sqlite_pragmas",
    "orm_unit_of_work_factory",
    "remove_sqlite_pragmas",
]

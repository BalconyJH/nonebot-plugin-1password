"""SQLite capability checks and connection-local safety settings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from sqlalchemy import event, text

from nonebot_plugin_1password.ports.repositories import PersistenceConfigurationError

from .models import AccessRequestRow

if TYPE_CHECKING:
    from sqlalchemy.engine.interfaces import DBAPIConnection
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
    from sqlalchemy.pool import ConnectionPoolEntry

_BUSY_TIMEOUT_MILLISECONDS = 5_000
_MINIMUM_SQLITE_VERSION = (3, 24, 0)
_SQLITE_VERSION_COMPONENTS = 3


class SQLiteConfigurationError(PersistenceConfigurationError):
    """The configured persistence bind lacks required SQLite guarantees."""

    _message = "invalid SQLite persistence configuration"


@dataclass(frozen=True, slots=True)
class SQLiteRuntimeSettings:
    """Observed settings for the actual AccessRequest model bind."""

    sqlite_version: str
    foreign_keys: bool
    journal_mode: str
    busy_timeout_milliseconds: int

    @property
    def supported(self) -> bool:
        """Return whether required version and safety settings are active."""
        return (
            _parse_version(self.sqlite_version) >= _MINIMUM_SQLITE_VERSION
            and self.foreign_keys
            and self.journal_mode in {"memory", "wal"}
            and self.busy_timeout_milliseconds == _BUSY_TIMEOUT_MILLISECONDS
        )


def _configure_sqlite_connection(
    dbapi_connection: DBAPIConnection,
    _: ConnectionPoolEntry,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA busy_timeout = 5000")
        cursor.execute("PRAGMA journal_mode = WAL")
    finally:
        cursor.close()


def install_sqlite_pragmas(engine: AsyncEngine) -> None:
    """Install safety settings before the engine opens its first connection."""
    if engine.dialect.name != "sqlite":
        raise SQLiteConfigurationError
    sync_engine = engine.sync_engine
    if not event.contains(sync_engine, "connect", _configure_sqlite_connection):
        event.listen(sync_engine, "connect", _configure_sqlite_connection)


def remove_sqlite_pragmas(engine: AsyncEngine) -> None:
    """Remove this module's listener without affecting other engines."""
    sync_engine = engine.sync_engine
    if event.contains(sync_engine, "connect", _configure_sqlite_connection):
        event.remove(sync_engine, "connect", _configure_sqlite_connection)


async def inspect_sqlite_runtime(
    session: AsyncSession,
) -> SQLiteRuntimeSettings:
    """Inspect the model's actual bind instead of the host default bind."""
    bind = session.get_bind(mapper=AccessRequestRow)
    if bind.dialect.name != "sqlite":
        raise SQLiteConfigurationError
    bind_arguments = {"mapper": AccessRequestRow}
    version = cast(
        "str",
        (
            await session.execute(
                text("SELECT sqlite_version()"),
                bind_arguments=bind_arguments,
            )
        ).scalar_one(),
    )
    foreign_keys = _strict_integer(
        (
            await session.execute(
                text("PRAGMA foreign_keys"),
                bind_arguments=bind_arguments,
            )
        ).scalar_one()
    )
    journal_mode = cast(
        "str",
        (
            await session.execute(
                text("PRAGMA journal_mode"),
                bind_arguments=bind_arguments,
            )
        ).scalar_one(),
    ).casefold()
    busy_timeout = _strict_integer(
        (
            await session.execute(
                text("PRAGMA busy_timeout"),
                bind_arguments=bind_arguments,
            )
        ).scalar_one()
    )
    settings = SQLiteRuntimeSettings(
        sqlite_version=version,
        foreign_keys=foreign_keys == 1,
        journal_mode=journal_mode,
        busy_timeout_milliseconds=busy_timeout,
    )
    if not settings.supported:
        raise SQLiteConfigurationError
    return settings


def _strict_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SQLiteConfigurationError
    return value


def _parse_version(value: str) -> tuple[int, int, int]:
    try:
        parts = tuple(int(part) for part in value.split(".", maxsplit=3)[:3])
    except ValueError as error:
        raise SQLiteConfigurationError from error
    if len(parts) != _SQLITE_VERSION_COMPONENTS or any(part < 0 for part in parts):
        raise SQLiteConfigurationError
    return parts


__all__ = [
    "SQLiteConfigurationError",
    "SQLiteRuntimeSettings",
    "inspect_sqlite_runtime",
    "install_sqlite_pragmas",
    "remove_sqlite_pragmas",
]

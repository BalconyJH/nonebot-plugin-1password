"""Verify SQLite safety settings on real pooled aiosqlite connections."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from nonebot_plugin_1password.integrations.persistence.models import AccessRequestRow
from nonebot_plugin_1password.integrations.persistence.sqlite import (
    SQLiteConfigurationError,
    inspect_sqlite_runtime,
    install_sqlite_pragmas,
    remove_sqlite_pragmas,
)

if TYPE_CHECKING:
    from pathlib import Path


def _database_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///{path.as_posix()}"


def _strict_int(value: object) -> int:
    assert isinstance(value, int)
    assert not isinstance(value, bool)
    return value


async def _read_pragmas(
    connection: AsyncConnection,
) -> tuple[int, str, int]:
    foreign_keys = _strict_int(
        (await connection.exec_driver_sql("PRAGMA foreign_keys")).scalar_one()
    )
    journal_mode = (
        await connection.exec_driver_sql("PRAGMA journal_mode")
    ).scalar_one()
    busy_timeout = _strict_int(
        (await connection.exec_driver_sql("PRAGMA busy_timeout")).scalar_one()
    )
    assert isinstance(journal_mode, str)
    return foreign_keys, journal_mode.casefold(), busy_timeout


async def _dispose_all(*engines: AsyncEngine) -> None:
    await asyncio.gather(*(engine.dispose() for engine in engines))


@pytest.mark.asyncio
async def test_pragmas_apply_to_two_real_pooled_connections(tmp_path: Path) -> None:
    """Each DBAPI connection receives foreign keys, WAL, and the timeout."""
    engine = create_async_engine(
        _database_url(tmp_path / "pooled.sqlite3"),
        pool_size=2,
        max_overflow=0,
    )
    install_sqlite_pragmas(engine)
    install_sqlite_pragmas(engine)
    try:
        async with engine.connect() as first, engine.connect() as second:
            observed = await asyncio.gather(
                _read_pragmas(first),
                _read_pragmas(second),
            )

        assert observed == [(1, "wal", 5_000), (1, "wal", 5_000)]
    finally:
        remove_sqlite_pragmas(engine)
        await engine.dispose()


@pytest.mark.asyncio
async def test_remove_pragmas_detaches_connection_listener(tmp_path: Path) -> None:
    """Removing the listener leaves replacement connections unconfigured."""
    engine = create_async_engine(_database_url(tmp_path / "removed.sqlite3"))
    install_sqlite_pragmas(engine)
    async with engine.connect() as configured_connection:
        assert (await _read_pragmas(configured_connection))[0] == 1

    remove_sqlite_pragmas(engine)
    await engine.dispose()
    try:
        async with engine.connect() as replacement_connection:
            assert (await _read_pragmas(replacement_connection))[0] == 0
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_inspection_uses_access_request_mapper_bind(tmp_path: Path) -> None:
    """Runtime inspection routes every query to the model-specific bind."""
    default_engine = create_async_engine(
        _database_url(tmp_path / "default-unconfigured.sqlite3")
    )
    model_engine = create_async_engine(
        _database_url(tmp_path / "model-configured.sqlite3")
    )
    install_sqlite_pragmas(model_engine)
    session_factory = async_sessionmaker(
        bind=default_engine,
        binds={AccessRequestRow: model_engine},
        expire_on_commit=False,
    )
    try:
        async with session_factory() as session:
            settings = await inspect_sqlite_runtime(session)

        assert settings.supported
        assert settings.foreign_keys
        assert settings.journal_mode == "wal"
        assert settings.busy_timeout_milliseconds == 5_000

        async with default_engine.connect() as default_connection:
            assert (await _read_pragmas(default_connection))[0] == 0
    finally:
        remove_sqlite_pragmas(model_engine)
        await _dispose_all(default_engine, model_engine)


@pytest.mark.asyncio
async def test_inspection_rejects_unconfigured_sqlite_bind(tmp_path: Path) -> None:
    """A SQLite bind without the listener fails closed during inspection."""
    engine = create_async_engine(_database_url(tmp_path / "unconfigured.sqlite3"))
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as session:
            with pytest.raises(
                SQLiteConfigurationError,
                match="invalid SQLite persistence configuration",
            ):
                await inspect_sqlite_runtime(session)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_non_sqlite_bind_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installation and inspection reject a bind with another dialect."""
    engine = create_async_engine(_database_url(tmp_path / "dialect.sqlite3"))
    monkeypatch.setattr(engine.dialect, "name", "postgresql")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        with pytest.raises(
            SQLiteConfigurationError,
            match="invalid SQLite persistence configuration",
        ):
            install_sqlite_pragmas(engine)

        async with session_factory() as session:
            with pytest.raises(
                SQLiteConfigurationError,
                match="invalid SQLite persistence configuration",
            ):
                await inspect_sqlite_runtime(session)
    finally:
        await engine.dispose()

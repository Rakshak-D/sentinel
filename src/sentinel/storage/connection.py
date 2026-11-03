"""Explicit, bounded SQLite connection management."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BUSY_TIMEOUT_MS = 5_000
MAX_BUSY_TIMEOUT_MS = 60_000
_MEMORY_DATABASE = ":memory:"


class DatabaseOpenError(RuntimeError):
    """Raised when the explicitly selected database cannot be opened safely."""


@dataclass(frozen=True, slots=True)
class ConnectionSettings:
    """Observed SQLite connection settings; these are not an ownership lease."""

    foreign_keys_enabled: bool
    journal_mode: str
    busy_timeout_ms: int


def _database_name(database: str | Path) -> tuple[str, bool]:
    if isinstance(database, Path):
        name = str(database)
    elif isinstance(database, str):
        name = database
    else:
        raise DatabaseOpenError("database selection must be a filesystem path or :memory:")
    if not name or "\x00" in name or name.startswith("file:"):
        raise DatabaseOpenError("database selection must be a non-empty filesystem path")
    return name, name == _MEMORY_DATABASE


def open_database(
    database: str | Path,
    *,
    create: bool = False,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> sqlite3.Connection:
    """Open one explicitly selected database; creation requires ``create=True``.

    File-backed databases use SQLite WAL and a 5-second default busy timeout.
    The timeout is bounded at 60 seconds. In-memory databases retain SQLite's
    in-memory journal mode. No database path is inferred by this API.
    """
    if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int):
        raise DatabaseOpenError("busy timeout must be an integer from 0 to 60000 ms")
    if not 0 <= busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS:
        raise DatabaseOpenError("busy timeout must be an integer from 0 to 60000 ms")

    name, is_memory = _database_name(database)
    if not is_memory:
        path = Path(name)
        if path.exists() and path.is_dir():
            raise DatabaseOpenError("selected database path is a directory")
        if not path.exists() and not create:
            raise DatabaseOpenError(
                "selected database does not exist; pass create=True to create it"
            )
        if not path.parent.exists() or not path.parent.is_dir():
            raise DatabaseOpenError("selected database parent directory does not exist")

    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            name,
            timeout=busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        if not is_memory:
            journal_mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0])
            if journal_mode.casefold() != "wal":
                raise DatabaseOpenError("SQLite could not enable WAL for the selected database")
        settings = inspect_connection(connection)
        if not settings.foreign_keys_enabled:
            raise DatabaseOpenError("SQLite foreign-key enforcement could not be enabled")
        return connection
    except DatabaseOpenError:
        if connection is not None:
            connection.close()
        raise
    except (OSError, sqlite3.Error) as exc:
        if connection is not None:
            connection.close()
        raise DatabaseOpenError(
            f"SQLite database could not be opened ({type(exc).__name__})"
        ) from exc


@contextmanager
def database_connection(
    database: str | Path,
    *,
    create: bool = False,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> Iterator[sqlite3.Connection]:
    """Yield a configured connection and always release its SQLite resource."""
    connection = open_database(
        database,
        create=create,
        busy_timeout_ms=busy_timeout_ms,
    )
    try:
        yield connection
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def inspect_connection(connection: sqlite3.Connection) -> ConnectionSettings:
    """Return settings read from the live connection rather than assumptions."""
    foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
    journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).casefold()
    busy_timeout_ms = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
    return ConnectionSettings(
        foreign_keys_enabled=foreign_keys,
        journal_mode=journal_mode,
        busy_timeout_ms=busy_timeout_ms,
    )


def open_database_readonly(
    database: str | Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> sqlite3.Connection:
    """Open an existing absolute database through SQLite URI ``mode=ro``.

    This API never creates the database or changes its journal mode. It enables
    per-connection foreign-key enforcement and ``query_only`` before returning.
    SQLite may still need to access WAL/SHM sidecars for a WAL database; callers
    must not infer that read-only mode guarantees zero filesystem side effects.
    """
    if isinstance(busy_timeout_ms, bool) or not isinstance(busy_timeout_ms, int):
        raise DatabaseOpenError("busy timeout must be an integer from 0 to 60000 ms")
    if not 0 <= busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS:
        raise DatabaseOpenError("busy timeout must be an integer from 0 to 60000 ms")
    if isinstance(database, Path):
        path = database
    elif type(database) is str:
        path = Path(database)
    else:
        raise DatabaseOpenError("database selection must be an absolute filesystem path")
    if not path.is_absolute() or "\x00" in str(path):
        raise DatabaseOpenError("database selection must be an absolute filesystem path")
    try:
        if path.is_symlink():
            raise DatabaseOpenError("selected database path must not be a symbolic link")
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise DatabaseOpenError("selected database path is not a regular file")
        uri = f"{resolved.as_uri()}?mode=ro"
    except DatabaseOpenError:
        raise
    except FileNotFoundError:
        raise DatabaseOpenError("selected database does not exist") from None
    except (OSError, RuntimeError, ValueError, TypeError):
        raise DatabaseOpenError("selected database path is unavailable") from None

    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        connection.execute("PRAGMA query_only = ON")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            raise DatabaseOpenError("SQLite query-only mode could not be enabled")
        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise DatabaseOpenError("SQLite foreign-key enforcement could not be enabled")
        return connection
    except DatabaseOpenError:
        if connection is not None:
            connection.close()
        raise
    except (OSError, sqlite3.Error):
        if connection is not None:
            connection.close()
        raise DatabaseOpenError("read-only SQLite database could not be opened") from None


@contextmanager
def readonly_database_connection(
    database: str | Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> Iterator[sqlite3.Connection]:
    """Yield a configured mode=ro SQLite connection and close it deterministically."""
    connection = open_database_readonly(database, busy_timeout_ms=busy_timeout_ms)
    try:
        yield connection
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()

"""Explicit, exclusive initialization of a new local Sentinel database."""

import os
import stat
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sentinel.storage.connection import database_connection
from sentinel.storage.migrations import (
    MIGRATIONS,
    initialize_storage,
    verify_integrity,
)


class InitializationErrorCode(StrEnum):
    """Bounded public categories for database initialization failures."""

    PATH_NOT_ABSOLUTE = "path_not_absolute"
    INVALID_PATH = "invalid_path"
    PARENT_MISSING = "parent_missing"
    ALREADY_EXISTS = "already_exists"
    PERMISSION_DENIED = "permission_denied"
    PATH_CHANGED = "path_changed"
    STORAGE_INITIALIZATION_FAILED = "storage_initialization_failed"


_ERROR_MESSAGES: dict[InitializationErrorCode, str] = {
    InitializationErrorCode.PATH_NOT_ABSOLUTE: "database path must be absolute",
    InitializationErrorCode.INVALID_PATH: "database path is invalid",
    InitializationErrorCode.PARENT_MISSING: "database parent directory is unavailable",
    InitializationErrorCode.ALREADY_EXISTS: "database path already exists",
    InitializationErrorCode.PERMISSION_DENIED: "permission denied while creating database",
    InitializationErrorCode.PATH_CHANGED: "database path changed during initialization",
    InitializationErrorCode.STORAGE_INITIALIZATION_FAILED: "database initialization failed",
}


class BootstrapInitError(RuntimeError):
    """A non-sensitive initialization error with a stable category."""

    def __init__(self, code: InitializationErrorCode) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class InitializationResult:
    """Evidence returned only after the registered schema passes integrity checks."""

    migration_ids: tuple[str, ...]


def _database_path(database: str | Path) -> Path:
    if isinstance(database, Path):
        path = database
    elif type(database) is str:
        path = Path(database)
    else:
        raise BootstrapInitError(InitializationErrorCode.INVALID_PATH)

    try:
        if "\x00" in os.fspath(path):
            raise BootstrapInitError(InitializationErrorCode.INVALID_PATH)
        if not path.is_absolute():
            raise BootstrapInitError(InitializationErrorCode.PATH_NOT_ABSOLUTE)
    except BootstrapInitError:
        raise
    except (OSError, TypeError, ValueError):
        raise BootstrapInitError(InitializationErrorCode.INVALID_PATH) from None

    try:
        parent_stat = os.stat(path.parent)
    except PermissionError:
        raise BootstrapInitError(InitializationErrorCode.PERMISSION_DENIED) from None
    except (FileNotFoundError, NotADirectoryError):
        raise BootstrapInitError(InitializationErrorCode.PARENT_MISSING) from None
    except (OSError, ValueError, TypeError):
        raise BootstrapInitError(InitializationErrorCode.INVALID_PATH) from None
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise BootstrapInitError(InitializationErrorCode.PARENT_MISSING)
    return path


def _reserve_new_file(path: Path) -> int:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags, 0o600)
    except (FileExistsError, IsADirectoryError):
        raise BootstrapInitError(InitializationErrorCode.ALREADY_EXISTS) from None
    except PermissionError:
        raise BootstrapInitError(InitializationErrorCode.PERMISSION_DENIED) from None
    except FileNotFoundError:
        raise BootstrapInitError(InitializationErrorCode.PARENT_MISSING) from None
    except (OSError, ValueError, TypeError):
        raise BootstrapInitError(InitializationErrorCode.INVALID_PATH) from None


def _verify_reserved_file(path: Path, descriptor: int) -> None:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
        descriptor_stat = os.fstat(descriptor)
    except OSError:
        raise BootstrapInitError(InitializationErrorCode.PATH_CHANGED) from None
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or path_stat.st_dev != descriptor_stat.st_dev
        or path_stat.st_ino != descriptor_stat.st_ino
    ):
        raise BootstrapInitError(InitializationErrorCode.PATH_CHANGED)


def _close_descriptor(descriptor: int, active_exception: BaseException | None) -> None:
    try:
        os.close(descriptor)
    except OSError:
        if active_exception is None:
            raise BootstrapInitError(
                InitializationErrorCode.STORAGE_INITIALIZATION_FAILED
            ) from None


def initialize_new_database(database: str | Path) -> InitializationResult:
    """Create and initialize exactly one new database at an explicit absolute path.

    The target is reserved with the operating system's exclusive-create flag before
    SQLite opens it. Existing files and final-component symlinks are refused. A
    newly reserved file is deliberately left in place if storage initialization
    fails, avoiding path-based cleanup that could affect a concurrently replaced
    file. The caller may inspect or remove that file after resolving the failure.
    """
    path = _database_path(database)
    descriptor = _reserve_new_file(path)
    try:
        _verify_reserved_file(path, descriptor)
        applied = initialize_storage(path, create=False)
        _verify_reserved_file(path, descriptor)
        expected_migrations = tuple(migration.migration_id for migration in MIGRATIONS)
        if applied != expected_migrations:
            raise BootstrapInitError(
                InitializationErrorCode.STORAGE_INITIALIZATION_FAILED
            )
        with database_connection(path, create=False) as connection:
            verify_integrity(connection)
        _verify_reserved_file(path, descriptor)
        return InitializationResult(migration_ids=applied)
    except BootstrapInitError:
        raise
    except PermissionError:
        error = BootstrapInitError(InitializationErrorCode.PERMISSION_DENIED)
        raise error from None
    except Exception:
        error = BootstrapInitError(
            InitializationErrorCode.STORAGE_INITIALIZATION_FAILED
        )
        raise error from None
    finally:
        _close_descriptor(descriptor, sys.exc_info()[1])

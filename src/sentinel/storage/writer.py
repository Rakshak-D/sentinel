"""Cooperative, process-wide SQLite writer ownership for Windows."""

from __future__ import annotations

import ctypes
import hashlib
import os
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Any, NoReturn

from sentinel.storage.connection import inspect_connection
from sentinel.storage.migrations import (
    MigrationIntegrityError,
    inspect_migration_history_readonly,
    verify_integrity,
    verify_schema_checkpoint_readonly,
)

WRITER_SQLITE_BUSY_TIMEOUT_MS = 500
WRITER_MUTEX_WAIT_MS = 0

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_ERROR_ALREADY_EXISTS = 183
_WAIT_OBJECT_0 = 0
_WAIT_ABANDONED = 0x80
_WAIT_TIMEOUT = 0x102
_DRIVE_REMOTE = 4

_PROCESS_LOCK = threading.Lock()
_PROCESS_MUTEX_NAMES: set[str] = set()
_LEASE_TOKEN = object()
_SCHEMA_ACTION_NAMES = (
    "SQLITE_CREATE_INDEX",
    "SQLITE_CREATE_TABLE",
    "SQLITE_CREATE_TEMP_INDEX",
    "SQLITE_CREATE_TEMP_TABLE",
    "SQLITE_CREATE_TEMP_TRIGGER",
    "SQLITE_CREATE_TEMP_VIEW",
    "SQLITE_CREATE_TRIGGER",
    "SQLITE_CREATE_VIEW",
    "SQLITE_DROP_INDEX",
    "SQLITE_DROP_TABLE",
    "SQLITE_DROP_TEMP_INDEX",
    "SQLITE_DROP_TEMP_TABLE",
    "SQLITE_DROP_TEMP_TRIGGER",
    "SQLITE_DROP_TEMP_VIEW",
    "SQLITE_DROP_TRIGGER",
    "SQLITE_DROP_VIEW",
    "SQLITE_ALTER_TABLE",
    "SQLITE_REINDEX",
    "SQLITE_ANALYZE",
    "SQLITE_CREATE_VTABLE",
    "SQLITE_DROP_VTABLE",
)
_SCHEMA_ACTIONS = {
    int(action)
    for action in (getattr(sqlite3, name, None) for name in _SCHEMA_ACTION_NAMES)
    if isinstance(action, int)
}
_DATA_WRITE_ACTIONS = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
_CONNECTION_PRAGMAS = frozenset(
    {"foreign_keys", "journal_mode", "busy_timeout", "user_version"}
)
_SQLITE_ACCESS_ERRORS = frozenset(
    {sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_PERM, sqlite3.SQLITE_READONLY}
)


class WriterLeaseErrorCode(StrEnum):
    """Stable, path-free writer error categories."""

    UNSUPPORTED_PLATFORM = "unsupported_platform"
    INVALID_PATH = "invalid_path"
    DATABASE_MISSING = "database_missing"
    DATABASE_UNAVAILABLE = "database_unavailable"
    DATABASE_INVALID = "database_invalid"
    MIGRATION_INVALID = "migration_invalid"
    LOCK_UNAVAILABLE = "lock_unavailable"
    LOCK_CONTENDED = "lock_contended"
    REENTRANT = "reentrant"
    LEASE_INACTIVE = "lease_inactive"
    THREAD_MISMATCH = "thread_mismatch"
    TRANSACTION_ACTIVE = "transaction_active"
    TRANSACTION_BUSY = "transaction_busy"
    TRANSACTION_FAILED = "transaction_failed"
    LEASE_RELEASE_FAILED = "lease_release_failed"


_ERROR_MESSAGES = {
    WriterLeaseErrorCode.UNSUPPORTED_PLATFORM: "Writer leases are supported only on Windows.",
    WriterLeaseErrorCode.INVALID_PATH: "Writer lease requires an absolute regular database path.",
    WriterLeaseErrorCode.DATABASE_MISSING: "The selected database does not exist.",
    WriterLeaseErrorCode.DATABASE_UNAVAILABLE: "The selected database is unavailable.",
    WriterLeaseErrorCode.DATABASE_INVALID: "The selected database failed integrity validation.",
    WriterLeaseErrorCode.MIGRATION_INVALID: "The selected database migration state is invalid.",
    WriterLeaseErrorCode.LOCK_UNAVAILABLE: "Windows writer ownership could not be established.",
    WriterLeaseErrorCode.LOCK_CONTENDED: "Another Sentinel writer session owns this database.",
    WriterLeaseErrorCode.REENTRANT: (
        "A writer lease for this database is already active in this process."
    ),
    WriterLeaseErrorCode.LEASE_INACTIVE: "The writer lease is no longer active.",
    WriterLeaseErrorCode.THREAD_MISMATCH: (
        "A Windows writer lease must stay on its acquiring thread."
    ),
    WriterLeaseErrorCode.TRANSACTION_ACTIVE: (
        "A writer transaction is already active on this lease."
    ),
    WriterLeaseErrorCode.TRANSACTION_BUSY: (
        "SQLite could not begin the writer transaction before timeout."
    ),
    WriterLeaseErrorCode.TRANSACTION_FAILED: "The writer transaction failed and was rolled back.",
    WriterLeaseErrorCode.LEASE_RELEASE_FAILED: (
        "Writer ownership cleanup did not complete normally."
    ),
}


class WriterLeaseError(RuntimeError):
    """A fixed-message error that never embeds a database path or SQLite detail."""

    def __init__(self, code: WriterLeaseErrorCode) -> None:
        if type(code) is not WriterLeaseErrorCode:
            raise TypeError("writer error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


def _raise(code: WriterLeaseErrorCode) -> NoReturn:
    raise WriterLeaseError(code) from None


def _is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    except (OSError, ValueError, TypeError):
        _raise(WriterLeaseErrorCode.DATABASE_UNAVAILABLE)
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_components(path: Path) -> None:
    current = path
    while True:
        if _is_reparse_point(current):
            _raise(WriterLeaseErrorCode.INVALID_PATH)
        parent = current.parent
        if parent == current:
            return
        current = parent


def _reject_remote_drive(path: Path) -> None:
    drive, _tail = os.path.splitdrive(str(path))
    if not drive or drive.startswith("\\\\"):
        _raise(WriterLeaseErrorCode.INVALID_PATH)
    try:
        kernel = _kernel32()
        kernel.GetDriveTypeW.argtypes = (ctypes.c_wchar_p,)
        kernel.GetDriveTypeW.restype = ctypes.c_uint32
        if int(kernel.GetDriveTypeW(f"{drive}\\")) == _DRIVE_REMOTE:
            _raise(WriterLeaseErrorCode.INVALID_PATH)
    except WriterLeaseError:
        raise
    except (AttributeError, OSError, ValueError, TypeError):
        _raise(WriterLeaseErrorCode.DATABASE_UNAVAILABLE)


def _canonical_database_and_mutex_name(database: str | Path) -> tuple[Path, str]:
    if os.name != "nt":
        _raise(WriterLeaseErrorCode.UNSUPPORTED_PLATFORM)
    if type(database) is str:
        raw_path = database
        if not raw_path or "\x00" in raw_path or raw_path.casefold().startswith("file:"):
            _raise(WriterLeaseErrorCode.INVALID_PATH)
        path = Path(raw_path)
    elif type(database) is type(Path()):
        path = database
        raw_path = str(path)
        if "\x00" in raw_path:
            _raise(WriterLeaseErrorCode.INVALID_PATH)
    else:
        _raise(WriterLeaseErrorCode.INVALID_PATH)

    if not path.is_absolute():
        _raise(WriterLeaseErrorCode.INVALID_PATH)
    # Reject network roots before stat/resolve can contact a UNC or mapped share.
    _reject_remote_drive(path)
    try:
        # Check the caller's path before resolving it so an explicit link is refused.
        _reject_reparse_components(path)
        canonical = path.resolve(strict=True)
        # Also reject reparse points in the resolved path's ancestry.
        _reject_reparse_components(canonical)
        info = canonical.stat()
    except FileNotFoundError:
        _raise(WriterLeaseErrorCode.DATABASE_MISSING)
    except WriterLeaseError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError):
        _raise(WriterLeaseErrorCode.DATABASE_UNAVAILABLE)

    if not stat.S_ISREG(info.st_mode):
        _raise(WriterLeaseErrorCode.INVALID_PATH)

    # Windows exposes volume/file-index values through st_dev/st_ino on common
    # local filesystems. This coalesces case/path aliases and hard links there.
    # A path-based fallback is used only when the filesystem reports no file ID.
    if info.st_ino:
        identity = f"file:{info.st_dev:x}:{info.st_ino:x}"
    else:
        identity = f"path:{os.path.normcase(str(canonical))}"
    digest = hashlib.sha256(identity.encode("utf-8", errors="strict")).hexdigest()
    return canonical, f"Global\\SentinelWriter-{digest}"


def _kernel32() -> Any:
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        _raise(WriterLeaseErrorCode.LOCK_UNAVAILABLE)
    kernel.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.ReleaseMutex.argtypes = (ctypes.c_void_p,)
    kernel.ReleaseMutex.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel.CloseHandle.restype = ctypes.c_int
    return kernel


def _close_handle(kernel: Any, handle: int) -> bool:
    return bool(kernel.CloseHandle(ctypes.c_void_p(handle)))


def _acquire_named_mutex(name: str) -> int:
    kernel = _kernel32()
    ctypes.set_last_error(0)
    raw_handle = kernel.CreateMutexW(None, 1, name)
    if not raw_handle:
        _raise(WriterLeaseErrorCode.LOCK_UNAVAILABLE)
    handle = int(raw_handle)
    last_error = ctypes.get_last_error()
    if last_error == _ERROR_ALREADY_EXISTS:
        wait_result = int(kernel.WaitForSingleObject(handle, WRITER_MUTEX_WAIT_MS))
        if wait_result in (_WAIT_OBJECT_0, _WAIT_ABANDONED):
            return handle
        _close_handle(kernel, handle)
        if wait_result == _WAIT_TIMEOUT:
            _raise(WriterLeaseErrorCode.LOCK_CONTENDED)
        _raise(WriterLeaseErrorCode.LOCK_UNAVAILABLE)
    return handle


def _release_named_mutex(handle: int) -> None:
    kernel = _kernel32()
    release_ok = bool(kernel.ReleaseMutex(handle))
    close_ok = _close_handle(kernel, handle)
    if not release_ok or not close_ok:
        _raise(WriterLeaseErrorCode.LEASE_RELEASE_FAILED)


def _set_internal_transaction_control(state: dict[str, bool], enabled: bool) -> None:
    state["internal"] = enabled


def _transaction_authorizer(
    state: dict[str, bool],
) -> Callable[[int, str | None, str | None, str | None, str | None], int]:
    transaction_actions = {sqlite3.SQLITE_TRANSACTION}
    savepoint_action = getattr(sqlite3, "SQLITE_SAVEPOINT", None)
    if isinstance(savepoint_action, int):
        transaction_actions.add(savepoint_action)

    def authorize(
        action: int,
        _argument_one: str | None,
        _argument_two: str | None,
        _database: str | None,
        _trigger: str | None,
    ) -> int:
        if action in transaction_actions and not state["internal"]:
            return sqlite3.SQLITE_DENY
        if action in _SCHEMA_ACTIONS or action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
            return sqlite3.SQLITE_DENY
        if action in _DATA_WRITE_ACTIONS and not state["write_allowed"]:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA:
            pragma = (_argument_one or "").casefold()
            if pragma not in _CONNECTION_PRAGMAS:
                return sqlite3.SQLITE_DENY
            if _argument_two is None:
                return sqlite3.SQLITE_OK
            if pragma == "user_version" and state["write_allowed"]:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    return authorize


def _execute_transaction_control(
    connection: sqlite3.Connection,
    state: dict[str, bool],
    statement: str,
) -> None:
    _set_internal_transaction_control(state, True)
    try:
        connection.execute(statement)
    finally:
        _set_internal_transaction_control(state, False)


def _rollback(connection: sqlite3.Connection, state: dict[str, bool]) -> bool:
    try:
        if not connection.in_transaction:
            return True
        _execute_transaction_control(connection, state, "ROLLBACK")
    except sqlite3.Error:
        return False
    return not connection.in_transaction


def _in_transaction(connection: sqlite3.Connection) -> bool:
    try:
        return connection.in_transaction
    except sqlite3.Error:
        return False


def _close_connection(connection: sqlite3.Connection) -> bool:
    try:
        connection.close()
    except sqlite3.Error:
        return False
    return True


def _sqlite_access_failure(error: sqlite3.Error) -> bool:
    code = getattr(error, "sqlite_errorcode", None)
    return isinstance(code, int) and code & 0xFF in _SQLITE_ACCESS_ERRORS


def _open_and_validate_database(path: Path) -> tuple[sqlite3.Connection, dict[str, bool]]:
    connection: sqlite3.Connection | None = None
    try:
        # mode=rw is essential: sqlite3.connect(path) would create a file if it
        # disappeared after a separate existence check.
        uri = f"{path.as_uri()}?mode=rw"
        connection = sqlite3.connect(
            uri,
            uri=True,
            timeout=WRITER_SQLITE_BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {WRITER_SQLITE_BUSY_TIMEOUT_MS}")
        settings = inspect_connection(connection)
        if not settings.foreign_keys_enabled or settings.journal_mode != "wal":
            _raise(WriterLeaseErrorCode.DATABASE_INVALID)

        # Existing migrations and schema are checked by the trusted registry on
        # a query-only connection state, without calling initialize_storage().
        connection.execute("PRAGMA query_only = ON")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            _raise(WriterLeaseErrorCode.DATABASE_INVALID)
        try:
            migration_ids = inspect_migration_history_readonly(connection)
            verify_schema_checkpoint_readonly(connection, migration_ids)
        except (MigrationIntegrityError, sqlite3.Error) as exc:
            if isinstance(exc, sqlite3.Error) and _sqlite_access_failure(exc):
                _raise(WriterLeaseErrorCode.DATABASE_UNAVAILABLE)
            _raise(WriterLeaseErrorCode.MIGRATION_INVALID)
        try:
            verify_integrity(connection)
        except (MigrationIntegrityError, sqlite3.Error) as exc:
            if isinstance(exc, sqlite3.Error) and _sqlite_access_failure(exc):
                _raise(WriterLeaseErrorCode.DATABASE_UNAVAILABLE)
            _raise(WriterLeaseErrorCode.DATABASE_INVALID)
        connection.execute("PRAGMA query_only = OFF")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 0:
            _raise(WriterLeaseErrorCode.DATABASE_INVALID)
        final_settings = inspect_connection(connection)
        if not final_settings.foreign_keys_enabled or final_settings.journal_mode != "wal":
            _raise(WriterLeaseErrorCode.DATABASE_INVALID)
        control_state = {"internal": False, "write_allowed": False}
        connection.set_authorizer(_transaction_authorizer(control_state))
        return connection, control_state
    except WriterLeaseError:
        if connection is not None:
            _close_connection(connection)
        raise
    except sqlite3.Error as exc:
        if connection is not None:
            _close_connection(connection)
        category = (
            WriterLeaseErrorCode.DATABASE_UNAVAILABLE
            if _sqlite_access_failure(exc)
            else WriterLeaseErrorCode.DATABASE_INVALID
        )
        _raise(category)


class WriterLease:
    """An active, thread-bound lease; all writes must use ``transaction()``."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        control_state: dict[str, bool],
        mutex_name: str,
        mutex_handle: int,
        token: object,
    ) -> None:
        if token is not _LEASE_TOKEN:
            raise TypeError("WriterLease instances require an acquired OS lease")
        self._connection = connection
        self._control_state = control_state
        self._mutex_name = mutex_name
        self._mutex_handle = mutex_handle
        self._owner_thread = threading.get_ident()
        self._state_lock = threading.Lock()
        self._active = True
        self._poisoned = False
        self._transaction_active = False

    def _check_thread(self) -> None:
        if threading.get_ident() != self._owner_thread:
            _raise(WriterLeaseErrorCode.THREAD_MISMATCH)

    def _claim_transaction(self) -> None:
        self._check_thread()
        with self._state_lock:
            if not self._active or self._poisoned:
                _raise(WriterLeaseErrorCode.LEASE_INACTIVE)
            if self._transaction_active:
                _raise(WriterLeaseErrorCode.TRANSACTION_ACTIVE)
            self._transaction_active = True

    def _finish_transaction(self) -> None:
        with self._state_lock:
            self._transaction_active = False

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run one explicit BEGIN IMMEDIATE transaction with commit/rollback."""
        self._claim_transaction()
        connection = self._connection
        begun = False
        try:
            try:
                _execute_transaction_control(connection, self._control_state, "BEGIN IMMEDIATE")
                begun = True
                self._control_state["write_allowed"] = True
            except sqlite3.Error as exc:
                if self._is_sqlite_busy(exc):
                    _raise(WriterLeaseErrorCode.TRANSACTION_BUSY)
                _raise(WriterLeaseErrorCode.TRANSACTION_FAILED)

            try:
                yield connection
            except sqlite3.Error:
                self._poisoned = True
                if not _rollback(connection, self._control_state):
                    _raise(WriterLeaseErrorCode.TRANSACTION_FAILED)
                _raise(WriterLeaseErrorCode.TRANSACTION_FAILED)
            except BaseException:
                self._poisoned = True
                if not _rollback(connection, self._control_state):
                    _raise(WriterLeaseErrorCode.TRANSACTION_FAILED)
                raise
            else:
                try:
                    self._control_state["write_allowed"] = False
                    if not _in_transaction(connection):
                        self._poisoned = True
                        _raise(WriterLeaseErrorCode.TRANSACTION_FAILED)
                    _execute_transaction_control(connection, self._control_state, "COMMIT")
                except sqlite3.Error as exc:
                    self._poisoned = True
                    _rollback(connection, self._control_state)
                    if self._is_sqlite_busy(exc):
                        _raise(WriterLeaseErrorCode.TRANSACTION_BUSY)
                    _raise(WriterLeaseErrorCode.TRANSACTION_FAILED)
        finally:
            self._control_state["write_allowed"] = False
            if begun and _in_transaction(connection):
                self._poisoned = True
                _rollback(connection, self._control_state)
            self._finish_transaction()

    @staticmethod
    def _is_sqlite_busy(error: sqlite3.Error) -> bool:
        code = getattr(error, "sqlite_errorcode", None)
        return isinstance(code, int) and code & 0xFF in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)

    def _release(self) -> None:
        self._check_thread()
        with self._state_lock:
            if not self._active:
                return
            self._active = False

        cleanup_failed = False
        try:
            if not _rollback(self._connection, self._control_state):
                cleanup_failed = True
            if not _close_connection(self._connection):
                cleanup_failed = True
        except sqlite3.Error:
            cleanup_failed = True
        try:
            _release_named_mutex(self._mutex_handle)
        except WriterLeaseError:
            cleanup_failed = True
        finally:
            with _PROCESS_LOCK:
                _PROCESS_MUTEX_NAMES.discard(self._mutex_name)
        if cleanup_failed:
            _raise(WriterLeaseErrorCode.LEASE_RELEASE_FAILED)


@contextmanager
def acquire_writer_lease(database: str | Path) -> Iterator[WriterLease]:
    """Acquire exclusive cooperating-process ownership of an existing Sentinel DB.

    The OS mutex wait is fail-fast. The database must be an absolute existing
    regular file with registered migration history, valid schema, integrity,
    foreign keys, and WAL. No database is created and no migration is applied.
    """
    canonical_path, mutex_name = _canonical_database_and_mutex_name(database)
    with _PROCESS_LOCK:
        if mutex_name in _PROCESS_MUTEX_NAMES:
            _raise(WriterLeaseErrorCode.REENTRANT)
        _PROCESS_MUTEX_NAMES.add(mutex_name)

    mutex_handle: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        mutex_handle = _acquire_named_mutex(mutex_name)
        connection, control_state = _open_and_validate_database(canonical_path)
        lease = WriterLease(
            connection,
            control_state,
            mutex_name,
            mutex_handle,
            _LEASE_TOKEN,
        )
    except BaseException:
        if connection is not None:
            _close_connection(connection)
        if mutex_handle is not None:
            try:
                _release_named_mutex(mutex_handle)
            except WriterLeaseError:
                pass
        with _PROCESS_LOCK:
            _PROCESS_MUTEX_NAMES.discard(mutex_name)
        raise

    try:
        yield lease
    finally:
        lease._release()


__all__ = [
    "WRITER_MUTEX_WAIT_MS",
    "WRITER_SQLITE_BUSY_TIMEOUT_MS",
    "WriterLease",
    "WriterLeaseError",
    "WriterLeaseErrorCode",
    "acquire_writer_lease",
]

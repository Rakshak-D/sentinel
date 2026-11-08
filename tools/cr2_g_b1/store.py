"""Separate disposable SQLite canary state for the CR2-G-B1 prototype.

This store is not a Sentinel workspace, credential store, or security boundary.
The Windows broker must be hosted under a separately protected identity before
any storage-isolation claim is made.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import TypeAlias

_APPLICATION_ID = 0x53474231  # ASCII "SGB1"
_USER_VERSION = 1
_SCHEMA_ID = "sentinel.cr2-g-b1-canary.v1"
_CANARY_ID = "synthetic-canary-0001"
_CLASSIFICATION = "SYNTHETIC_ONLY"
_STATE = "PRESENT"
_TABLE_SQL = {
    "lab_metadata": (
        "CREATE TABLE lab_metadata ("
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "schema_id TEXT NOT NULL CHECK (schema_id = 'sentinel.cr2-g-b1-canary.v1')"
        ") STRICT"
    ),
    "canary_record": (
        "CREATE TABLE canary_record ("
        "canary_id TEXT PRIMARY KEY CHECK (canary_id = 'synthetic-canary-0001'), "
        "classification TEXT NOT NULL CHECK (classification = 'SYNTHETIC_ONLY'), "
        "state TEXT NOT NULL CHECK (state = 'PRESENT')"
        ") STRICT"
    ),
}

PathArgument: TypeAlias = str | os.PathLike[str]


class CanaryStoreError(RuntimeError):
    """A bounded store error whose message contains no path or SQLite data."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _validated_path(value: PathArgument, *, must_exist: bool) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or path.is_symlink():
            raise CanaryStoreError("INVALID_STORE_PATH")
        resolved = path.resolve(strict=must_exist)
        if must_exist and not resolved.is_file():
            raise CanaryStoreError("STORE_UNAVAILABLE")
        return resolved
    except CanaryStoreError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise CanaryStoreError("STORE_UNAVAILABLE") from exc


def _connect_read_only(path: Path) -> sqlite3.Connection:
    try:
        uri = f"{path.as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise CanaryStoreError("STORE_UNAVAILABLE") from exc


class CanaryStore:
    """Read-only access to an explicitly initialized synthetic canary store."""

    __slots__ = ("__path",)

    def __init__(self, path: Path) -> None:
        self.__path = path

    @classmethod
    def initialize(cls, path: PathArgument) -> CanaryStore:
        """Create a new lab DB; never adopt or overwrite an existing file."""
        target = _validated_path(path, must_exist=False)
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            descriptor = os.open(target, flags, 0o600)
            os.close(descriptor)
        except FileExistsError as exc:
            raise CanaryStoreError("STORE_ALREADY_EXISTS") from exc
        except (OSError, ValueError) as exc:
            raise CanaryStoreError("STORE_INITIALIZATION_FAILED") from exc

        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(target, timeout=1, isolation_level=None)
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {_USER_VERSION}")
            for create_sql in _TABLE_SQL.values():
                connection.execute(create_sql)
            connection.execute(
                "INSERT INTO lab_metadata(singleton, schema_id) VALUES (?, ?)",
                (1, _SCHEMA_ID),
            )
            connection.execute(
                "INSERT INTO canary_record(canary_id, classification, state) "
                "VALUES (?, ?, ?)",
                (_CANARY_ID, _CLASSIFICATION, _STATE),
            )
            connection.commit()
        except (OSError, sqlite3.Error, ValueError) as exc:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise CanaryStoreError("STORE_INITIALIZATION_FAILED") from exc
        finally:
            if connection is not None:
                connection.close()

        store = cls(target)
        store._validate()
        return store

    @classmethod
    def open_existing(cls, path: PathArgument) -> CanaryStore:
        target = _validated_path(path, must_exist=True)
        store = cls(target)
        store._validate()
        return store

    def _validate(self) -> None:
        connection = _connect_read_only(self.__path)
        try:
            if connection.execute("PRAGMA application_id").fetchone() != (_APPLICATION_ID,):
                raise CanaryStoreError("STORE_IDENTITY_INVALID")
            if connection.execute("PRAGMA user_version").fetchone() != (_USER_VERSION,):
                raise CanaryStoreError("STORE_SCHEMA_INVALID")
            check = connection.execute("PRAGMA integrity_check").fetchone()
            if check != ("ok",):
                raise CanaryStoreError("STORE_INTEGRITY_FAILED")
            objects = connection.execute(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            if dict(objects) != _TABLE_SQL:
                raise CanaryStoreError("STORE_SCHEMA_INVALID")
            other_objects = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type IN ('view', 'trigger') AND name NOT LIKE 'sqlite_%'"
            ).fetchone()
            if other_objects != (0,):
                raise CanaryStoreError("STORE_SCHEMA_INVALID")
            metadata = connection.execute(
                "SELECT singleton, schema_id FROM lab_metadata"
            ).fetchall()
            records = connection.execute(
                "SELECT canary_id, classification, state FROM canary_record"
            ).fetchall()
            if metadata != [(1, _SCHEMA_ID)] or records != [
                (_CANARY_ID, _CLASSIFICATION, _STATE)
            ]:
                raise CanaryStoreError("CANARY_STATE_INVALID")
        except CanaryStoreError:
            raise
        except sqlite3.Error as exc:
            raise CanaryStoreError("STORE_INTEGRITY_FAILED") from exc
        finally:
            connection.close()

    def status(self) -> dict[str, str]:
        """Return only fixed canary metadata after full read-only validation."""
        self._validate()
        return {
            "canary_id": _CANARY_ID,
            "classification": _CLASSIFICATION,
            "state": _STATE,
        }


__all__ = ["CanaryStore", "CanaryStoreError"]

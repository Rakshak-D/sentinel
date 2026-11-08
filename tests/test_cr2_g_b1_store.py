from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tools.cr2_g_b1.store import CanaryStore, CanaryStoreError


def test_store_is_separate_synthetic_schema_and_reopens_read_only(tmp_path: Path) -> None:
    path = tmp_path / "lab-canary.db"
    store = CanaryStore.initialize(path)

    assert store.status() == {
        "canary_id": "synthetic-canary-0001",
        "classification": "SYNTHETIC_ONLY",
        "state": "PRESENT",
    }
    assert CanaryStore.open_existing(path).status() == store.status()

    with sqlite3.connect(path) as connection:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert names == {"lab_metadata", "canary_record"}
    assert not names.intersection(
        {"tasks", "action_proposals", "credentials", "owner_intents"}
    )


def test_reopen_in_independent_process_retains_only_canary(tmp_path: Path) -> None:
    path = tmp_path / "lab-canary.db"
    CanaryStore.initialize(path)
    script = (
        "import json,sys; from tools.cr2_g_b1.store import CanaryStore; "
        "print(json.dumps(CanaryStore.open_existing(sys.argv[1]).status(), "
        "sort_keys=True,separators=(',',':')))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        check=False,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == json.dumps(
        {
            "canary_id": "synthetic-canary-0001",
            "classification": "SYNTHETIC_ONLY",
            "state": "PRESENT",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert result.stderr == ""


def test_failed_seed_transaction_leaves_no_trusted_partial_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.cr2_g_b1.store as store_module

    path = tmp_path / "failed-canary.db"
    real_connect = sqlite3.connect

    def failing_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = real_connect(*args, **kwargs)

        def deny_seed(action: int, first: str | None, *_: object) -> int:
            if action == sqlite3.SQLITE_INSERT and first == "canary_record":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(deny_seed)
        return connection

    monkeypatch.setattr(store_module.sqlite3, "connect", failing_connect)

    with pytest.raises(CanaryStoreError):
        CanaryStore.initialize(path)

    monkeypatch.undo()
    with real_connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        assert tables == []
    with pytest.raises(CanaryStoreError):
        CanaryStore.open_existing(path)


def test_existing_sentinel_workspace_is_not_adopted(tmp_path: Path) -> None:
    path = tmp_path / "unrelated.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE tasks(task_id TEXT)")

    digest_before = hashlib.sha256(path.read_bytes()).digest()
    with pytest.raises(CanaryStoreError):
        CanaryStore.open_existing(path)
    assert hashlib.sha256(path.read_bytes()).digest() == digest_before


def test_modified_canary_record_is_rejected_on_readback(tmp_path: Path) -> None:
    path = tmp_path / "tampered-canary.db"
    CanaryStore.initialize(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE canary_record SET state = 'CHANGED'")

    with pytest.raises(CanaryStoreError):
        CanaryStore.open_existing(path)


def test_initialize_never_adopts_an_existing_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "already-there.db"
    path.write_bytes(b"disposable existing bytes")
    before = hashlib.sha256(path.read_bytes()).digest()

    with pytest.raises(CanaryStoreError):
        CanaryStore.initialize(path)

    assert hashlib.sha256(path.read_bytes()).digest() == before

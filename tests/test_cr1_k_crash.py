"""Real-process crash and writer-contention evidence for CR1-K."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sentinel.sync import (
    FixtureSyncAdvanceResult,
    FixtureSyncError,
    advance_incremental_github_fixture,
    read_incremental_github_fixture_state,
)
from tests.cr1_k_support import setup_case, source_rows

_CRASH_SCRIPT = r"""
import os
from pathlib import Path
import sentinel.sync.github_fixture as module

phase = os.environ["SENTINEL_CR1_K_PHASE"]
database = Path(os.environ["SENTINEL_CR1_K_DATABASE"])
store_root = Path(os.environ["SENTINEL_CR1_K_STORE_ROOT"])
crash_code = 73

if phase in {"before-item", "after-item"}:
    original = module._insert_page_item
    def hook(connection, item):
        if phase == "before-item":
            os._exit(crash_code)
        original(connection, item)
        if phase == "after-item":
            os._exit(crash_code)
    module._insert_page_item = hook
elif phase == "partial-span":
    original = module._insert_page_span
    count = 0
    def hook(connection, span):
        global count
        original(connection, span)
        count += 1
        if count == 1:
            os._exit(crash_code)
    module._insert_page_span = hook
elif phase == "after-all-spans":
    def hook(*args, **kwargs):
        os._exit(crash_code)
    module._advance_cursor = hook
elif phase == "after-cursor-before-commit":
    original = module._verify_complete_state
    count = 0
    def hook(*args, **kwargs):
        global count
        result = original(*args, **kwargs)
        count += 1
        if count == 2:
            os._exit(crash_code)
        return result
    module._verify_complete_state = hook

result = module.advance_incremental_github_fixture(
    database, store_root=store_root, expected_generation=0
)
if phase == "after-commit":
    os._exit(0)
os._exit(74)
"""


@pytest.mark.parametrize(
    ("phase", "expected_exit", "expected_generation"),
    (
        ("before-item", 73, 0),
        ("after-item", 73, 0),
        ("partial-span", 73, 0),
        ("after-all-spans", 73, 0),
        ("after-cursor-before-commit", 73, 0),
        ("after-commit", 0, 1),
    ),
)
def test_child_process_death_has_only_complete_page_states(
    tmp_path: Path,
    phase: str,
    expected_exit: int,
    expected_generation: int,
) -> None:
    database, store_root, source_id = setup_case(tmp_path, name=phase)
    before = source_rows(database, source_id)
    child_env = os.environ.copy()
    child_env.update(
        {
            "SENTINEL_CR1_K_PHASE": phase,
            "SENTINEL_CR1_K_DATABASE": str(database),
            "SENTINEL_CR1_K_STORE_ROOT": str(store_root),
        }
    )

    child = subprocess.run(
        [sys.executable, "-c", _CRASH_SCRIPT],
        cwd=tmp_path,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert child.returncode == expected_exit, child.stderr
    state = read_incremental_github_fixture_state(database, store_root=store_root)
    assert state.generation == expected_generation
    after = source_rows(database, source_id)
    if expected_generation == 0:
        assert after == before
        retry = advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=0
        )
        assert retry.result is FixtureSyncAdvanceResult.APPLIED
        assert retry.state.generation == 1
    else:
        assert len(after["items"]) == 1
        assert len(after["spans"]) == 3
        retry = advance_incremental_github_fixture(
            database, store_root=store_root, expected_generation=0
        )
        assert retry.result is FixtureSyncAdvanceResult.ALREADY_APPLIED
        assert retry.state.generation == 1


def test_independent_process_status_reports_committed_page(tmp_path: Path) -> None:
    database, store_root, _source_id = setup_case(tmp_path, name="child-status")
    advance_incremental_github_fixture(database, store_root=store_root, expected_generation=0)
    executable = Path(sys.executable).parent / "sentinel.exe"
    result = subprocess.run(
        [
            str(executable),
            "fixture-sync",
            "status",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert '"generation":1' in result.stdout
    assert '"item_count":1' in result.stdout
    assert '"span_count":3' in result.stdout


def test_independent_writer_process_denies_competing_advance(tmp_path: Path) -> None:
    database, store_root, _source_id = setup_case(tmp_path, name="competing-writer")
    ready = tmp_path / "writer-ready.flag"
    release = tmp_path / "writer-release.flag"
    script = r"""
import os
from pathlib import Path
import time
from sentinel.storage.writer import acquire_writer_lease

database = Path(os.environ["SENTINEL_CR1_K_DATABASE"])
ready = Path(os.environ["SENTINEL_CR1_K_READY"])
release = Path(os.environ["SENTINEL_CR1_K_RELEASE"])
with acquire_writer_lease(database):
    ready.write_text("ready", encoding="ascii")
    deadline = time.monotonic() + 20
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not release.exists():
        raise SystemExit(9)
"""
    child_env = os.environ.copy()
    child_env.update(
        {
            "SENTINEL_CR1_K_DATABASE": str(database),
            "SENTINEL_CR1_K_READY": str(ready),
            "SENTINEL_CR1_K_RELEASE": str(release),
        }
    )
    child = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and time.monotonic() < deadline:
            if child.poll() is not None:
                stdout, stderr = child.communicate(timeout=2)
                pytest.fail(f"writer child exited early: {child.returncode} {stdout} {stderr}")
            time.sleep(0.02)
        assert ready.exists(), "writer child did not acquire lease before deadline"
        with pytest.raises(FixtureSyncError) as caught:
            advance_incremental_github_fixture(
                database, store_root=store_root, expected_generation=0
            )
        assert caught.value.code.value == "writer_unavailable"
    finally:
        release.write_text("release", encoding="ascii")
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, (stdout, stderr)
    state = read_incremental_github_fixture_state(database, store_root=store_root)
    assert state.generation == 0

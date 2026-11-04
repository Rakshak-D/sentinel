from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.ingestion import promote_github_fixture_to_public_blobs
from tests.cr1_h1_support import blob_files, prepared_case, refs_by_item

_CHILD_SCRIPT = r"""
import os, sys
import sentinel.content.public_fixture_store as store
import sentinel.ingestion.blob_promotion as promotion
import sentinel.storage.writer as writer
database, root, stage = sys.argv[1:]
exit_code = int(stage[-2:])
if stage == "A81":
    store._publish_no_clobber = lambda *_: os._exit(exit_code)
elif stage == "B82":
    original = store._publish_no_clobber
    def publish_then_die(*args):
        original(*args)
        os._exit(exit_code)
    store._publish_no_clobber = publish_then_die
elif stage == "C83":
    original = store._publish_no_clobber
    calls = 0
    def publish_three_then_die(*args):
        global calls
        result = original(*args)
        calls += 1
        if calls == 3:
            os._exit(exit_code)
        return result
    store._publish_no_clobber = publish_three_then_die
elif stage == "D84":
    original = writer._execute_transaction_control
    def die_before_begin(connection, state, statement):
        if statement == "BEGIN IMMEDIATE":
            os._exit(exit_code)
        return original(connection, state, statement)
    writer._execute_transaction_control = die_before_begin
elif stage in {"E85", "F86"}:
    original = promotion._update_content_reference
    calls = 0
    limit = 1 if stage.startswith("E") else 3
    def update_then_die(connection, item_id, old_ref, new_ref):
        global calls
        result = original(connection, item_id, old_ref, new_ref)
        calls += 1
        if calls == limit:
            os._exit(exit_code)
        return result
    promotion._update_content_reference = update_then_die
report = promotion.promote_github_fixture_to_public_blobs(database, store_root=root)
if stage == "G87":
    os._exit(exit_code)
"""


@pytest.mark.parametrize(
    ("stage", "exit_code", "expected_blobs", "committed"),
    [
        ("A81", 81, 0, False),
        ("B82", 82, 1, False),
        ("C83", 83, 3, False),
        ("D84", 84, 3, False),
        ("E85", 85, 3, False),
        ("F86", 86, 3, False),
        ("G87", 87, 3, True),
    ],
)
def test_real_process_crash_matrix_and_retry(
    tmp_path: Path,
    stage: str,
    exit_code: int,
    expected_blobs: int,
    committed: bool,
) -> None:
    database, store_root = prepared_case(tmp_path, name=f"crash-{stage}")
    before_refs = refs_by_item(database)
    environment = os.environ.copy()
    child = subprocess.run(
        [sys.executable, "-c", _CHILD_SCRIPT, str(database), str(store_root), stage],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert child.returncode == exit_code
    assert child.stdout == ""
    assert child.stderr == ""
    assert len(blob_files(store_root)) == expected_blobs
    observed_refs = refs_by_item(database)
    if committed:
        assert all(
            ref.startswith("sentinel-public-blob-v1:sha256:") for ref in observed_refs.values()
        )
    else:
        assert observed_refs == before_refs

    retry = promote_github_fixture_to_public_blobs(database, store_root=store_root)
    if committed:
        assert retry.updated_references == 0
        assert retry.existing_references == 3
    else:
        assert retry.updated_references == 3
        assert retry.existing_references == 0
    assert all(
        ref.startswith("sentinel-public-blob-v1:sha256:") for ref in refs_by_item(database).values()
    )

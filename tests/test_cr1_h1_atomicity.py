from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

import sentinel.ingestion.blob_promotion as promotion_module
import sentinel.ingestion.blob_validation as validation_module
from sentinel.ingestion import (
    GithubBlobIntegrationError,
    GithubBlobIntegrationErrorCode,
    promote_github_fixture_to_public_blobs,
)
from tests.cr1_h1_support import blob_files, item_rows, prepared_case, refs_by_item, span_rows


@pytest.mark.parametrize("updates_before_failure", [1, 3])
def test_failure_after_ref_updates_rolls_back_all_three_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, updates_before_failure: int
) -> None:
    database, store_root = prepared_case(tmp_path, name=f"rollback-{updates_before_failure}")
    old_refs = refs_by_item(database)
    old_rows = item_rows(database)
    old_spans = span_rows(database)
    original = getattr(promotion_module, "_update_content_reference", None)
    calls = 0

    def fail_after_update(connection, item_id, old_ref, new_ref):
        nonlocal calls
        assert original is not None
        result = original(connection, item_id, old_ref, new_ref)
        calls += 1
        if calls == updates_before_failure:
            raise RuntimeError("SYNTHETIC-PRIVATE-CANARY")
        return result

    monkeypatch.setattr(
        promotion_module, "_update_content_reference", fail_after_update, raising=False
    )
    with pytest.raises(GithubBlobIntegrationError) as error:
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert error.value.code is GithubBlobIntegrationErrorCode.PROMOTION_FAILURE
    assert "SYNTHETIC-PRIVATE-CANARY" not in str(error.value)
    assert refs_by_item(database) == old_refs
    assert item_rows(database) == old_rows
    assert span_rows(database) == old_spans
    assert len(blob_files(store_root)) == 3


def test_retry_after_sql_rollback_reuses_published_blobs(tmp_path, monkeypatch):
    database, store_root = prepared_case(tmp_path, name="rollback-retry")
    original = getattr(promotion_module, "_update_content_reference", None)

    def fail_once(connection, item_id, old_ref, new_ref):
        assert original is not None
        monkeypatch.setattr(promotion_module, "_update_content_reference", original)
        original(connection, item_id, old_ref, new_ref)
        raise RuntimeError("synthetic update failure")

    monkeypatch.setattr(promotion_module, "_update_content_reference", fail_once, raising=False)
    with pytest.raises(GithubBlobIntegrationError):
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    report = promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert report.updated_references == 3
    assert report.existing_references == 0
    assert len(blob_files(store_root)) == 3


def test_final_complete_state_verification_runs_in_transaction_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store_root = prepared_case(tmp_path, name="postcondition-rollback")
    old_rows = item_rows(database)
    old_spans = span_rows(database)
    old_refs = refs_by_item(database)
    original = validation_module.verify_spans
    calls = 0

    def fail_postcondition(connection):
        nonlocal calls
        calls += 1
        if calls == 3:
            assert connection.in_transaction
            raise RuntimeError("SYNTHETIC-CANARY")
        return original(connection)

    monkeypatch.setattr(validation_module, "verify_spans", fail_postcondition)
    with pytest.raises(GithubBlobIntegrationError) as error:
        promote_github_fixture_to_public_blobs(database, store_root=store_root)
    assert error.value.code is GithubBlobIntegrationErrorCode.PROMOTION_FAILURE
    assert "SYNTHETIC-CANARY" not in str(error.value)
    assert calls == 3
    assert refs_by_item(database) == old_refs
    assert item_rows(database) == old_rows
    assert span_rows(database) == old_spans
    assert len(blob_files(store_root)) == 3


def test_competing_process_writer_lease_denies_promotion(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="contended")
    marker = tmp_path / "lease-ready.marker"
    old_refs = refs_by_item(database)
    script = r"""
import sys, time
from sentinel.storage.writer import acquire_writer_lease
with acquire_writer_lease(sys.argv[1]):
    open(sys.argv[2], "w", encoding="ascii").write("ready")
    time.sleep(60)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(database), str(marker)],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 12
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        assert marker.exists(), "second process did not acquire the cooperating lease"
        with pytest.raises(GithubBlobIntegrationError) as error:
            promote_github_fixture_to_public_blobs(database, store_root=store_root)
        assert error.value.code is GithubBlobIntegrationErrorCode.WRITER_UNAVAILABLE
        assert refs_by_item(database) == old_refs
        # Publication precedes lease acquisition, so verified orphan blobs are valid.
        assert len(blob_files(store_root)) == 3
    finally:
        process.kill()
        process.communicate(timeout=5)

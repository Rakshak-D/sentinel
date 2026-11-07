from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.content.public_fixture_store import _blob_path
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.policy.source_binding import resolve_github_fixture_public_read
from sentinel.proposals import review
from sentinel.proposals.persistence import (
    get_github_fixture_proposal,
    list_github_fixture_proposals,
)
from sentinel.proposals.review import (
    ProposalReviewError,
    ProposalReviewErrorCode,
    check_github_fixture_proposal,
)
from sentinel.proposals.review_formatters import (
    format_json_proposal_review,
    format_text_proposal_review,
)
from sentinel.proposals.review_types import ProposalReviewReadiness
from tests.test_cr1_i_support import promoted_case


def _invoke_save(database: Path, store_root: Path, issue: int = 101) -> dict[str, object]:
    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "save-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            str(issue),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout)["proposal"]


def _invoke_check(
    database: Path,
    store_root: Path,
    proposal_id: str,
    output_format: str = "json",
):
    return CliRunner().invoke(
        app,
        [
            "proposal",
            "check",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--id",
            proposal_id,
            "--format",
            output_format,
        ],
    )


def _db_snapshot(database: Path) -> tuple[tuple[str, tuple[tuple[object, ...], ...]], ...]:
    tables = (
        "principals",
        "config_revisions",
        "run_manifests",
        "runs",
        "action_proposals",
        "proposal_sources",
        "source_items",
        "source_spans",
        "tasks",
        "task_creation_requests",
        "sync_cursors",
    )
    with sqlite3.connect(database) as connection:
        return tuple(
            (
                table,
                tuple(
                    tuple(row)
                    for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")
                ),
            )
            for table in tables
        )


def _blob_snapshot(store_root: Path) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (
                path.relative_to(store_root).as_posix(),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in store_root.rglob("*")
            if path.is_file()
        )
    )


def test_review_check_reports_ready_for_existing_pending_proposal(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-ready")
    proposal = _invoke_save(database, store_root)

    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "check",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--id",
            proposal["proposal_id"],
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["schema_version"] == "sentinel.proposal-review-check.v1"
    assert report["proposal_id"] == proposal["proposal_id"]
    assert report["review_readiness"] == "READY_FOR_OWNER_REVIEW"
    assert report["owner_verified"] is False
    assert report["executable"] is False


@pytest.mark.parametrize("issue", [101, 102, 103])
def test_each_pending_issue_is_ready_only_when_current_sources_match(tmp_path, issue: int) -> None:
    database, store_root = promoted_case(tmp_path, name=f"cr2-e-ready-{issue}")
    saved = _invoke_save(database, store_root, issue)
    record = get_github_fixture_proposal(database, proposal_id=saved["proposal_id"])
    fixed_time = record.created_at + timedelta(seconds=1)
    calls: list[object] = []

    def fixed_clock():
        calls.append(fixed_time)
        return fixed_time

    import sentinel.proposals.review as review_module

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(review_module, "_utc_now", fixed_clock)
    try:
        result = check_github_fixture_proposal(
            database,
            store_root=store_root,
            proposal_id=record.proposal_id,
        )
    finally:
        monkeypatch.undo()

    assert result.review_readiness is ProposalReviewReadiness.READY_FOR_OWNER_REVIEW
    assert result.source_item_id == record.source_item_id
    assert result.source_content_sha256 == record.source_content_sha256
    assert result.source_binding_sha256 == record.source_binding_sha256
    assert result.evidence_span_count == len(record.evidence_span_ids)
    assert result.stored_status == "PENDING_REVIEW"
    assert result.owner_verified is False
    assert result.executable is False
    assert calls == [fixed_time]


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (timedelta(microseconds=-1), ProposalReviewReadiness.READY_FOR_OWNER_REVIEW),
        (timedelta(0), ProposalReviewReadiness.EXPIRED),
        (timedelta(microseconds=1), ProposalReviewReadiness.EXPIRED),
    ],
)
def test_expiry_uses_exact_inclusive_boundary(tmp_path, monkeypatch, delta, expected) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-expiry")
    saved = _invoke_save(database, store_root)
    proposal = get_github_fixture_proposal(database, proposal_id=saved["proposal_id"])
    checked_at = proposal.expires_at + delta
    calls = 0

    def clock_once():
        nonlocal calls
        calls += 1
        return checked_at

    monkeypatch.setattr(review, "_utc_now", clock_once)
    result = check_github_fixture_proposal(
        database,
        store_root=store_root,
        proposal_id=proposal.proposal_id,
    )
    cli_result = _invoke_check(database, store_root, proposal.proposal_id)

    assert result.review_readiness is expected
    assert result.checked_at == checked_at
    assert cli_result.exit_code == 0, cli_result.stderr
    assert json.loads(cli_result.stdout)["review_readiness"] == expected.value
    assert calls == 2
    assert get_github_fixture_proposal(database, proposal_id=proposal.proposal_id) == proposal


def test_review_report_formatters_are_stable_and_do_not_render_source_citations(
    tmp_path, monkeypatch
) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-format")
    saved = _invoke_save(database, store_root)
    proposal = get_github_fixture_proposal(database, proposal_id=saved["proposal_id"])
    checked_at = proposal.created_at + timedelta(seconds=2)
    monkeypatch.setattr(review, "_utc_now", lambda: checked_at)
    report = check_github_fixture_proposal(
        database,
        store_root=store_root,
        proposal_id=proposal.proposal_id,
    )
    json_once = format_json_proposal_review(report)
    text_once = format_text_proposal_review(report)

    assert json_once == format_json_proposal_review(report)
    assert text_once == format_text_proposal_review(report)
    assert "READY_FOR_OWNER_REVIEW" in text_once
    assert "Owner verified: no" in text_once
    assert "Executable: no" in text_once
    assert "PENDING_REVIEW" in json_once
    assert "owner_verified" in json_once and "false" in json_once
    assert "executable" in json_once and "false" in json_once
    assert "credential_alias" not in json_once
    assert "source_body" not in json_once
    assert "instruction" not in text_once.casefold()
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    selected = next(
        item for item in verified.evidence.items if item.item_id == proposal.source_item_id
    )
    assert all(citation.cited_text not in json_once for citation in selected.citations)
    assert all(citation.cited_text not in text_once for citation in selected.citations)


def test_check_is_read_only_for_database_blobs_and_all_relevant_rows(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-read-only")
    saved = _invoke_save(database, store_root)
    proposal = get_github_fixture_proposal(database, proposal_id=saved["proposal_id"])
    monkeypatch.setattr(review, "_utc_now", lambda: proposal.created_at + timedelta(seconds=1))
    before = (_db_snapshot(database), _blob_snapshot(store_root))

    check_github_fixture_proposal(
        database,
        store_root=store_root,
        proposal_id=proposal.proposal_id,
    )

    assert (_db_snapshot(database), _blob_snapshot(store_root)) == before
    assert list_github_fixture_proposals(database).proposal_count == 1


def test_missing_or_changed_blob_fails_with_empty_cli_stdout_and_no_writes(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-blob-failure")
    saved = _invoke_save(database, store_root)
    expected_digest = EXPECTED_MANIFEST.items[0].values[6]
    blob = _blob_path(store_root, str(expected_digest))
    original = blob.read_bytes()
    before = _db_snapshot(database)
    try:
        blob.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        result = _invoke_check(database, store_root, saved["proposal_id"])
        assert result.exit_code != 0
        assert result.stdout == ""
        assert str(database) not in result.stderr
        assert "unavailable" in result.stderr.casefold()
    finally:
        blob.write_bytes(original)

    assert _db_snapshot(database) == before
    assert _blob_snapshot(store_root)


def test_missing_blob_is_not_replaced_from_packaged_fixture(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-no-fallback")
    saved = _invoke_save(database, store_root)
    expected_digest = EXPECTED_MANIFEST.items[1].values[6]
    blob = _blob_path(store_root, str(expected_digest))
    original = blob.read_bytes()
    before = _db_snapshot(database)
    blob.unlink()
    try:
        with pytest.raises(ProposalReviewError) as raised:
            check_github_fixture_proposal(
                database,
                store_root=store_root,
                proposal_id=saved["proposal_id"],
            )
        assert raised.value.code is ProposalReviewErrorCode.SOURCE_UNAVAILABLE
        assert not blob.exists()
    finally:
        blob.write_bytes(original)
    assert _db_snapshot(database) == before


def test_tampered_record_is_rejected_without_review_stdout(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-record-tamper")
    saved = _invoke_save(database, store_root)
    proposal_id = saved["proposal_id"]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE action_proposals SET canonical_args_sha256 = ? WHERE proposal_id = ?",
            ("f" * 64, proposal_id),
        )

    result = _invoke_check(database, store_root, proposal_id)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr
    assert "f" * 20 not in result.stderr


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("status", "APPROVED"),
        ("canonical_args_sha256", "f" * 64),
        ("source_binding_sha256", "f" * 64),
        ("source_manifest_sha256", "f" * 64),
        ("config_sha256", "f" * 64),
        ("run_id", "00000000-0000-0000-0000-000000000000"),
        ("principal_id", "00000000-0000-0000-0000-000000000000"),
    ],
)
def test_check_uses_strict_persisted_lineage_validation(
    tmp_path, column: str, replacement: str
) -> None:
    database, store_root = promoted_case(tmp_path, name=f"cr2-e-tamper-{column}")
    saved = _invoke_save(database, store_root)
    with sqlite3.connect(database) as connection:
        connection.execute(
            f"UPDATE action_proposals SET {column} = ? WHERE proposal_id = ?",
            (replacement, saved["proposal_id"]),
        )

    result = _invoke_check(database, store_root, saved["proposal_id"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr


def test_check_rejects_selected_source_item_tampering(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-source-item-tamper")
    saved = _invoke_save(database, store_root)
    with sqlite3.connect(database) as connection:
        other_item, = connection.execute(
            "SELECT item_id FROM source_items WHERE item_id <> ? ORDER BY item_id LIMIT 1",
            (saved["source_item_id"],),
        ).fetchone()
        connection.execute(
            "UPDATE action_proposals SET selected_source_item_id = ? WHERE proposal_id = ?",
            (other_item, saved["proposal_id"]),
        )

    result = _invoke_check(database, store_root, saved["proposal_id"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr


def test_check_rejects_corrupt_migration_history_with_empty_stdout(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-migration-tamper")
    saved = _invoke_save(database, store_root)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE schema_migrations SET artifact_sha256 = ? "
            "WHERE migration_id = 'cr2-d-0005-durable-pending-proposals'",
            ("f" * 64,),
        )

    result = _invoke_check(database, store_root, saved["proposal_id"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr


def test_check_rejects_tampered_source_citation_reference(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-citation-tamper")
    saved = _invoke_save(database, store_root)
    proposal_id = saved["proposal_id"]
    with sqlite3.connect(database) as connection:
        selected_item, = connection.execute(
            "SELECT selected_source_item_id FROM action_proposals WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()
        replacement_item, replacement_span = connection.execute(
            "SELECT item_id, span_id FROM source_spans WHERE item_id <> ? LIMIT 1",
            (selected_item,),
        ).fetchone()
        span_id, = connection.execute(
            "SELECT span_id FROM proposal_sources WHERE proposal_id = ? LIMIT 1",
            (proposal_id,),
        ).fetchone()
        connection.execute(
            "UPDATE proposal_sources SET item_id = ?, span_id = ? "
            "WHERE proposal_id = ? AND span_id = ?",
            (replacement_item, replacement_span, proposal_id, span_id),
        )

    result = _invoke_check(database, store_root, proposal_id)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr


def test_missing_malformed_and_unknown_proposal_ids_fail_closed(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-id-failure")

    missing = _invoke_check(database, store_root, "a" * 64)
    malformed = _invoke_check(database, store_root, "../not-a-proposal")
    no_id = CliRunner().invoke(
        app,
        [
            "proposal",
            "check",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--format",
            "json",
        ],
    )

    for result in (missing, malformed, no_id):
        assert result.exit_code != 0
        assert result.stdout == ""
        assert str(database) not in result.stderr

    owner_flag = CliRunner().invoke(
        app,
        [
            "proposal",
            "check",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--id",
            "a" * 64,
            "--approve",
            "--format",
            "json",
        ],
    )
    assert owner_flag.exit_code != 0
    assert owner_flag.stdout == ""
    assert str(database) not in owner_flag.stderr


def test_current_source_binding_must_match_saved_source_set(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-source-set-mismatch")
    saved = _invoke_save(database, store_root)
    original = review._resolve_current_source

    def mismatch(*args, **kwargs):
        verified = original(*args, **kwargs)
        object.__setattr__(verified.binding, "source_set_sha256", "f" * 64)
        return verified

    monkeypatch.setattr(review, "_resolve_current_source", mismatch)

    with pytest.raises(ProposalReviewError) as raised:
        check_github_fixture_proposal(
            database,
            store_root=store_root,
            proposal_id=saved["proposal_id"],
        )

    assert raised.value.code is ProposalReviewErrorCode.SOURCE_UNAVAILABLE


def test_list_and_review_check_do_not_change_pending_proposal_or_tasks(
    tmp_path, monkeypatch
) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-list-preserve")
    saved = _invoke_save(database, store_root)
    proposal_id = saved["proposal_id"]
    before = _db_snapshot(database)
    proposal = get_github_fixture_proposal(database, proposal_id=proposal_id)
    monkeypatch.setattr(review, "_utc_now", lambda: proposal.created_at)

    checked = _invoke_check(database, store_root, proposal_id)
    listed = CliRunner().invoke(
        app,
        ["proposal", "list", "--database", str(database), "--format", "json"],
    )

    assert checked.exit_code == 0, checked.stderr
    assert listed.exit_code == 0, listed.stderr
    assert json.loads(listed.stdout)["proposals"][0]["proposal_id"] == proposal_id
    assert _db_snapshot(database) == before


def test_late_formatter_failure_has_empty_stdout(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-e-format-failure")
    saved = _invoke_save(database, store_root)
    proposal = get_github_fixture_proposal(database, proposal_id=saved["proposal_id"])
    monkeypatch.setattr(review, "_utc_now", lambda: proposal.created_at)

    def fail_format(_output: str) -> None:
        raise ValueError("sensitive internal formatting state")

    monkeypatch.setattr("sentinel.proposals.review_formatters._require_bound", fail_format)
    result = _invoke_check(database, store_root, proposal.proposal_id)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "sensitive" not in result.stderr
    assert str(database) not in result.stderr

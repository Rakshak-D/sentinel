from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Barrier

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.content.public_fixture_store import _blob_path
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.policy import (
    BUILTIN_REGISTRY,
    EffectClass,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRuleId,
    build_policy_context,
    evaluate_policy,
)
from sentinel.policy.evaluator import (
    build_proposal_persistence_policy_request,
    build_verified_proposal_preview_policy_input,
)
from sentinel.policy.source_binding import resolve_github_fixture_public_read
from sentinel.proposals import persistence
from sentinel.proposals.persistence import ProposalPersistenceError, ProposalPersistenceErrorCode
from sentinel.proposals.preview import build_github_issue_proposal_preview
from sentinel.storage.migrations import initialize_storage
from tests.test_cr1_i_support import promoted_case


def _save(database: Path, store_root: Path, issue: int):
    return CliRunner().invoke(
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


def _stored_counts(database: Path) -> tuple[int, int, int, int, int]:
    with sqlite3.connect(database) as connection:
        proposal_count = connection.execute("SELECT count(*) FROM action_proposals").fetchone()[0]
        source_count = connection.execute("SELECT count(*) FROM proposal_sources").fetchone()[0]
        task_count = connection.execute("SELECT count(*) FROM tasks").fetchone()[0]
        run_count = connection.execute("SELECT count(*) FROM runs").fetchone()[0]
        receipt_count = connection.execute(
            "SELECT count(*) FROM task_creation_requests"
        ).fetchone()[0]
    return proposal_count, source_count, task_count, run_count, receipt_count


def _lineage_counts(database: Path) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "principals",
                "config_revisions",
                "run_manifests",
                "runs",
                "action_proposals",
                "proposal_sources",
                "tasks",
                "task_creation_requests",
            )
        )


def test_save_selected_github_issue_creates_pending_proposal(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-save-101")

    result = _save(database, store_root, 101)

    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == "sentinel.synthetic-pending-proposal-save.v1"
    proposal = document["proposal"]
    assert proposal["schema_version"] == "sentinel.synthetic-pending-proposal.v1"
    assert proposal["status"] == "PENDING_REVIEW"
    assert proposal["proposal_kind"] == "REVIEW_SOURCE"
    assert proposal["capability"] == "C2_WRITE_LOCAL_PROPOSAL"
    assert proposal["source_item_id"]
    assert proposal["source_content_sha256"]
    assert len(proposal["evidence_span_ids"]) == 3
    assert proposal["owner_intent_id"] is None
    assert proposal["credential_alias"] is None
    assert proposal["executable"] is False
    assert proposal["policy_rule_id"] == "P06"
    with sqlite3.connect(database) as connection:
        canonical_args = connection.execute(
            "SELECT canonical_args_json FROM action_proposals WHERE proposal_id = ?",
            (proposal["proposal_id"],),
        ).fetchone()[0]
    canonical_bytes = canonical_args.encode("utf-8", errors="strict")
    expected_args_sha256 = hashlib.sha256(
        b"sentinel.synthetic-pending-proposal-arguments.v1\x00" + canonical_bytes
    ).hexdigest()
    assert proposal["canonical_args_sha256"] == expected_args_sha256
    assert proposal["canonical_args_ref"] == f"sha256:{expected_args_sha256}"
    display = (
        "Review synthetic GitHub issue #101\n\n"
        "Possible review only; not an actual task assignment."
    )
    assert proposal["display_sha256"] == hashlib.sha256(display.encode("utf-8")).hexdigest()
    assert datetime.fromisoformat(proposal["expires_at"]) > datetime.fromisoformat(
        proposal["created_at"]
    )
    assert _stored_counts(database) == (1, 3, 0, 1, 0)


@pytest.mark.parametrize("issue", [101, 102, 103])
def test_each_explicit_issue_is_saved_as_its_own_pending_proposal(tmp_path, issue: int) -> None:
    database, store_root = promoted_case(tmp_path, name=f"cr2-d-save-{issue}")

    result = _save(database, store_root, issue)

    assert result.exit_code == 0, result.stderr
    saved = json.loads(result.stdout)["proposal"]
    assert saved["issue_number"] == issue
    assert saved["provider_item_id"] == f"example-owner/fixture-project#{issue}"
    assert saved["status"] == "PENDING_REVIEW"
    assert saved["source_trust"] == "T4 EXTERNAL"
    assert saved["source_sensitivity"] == "PUBLIC"
    assert saved["derived_trust"] == "T3 DERIVED"
    assert saved["derived_sensitivity"] == "PUBLIC"
    assert _stored_counts(database) == (1, len(saved["evidence_span_ids"]), 0, 1, 0)


def test_repeat_save_is_idempotent_and_preserves_first_timestamps(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-repeat")

    first = _save(database, store_root, 102)
    assert first.exit_code == 0, first.stderr
    first_proposal = json.loads(first.stdout)["proposal"]
    second = _save(database, store_root, 102)

    assert second.exit_code == 0, second.stderr
    second_document = json.loads(second.stdout)
    second_proposal = second_document["proposal"]
    assert second_document["disposition"] == "ALREADY_EXISTS"
    assert second_proposal["proposal_id"] == first_proposal["proposal_id"]
    assert second_proposal["created_at"] == first_proposal["created_at"]
    assert second_proposal["expires_at"] == first_proposal["expires_at"]
    assert _stored_counts(database) == (1, 5, 0, 1, 0)


def test_list_reads_persisted_proposals_and_detects_tampering(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-list-persisted")
    saved = _save(database, store_root, 103)
    assert saved.exit_code == 0, saved.stderr
    proposal_id = json.loads(saved.stdout)["proposal"]["proposal_id"]

    listed = CliRunner().invoke(
        app,
        ["proposal", "list", "--database", str(database), "--format", "json"],
    )
    assert listed.exit_code == 0, listed.stderr
    document = json.loads(listed.stdout)
    assert document["proposal_count"] == 1
    assert document["proposals"][0]["proposal_id"] == proposal_id

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE action_proposals SET status = 'APPROVED' WHERE proposal_id = ?",
            (proposal_id,),
        )
    rejected = CliRunner().invoke(
        app,
        ["proposal", "list", "--database", str(database), "--format", "json"],
    )
    assert rejected.exit_code != 0
    assert rejected.stdout == ""
    assert "APPROVED" not in rejected.stderr
    assert str(database) not in rejected.stderr


def test_proposal_list_is_available_for_an_empty_database(tmp_path) -> None:
    database = tmp_path / "cr2-d-list.sqlite3"
    initialize_storage(database, create=True)

    result = CliRunner().invoke(
        app,
        ["proposal", "list", "--database", str(database), "--format", "json"],
    )

    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == "sentinel.synthetic-pending-proposal-list.v1"
    assert document["proposal_count"] == 0
    assert document["proposals"] == []


def test_invalid_issue_selection_fails_without_database_writes(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-invalid-selection")
    before = _lineage_counts(database)

    result = _save(database, store_root, 999)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "Select one supported synthetic issue number." in result.stderr
    assert str(database) not in result.stderr
    assert _lineage_counts(database) == before


def test_corrupt_source_blob_denies_without_partial_proposal(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-corrupt-blob")
    before = _lineage_counts(database)
    digest = EXPECTED_MANIFEST.items[0].values[6]
    blob = _blob_path(store_root, str(digest))
    original = blob.read_bytes()
    try:
        blob.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        result = _save(database, store_root, 101)
    finally:
        blob.write_bytes(original)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr
    assert "".join(chr(value) for value in original[:20]) not in result.stderr
    assert _lineage_counts(database) == before


def test_failure_after_supporting_rows_rolls_back_the_entire_transaction(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-late-failure")
    before = _lineage_counts(database)

    def fail_recheck(*_args, **_kwargs) -> None:
        raise ProposalPersistenceError(ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE)

    monkeypatch.setattr(persistence, "_recheck_source_snapshot", fail_recheck)
    result = _save(database, store_root, 102)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert str(database) not in result.stderr
    assert _lineage_counts(database) == before


def test_missing_blob_denies_before_any_proposal_or_lineage_write(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-missing-blob")
    before = _lineage_counts(database)
    digest = EXPECTED_MANIFEST.items[1].values[6]
    blob = _blob_path(store_root, str(digest))
    original = blob.read_bytes()
    blob.unlink()
    result = _save(database, store_root, 102)
    blob.write_bytes(original)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert _lineage_counts(database) == before


def test_list_rejects_source_citation_reference_tampering(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-citation-tamper")
    saved = _save(database, store_root, 101)
    assert saved.exit_code == 0, saved.stderr
    proposal_id = json.loads(saved.stdout)["proposal"]["proposal_id"]
    with sqlite3.connect(database) as connection:
        item_id = connection.execute(
            "SELECT selected_source_item_id FROM action_proposals WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()[0]
        original_span = connection.execute(
            "SELECT span_id FROM proposal_sources WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()[0]
        replacement_item, replacement_span = connection.execute(
            "SELECT item_id, span_id FROM source_spans WHERE item_id <> ? LIMIT 1",
            (item_id,),
        ).fetchone()
        connection.execute(
            "UPDATE proposal_sources SET item_id = ?, span_id = ? "
            "WHERE proposal_id = ? AND span_id = ?",
            (replacement_item, replacement_span, proposal_id, original_span),
        )

    listed = CliRunner().invoke(
        app,
        ["proposal", "list", "--database", str(database), "--format", "json"],
    )
    assert listed.exit_code != 0
    assert listed.stdout == ""
    assert str(database) not in listed.stderr


def test_task_rows_remain_untouched_when_pending_proposal_is_saved(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-task-preservation")
    with sqlite3.connect(database) as connection:
        before = connection.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()
        source_items_before = connection.execute(
            "SELECT * FROM source_items ORDER BY item_id"
        ).fetchall()
        source_spans_before = connection.execute(
            "SELECT * FROM source_spans ORDER BY item_id, span_id"
        ).fetchall()
        cursors_before = connection.execute(
            "SELECT * FROM sync_cursors ORDER BY source_id"
        ).fetchall()

    saved = _save(database, store_root, 103)

    assert saved.exit_code == 0, saved.stderr
    with sqlite3.connect(database) as connection:
        after = connection.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()
        source_items_after = connection.execute(
            "SELECT * FROM source_items ORDER BY item_id"
        ).fetchall()
        source_spans_after = connection.execute(
            "SELECT * FROM source_spans ORDER BY item_id, span_id"
        ).fetchall()
        cursors_after = connection.execute(
            "SELECT * FROM sync_cursors ORDER BY source_id"
        ).fetchall()
    assert after == before == []
    assert source_items_after == source_items_before
    assert source_spans_after == source_spans_before
    assert cursors_after == cursors_before


def test_persistence_policy_is_distinct_from_preview_permission(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-preview-allow-not-write")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    preview_request, preview_context = build_verified_proposal_preview_policy_input(
        verified,
        issue_number=101,
    )
    preview_decision = evaluate_policy(
        request=preview_request,
        context=preview_context,
        registry=BUILTIN_REGISTRY,
        evidence_binding=verified,
    )
    assert preview_decision.outcome is PolicyOutcome.ALLOW
    assert preview_decision.reason_code is PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED

    monkeypatch.setattr(persistence, "evaluate_policy", lambda **_kwargs: preview_decision)
    before = _lineage_counts(database)
    result = _save(database, store_root, 101)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "Proposal save failed:" in result.stderr
    assert _lineage_counts(database) == before


def test_persistence_policy_binds_exact_request_and_resolved_source(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-persistence-p09")
    verified = resolve_github_fixture_public_read(database, store_root=store_root)
    source = next(
        item
        for item in verified.binding.sources
        if item.provider_item_id == "example-owner/fixture-project#102"
    )
    preview = build_github_issue_proposal_preview(
        database,
        store_root=store_root,
        issue_number=102,
    )
    request = build_proposal_persistence_policy_request(
        binding=verified.binding,
        issue_number=102,
        preview_id=preview.preview_id,
    )
    context = build_policy_context(
        sources=verified.source_envelopes,
        source_binding_sha256=verified.binding.source_set_sha256,
    )
    allowed = evaluate_policy(
        request=request,
        context=context,
        registry=BUILTIN_REGISTRY,
        evidence_binding=verified,
    )
    assert request.operation_id == "sentinel.synthetic.proposal.persist"
    assert allowed.outcome is PolicyOutcome.ALLOW
    assert allowed.rule_id is PolicyRuleId.P06
    assert allowed.reason_code is PolicyReasonCode.PROPOSAL_PERSISTENCE_ALLOWED
    assert allowed.executable is False
    assert allowed.evidence_binding_sha256 == verified.binding.source_set_sha256
    assert allowed.evidence_ids == (
        request.request_id,
        source.source_id,
        *(citation.span_id for citation in source.citations),
    )

    changed_arguments = tuple(
        (name, "f" * 64 if name == "source_content_sha256" else value)
        for name, value in request.arguments
    )
    changed_requests = (
        request.model_copy(update={"source_binding_sha256": "f" * 64}),
        request.model_copy(update={"source_ids": request.source_ids[:-1]}),
        request.model_copy(update={"evidence_span_ids": request.evidence_span_ids[:-1]}),
        request.model_copy(update={"arguments": changed_arguments}),
        request.model_copy(update={"requested_effect_class": EffectClass.READ_ONLY}),
        request.model_copy(update={"registry_sha256": "f" * 64}),
        request.model_copy(update={"policy_sha256": "f" * 64}),
        request.model_copy(update={"operation_id": "sentinel.synthetic.proposal.local"}),
    )
    for changed in changed_requests:
        decision = evaluate_policy(
            request=changed,
            context=context,
            registry=BUILTIN_REGISTRY,
            evidence_binding=verified,
        )
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.executable is False


def test_storage_insert_guard_rejects_accepted_or_executable_rows(tmp_path) -> None:
    database = tmp_path / "cr2-d-insert-guard.sqlite3"
    initialize_storage(database, create=True)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="invalid bounded pending proposal"):
            connection.execute(
                """INSERT INTO action_proposals
                   (proposal_id, run_id, principal_id, tool_id, capability,
                    canonical_args_ref, canonical_args_sha256, display_sha256,
                    owner_intent_id, status, created_at, expires_at, credential_alias,
                    proposal_schema_version, proposal_kind, executable)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "proposal-id",
                    "run-id",
                    "principal-id",
                    "sentinel.synthetic.proposal.persist",
                    "C2_WRITE_LOCAL_PROPOSAL",
                    "sha256:" + "a" * 64,
                    "a" * 64,
                    "b" * 64,
                    None,
                    "APPROVED",
                    "2026-11-06T00:00:00.000000+00:00",
                    "2026-12-06T00:00:00.000000+00:00",
                    None,
                    "sentinel.synthetic-pending-proposal.v1",
                    "REVIEW_SOURCE",
                    0,
                ),
            )
        assert connection.execute("SELECT count(*) FROM action_proposals").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("crash_target", "exit_code"),
    [("_ensure_supporting_lineage", 91), ("_insert_proposal", 92)],
)
def test_process_termination_mid_transaction_leaves_no_partial_state(
    tmp_path, crash_target: str, exit_code: int
) -> None:
    database, store_root = promoted_case(tmp_path, name=f"cr2-d-crash-{exit_code}")
    before = _lineage_counts(database)
    script = f"""
import os
import sys
from pathlib import Path
from sentinel.proposals import persistence
target = {crash_target!r}
original = getattr(persistence, target)
def crash_after(*args, **kwargs):
    original(*args, **kwargs)
    os._exit({exit_code})
setattr(persistence, target, crash_after)
persistence.save_github_fixture_proposal(
    Path(sys.argv[1]), store_root=Path(sys.argv[2]), issue_number=101
)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(database), str(store_root)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=45,
    )

    assert result.returncode == exit_code
    assert result.stdout == b""
    assert result.stderr == b""
    assert _lineage_counts(database) == before


def test_duplicate_concurrent_requests_cannot_create_duplicate_proposals(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-d-concurrent-duplicate")
    gate = Barrier(2)

    def save_once():
        gate.wait(timeout=10)
        try:
            return persistence.save_github_fixture_proposal(
                database,
                store_root=store_root,
                issue_number=102,
            )
        except ProposalPersistenceError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _item: save_once(), range(2)))

    successful = tuple(item for item in outcomes if item is not None)
    assert successful
    assert len({item.proposal.proposal_id for item in successful}) == 1
    assert _stored_counts(database) == (1, 5, 0, 1, 0)
    retry = persistence.save_github_fixture_proposal(
        database,
        store_root=store_root,
        issue_number=102,
    )
    assert retry.disposition == "ALREADY_EXISTS"
    assert _stored_counts(database) == (1, 5, 0, 1, 0)

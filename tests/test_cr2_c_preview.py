from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from tests.test_cr1_i_support import promoted_case


@pytest.mark.parametrize("issue", [101, 102, 103])
def test_explicit_github_issue_preview_is_source_bound_and_nonpersistent(
    tmp_path, issue: int
) -> None:
    database, store_root = promoted_case(tmp_path, name=f"cr2-c-preview-{issue}")
    database_before = database.read_bytes()
    blob_paths = tuple(sorted(path for path in store_root.rglob("*") if path.is_file()))
    blob_bytes = tuple(path.read_bytes() for path in blob_paths)

    result = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
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
    document = json.loads(result.stdout)
    assert document["schema_version"] == "sentinel.synthetic-proposal-preview.v1"
    assert document["synthetic_data"] is True
    assert document["provider_item_id"] == f"example-owner/fixture-project#{issue}"
    expected_item = next(
        item for item in EXPECTED_MANIFEST.items if item.provider_item_id.endswith(f"#{issue}")
    )
    assert document["source_item_id"] == str(expected_item.item_id)
    assert document["source_envelope_id"] == str(expected_item.source_envelope_id)
    assert document["source_content_sha256"] == expected_item.content_sha256
    assert document["evidence_span_ids"] == [str(span.span_id) for span in expected_item.spans]
    assert document["status"] == "PREVIEW_ONLY"
    assert document["policy_rule_id"] == "P06"
    assert document["source_trust"] == "T4 EXTERNAL"
    assert document["source_sensitivity"] == "PUBLIC"
    assert document["derived_trust"] == "T3 DERIVED"
    assert document["derived_sensitivity"] == "PUBLIC"
    assert document["proposed_capability"] == "C2_WRITE_LOCAL_PROPOSAL"
    assert "not an accepted task" in document["disclaimer"]
    assert "source_body" not in document
    assert database.read_bytes() == database_before
    assert tuple(sorted(path for path in store_root.rglob("*") if path.is_file())) == blob_paths
    assert tuple(path.read_bytes() for path in blob_paths) == blob_bytes


def test_preview_cli_requires_explicit_issue_and_rejects_unknown_issue(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-preview-invalid")

    missing = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--format",
            "json",
        ],
    )
    unknown = CliRunner().invoke(
        app,
        [
            "proposal",
            "preview-github-fixture",
            "--database",
            str(database),
            "--store-root",
            str(store_root),
            "--issue",
            "999",
            "--format",
            "json",
        ],
    )

    assert missing.exit_code != 0
    assert unknown.exit_code == 1
    assert unknown.stdout == ""
    assert "explicit supported issue number" in unknown.stderr

"""Transactional registration and item persistence for the pinned issue fixture."""

import hashlib
import json
from pathlib import Path

from sentinel.ingestion import ingest_packaged_github_fixture
from sentinel.readers.github_fixture import read_packaged_github_fixture
from sentinel.storage.connection import readonly_database_connection
from tests.cr1_g_support import initialized_database


def test_first_ingestion_persists_registry_three_items_and_nine_spans(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "cr1-g.sqlite3")
    fixture = read_packaged_github_fixture()

    report = ingest_packaged_github_fixture(database)

    assert report.inserted_items == 3
    assert report.existing_items == 0
    assert report.inserted_spans == 9
    assert report.existing_spans == 0
    assert report.fixture_sha256 == (
        "7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1"
    )
    assert len(report.items) == 3
    with readonly_database_connection(database) as connection:
        assert connection.execute("SELECT count(*) FROM principals").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM plugin_manifests").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM sources").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM source_items").fetchone() == (3,)
        assert connection.execute("SELECT count(*) FROM source_spans").fetchone() == (9,)
        assert connection.execute("SELECT count(*) FROM runs").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM boundary_envelopes").fetchone() == (0,)
        principal = connection.execute(
            "SELECT principal_id, kind, display_name, os_binding FROM principals"
        ).fetchone()
        plugin = connection.execute(
            "SELECT plugin_id, plugin_version, fixture_set_sha256, trust, sensitivity, enabled "
            "FROM plugin_manifests"
        ).fetchone()
        source = connection.execute(
            "SELECT source_id, plugin_id, plugin_version, principal_id, source_type, "
            "account_alias, scope_json, host_allowlist_json, trust, default_sensitivity, enabled "
            "FROM sources"
        ).fetchone()
        item_rows = connection.execute(
            "SELECT item_id, source_id, provider_item_id, provider_revision, content_ref, "
            "content_sha256, trust, "
            "sensitivity, observed_at, source_at, metadata_json "
            "FROM source_items ORDER BY provider_item_id, content_sha256"
        ).fetchall()
        span_rows = connection.execute(
            "SELECT span_id, item_id, start_byte, end_byte, text_sha256, context_ref, "
            "derived_by_boundary_id FROM source_spans ORDER BY item_id, start_byte, span_id"
        ).fetchall()

    assert principal is not None
    assert principal[1:] == (
        "synthetic-fixture", "Synthetic GitHub fixture principal", "synthetic:fixture-only"
    )
    assert plugin == (
        "github.fixture", "1.0.0", fixture.fixture_sha256, "T4 EXTERNAL", "PUBLIC", 0
    )
    assert source is not None
    assert source[0] == str(report.registry_source_id)
    assert source[1:6] == (
        "github.fixture", "1.0.0", principal[0], "github_issue_fixture",
        "example-owner/fixture-project",
    )
    assert source[6] == json.dumps(
        {
            "fixture_sha256": fixture.fixture_sha256,
            "fixture_version": fixture.fixture_version,
            "repository": "example-owner/fixture-project",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert source[7:] == ("[]", "T4 EXTERNAL", "PUBLIC", 1)

    expected = {f"{issue.repository}#{issue.issue_number}": issue for issue in fixture.issues}
    for row in item_rows:
        (
            item_id,
            source_id,
            provider_item_id,
            provider_revision,
            content_ref,
            content_sha256,
            trust,
            sensitivity,
            observed_at,
            source_at,
            metadata,
        ) = row
        issue = expected[provider_item_id]
        parsed_metadata = json.loads(metadata)
        assert provider_revision is None
        assert source_id == str(report.registry_source_id)
        assert source_id != parsed_metadata.get("in_memory_source_id")
        assert content_sha256 == issue.normalized_source.envelope.content_sha256
        assert content_sha256 == hashlib.sha256(issue.normalized_source.original_bytes).hexdigest()
        assert content_ref == f"fixture:{fixture.fixture_version}:{provider_item_id}"
        assert (trust, sensitivity) == ("T4 EXTERNAL", "PUBLIC")
        assert observed_at == issue.normalized_source.envelope.observed_at.isoformat()
        assert source_at == issue.updated_at.isoformat()
        assert json.dumps(parsed_metadata, sort_keys=True, separators=(",", ":")) == metadata
        assert parsed_metadata["in_memory_source_id"] == str(issue.source_id)
        assert parsed_metadata["repository"] == issue.repository
        assert parsed_metadata["issue_number"] == issue.issue_number
        assert parsed_metadata["fixture_sha256"] == fixture.fixture_sha256
        assert issue.body_text.encode() not in metadata.encode()
        assert issue.title.encode() not in metadata.encode()
        assert item_id

    assert len(span_rows) == 9
    for span_id, item_id, start_byte, end_byte, digest, context_ref, boundary_id in span_rows:
        assert span_id and item_id
        assert isinstance(start_byte, int) and isinstance(end_byte, int)
        assert end_byte > start_byte
        assert len(digest) == 64
        assert context_ref is None
        assert boundary_id is None


def test_persisted_and_in_memory_source_ids_are_distinct(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "identity-domains.sqlite3")
    report = ingest_packaged_github_fixture(database)
    fixture = read_packaged_github_fixture()
    by_provider_id = {
        f"{issue.repository}#{issue.issue_number}": issue for issue in fixture.issues
    }

    for item in report.items:
        issue = by_provider_id[item.provider_item_id]
        assert item.source_envelope_id == issue.source_id
        assert item.item_id != item.source_envelope_id
        assert item.item_id != report.registry_source_id
        assert all(span.span_id != span.in_memory_span_id for span in item.spans)
def test_ingestion_report_contains_no_fixture_body_or_titles(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "report.sqlite3")
    fixture = read_packaged_github_fixture()
    report = ingest_packaged_github_fixture(database)
    representation = repr(report)
    assert fixture.fixture_sha256 in representation
    assert len(report.items) == 3
    for issue in fixture.issues:
        assert issue.body_text not in representation
        assert issue.title not in representation

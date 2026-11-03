"""Persisted byte spans are verified against reconstructed fixture bytes."""

from pathlib import Path

from sentinel.ingestion import (
    ingest_packaged_github_fixture,
    read_persisted_github_fixture,
    verify_persisted_github_citation,
)
from sentinel.readers.github_fixture import read_packaged_github_fixture
from sentinel.storage.connection import readonly_database_connection
from tests.cr1_g_support import initialized_database


def test_restart_reader_checks_all_items_and_source_bound_spans(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "citations.sqlite3")
    ingested = ingest_packaged_github_fixture(database)
    fixture = read_packaged_github_fixture()

    persisted = read_persisted_github_fixture(database)

    assert persisted.fixture_version == fixture.fixture_version
    assert persisted.fixture_sha256 == fixture.fixture_sha256
    assert persisted.registry_source_id == ingested.registry_source_id
    assert len(persisted.items) == 3
    assert sum(len(item.spans) for item in persisted.items) == 9
    fixture_by_provider_id = {
        f"{issue.repository}#{issue.issue_number}": issue for issue in fixture.issues
    }
    for item in persisted.items:
        issue = fixture_by_provider_id[item.provider_item_id]
        assert item.source_envelope_id == issue.source_id
        assert item.content_sha256 == issue.normalized_source.envelope.content_sha256
        assert len(item.spans) == len(issue.citations)
        for saved_span, citation in zip(item.spans, issue.citations, strict=True):
            assert saved_span.in_memory_span_id == citation.span.span_id
            assert saved_span.start_byte == citation.span.start_byte
            assert saved_span.end_byte == citation.span.end_byte
            assert saved_span.text_sha256 == citation.span.text_sha256
            assert verify_persisted_github_citation(
                database, item_id=item.item_id, span_id=saved_span.span_id
            ) == issue.normalized_source.original_bytes[
                citation.span.start_byte : citation.span.end_byte
            ].decode("utf-8")


def test_read_api_exposes_body_only_through_explicit_citation_verifier(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "body-free-read.sqlite3")
    ingest_packaged_github_fixture(database)
    fixture = read_packaged_github_fixture()
    persisted = read_persisted_github_fixture(database)
    representation = repr(persisted)
    for issue in fixture.issues:
        assert issue.body_text not in representation
        assert issue.title not in representation


def test_ascii_unicode_crlf_and_repeated_byte_ranges_return_exact_text(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "byte-ranges.sqlite3")
    report = ingest_packaged_github_fixture(database)
    persisted = read_persisted_github_fixture(database)
    fixture = read_packaged_github_fixture()
    issues = {
        f"{issue.repository}#{issue.issue_number}": issue for issue in fixture.issues
    }
    verified: list[str] = []
    for item in persisted.items:
        assert item.provider_item_id in issues
        for span in item.spans:
            verified.append(
                verify_persisted_github_citation(
                    database, item_id=item.item_id, span_id=span.span_id
                )
            )
    assert "parser reports" in verified
    assert "🙂" in verified
    assert "日本語" in verified
    assert "\r\n" in verified
    assert verified.count("done") == 2
    first_issue = next(
        item for item in report.items if item.provider_item_id.endswith("#101")
    )
    source_issue = issues[first_issue.provider_item_id]
    done_span_ids = {
        citation.span.span_id
        for citation in source_issue.citations
        if source_issue.normalized_source.original_bytes[
            citation.span.start_byte : citation.span.end_byte
        ] == b"done"
    }
    done_spans = [
        span for span in first_issue.spans if span.in_memory_span_id in done_span_ids
    ]
    assert len(done_spans) == 2
    assert done_spans[0].start_byte != done_spans[1].start_byte
    assert report.registry_source_id == persisted.registry_source_id


def test_restart_verification_is_read_only_and_repeatable(tmp_path: Path) -> None:
    database = initialized_database(tmp_path / "read-only.sqlite3")
    ingest_packaged_github_fixture(database)
    before = _rows(database)

    first = read_persisted_github_fixture(database)
    second = read_persisted_github_fixture(database)

    assert first == second
    assert _rows(database) == before


def _rows(database: Path) -> tuple[object, ...]:
    with readonly_database_connection(database) as connection:
        return (
            tuple(connection.execute("SELECT * FROM sources").fetchall()),
            tuple(connection.execute("SELECT * FROM source_items ORDER BY item_id").fetchall()),
            tuple(connection.execute("SELECT * FROM source_spans ORDER BY span_id").fetchall()),
        )

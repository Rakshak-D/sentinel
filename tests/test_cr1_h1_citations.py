from __future__ import annotations

import hashlib

from sentinel.ingestion import (
    promote_github_fixture_to_public_blobs,
    read_blob_backed_github_body,
    read_blob_backed_github_fixture,
    verify_blob_backed_github_citation,
)
from sentinel.normalization import verify_bound_citation
from sentinel.readers.github_fixture import read_packaged_github_fixture
from tests.cr1_h1_support import prepared_case


def test_all_nine_promoted_citations_verify_exact_slices_and_source_identity(tmp_path):
    database, store_root = prepared_case(tmp_path, name="citations")
    fixture = read_packaged_github_fixture()
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    result = read_blob_backed_github_fixture(database, store_root=store_root)

    assert len(result.items) == 3
    assert sum(len(item.spans) for item in result.items) == 9
    for issue in fixture.issues:
        source_id = issue.normalized_source.envelope.source_id
        digest = issue.normalized_source.envelope.content_sha256
        persisted = next(
            row for row in result.items if row.provider_item_id.endswith(f"#{issue.issue_number}")
        )
        assert persisted.source_envelope_id == source_id
        body = read_blob_backed_github_body(
            database, store_root=store_root, item_id=persisted.item_id
        )
        assert body == issue.normalized_source.original_bytes
        assert hashlib.sha256(body).hexdigest() == digest
        for old_span in issue.citations:
            stored_span = next(
                span for span in persisted.spans if span.in_memory_span_id == old_span.span.span_id
            )
            expected_text = verify_bound_citation(
                issue.normalized_source,
                old_span,
                original_bytes=body,
            )
            assert (
                verify_blob_backed_github_citation(
                    database,
                    store_root=store_root,
                    item_id=persisted.item_id,
                    span_id=stored_span.span_id,
                )
                == expected_text
            )


def test_emoji_japanese_and_line_ending_citations_are_byte_accurate(tmp_path):
    database, store_root = prepared_case(tmp_path, name="unicode")
    fixture = read_packaged_github_fixture()
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    result = read_blob_backed_github_fixture(database, store_root=store_root)
    issue = next(item for item in fixture.issues if item.issue_number == 102)
    persisted = next(row for row in result.items if row.provider_item_id.endswith("#102"))
    body = read_blob_backed_github_body(database, store_root=store_root, item_id=persisted.item_id)
    decoded = body.decode("utf-8", errors="strict")
    outputs = {
        verify_blob_backed_github_citation(
            database, store_root=store_root, item_id=persisted.item_id, span_id=span.span_id
        )
        for span in persisted.spans
    }
    assert any(ord(char) > 0xFFFF for char in decoded)
    assert any("\u3040" <= char <= "\u30ff" or "\u4e00" <= char <= "\u9fff" for char in decoded)
    assert b"\r\n" in body and b"\n" in body
    assert outputs == {verify_bound_citation(issue.normalized_source, c) for c in issue.citations}


def test_body_free_reports_do_not_dump_content(tmp_path):
    database, store_root = prepared_case(tmp_path, name="bodyfree")
    fixture = read_packaged_github_fixture()
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    report = read_blob_backed_github_fixture(database, store_root=store_root)
    rendered = repr(report)
    for issue in fixture.issues:
        assert issue.title not in rendered
        assert issue.body_text not in rendered

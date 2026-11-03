"""Byte-accurate source-bound citation tests for the packaged issue fixture."""

import hashlib
import json

import pytest

from sentinel.normalization import NormalizationError, verify_bound_citation
from sentinel.readers import (
    FIXTURE_OBSERVED_AT,
    FIXTURE_SCHEMA_VERSION,
    read_packaged_github_fixture,
)
from sentinel.readers import github_fixture as reader_impl


def _valid_document() -> dict[str, object]:
    return {
        "fixture_version": FIXTURE_SCHEMA_VERSION,
        "issues": [
            {
                "repository": "example-owner/fixture-project",
                "issue_number": 101,
                "updated_at": "2026-11-02T10:30:00Z",
                "title": "Synthetic issue title",
                "body": "Synthetic issue body contains a note.",
                "evidence_spans": [
                    {
                        "span_id": "d767cdd2-90cb-45d6-9291-95d0c8aa0d09",
                        "start_byte": 16,
                        "end_byte": 26,
                        "expected_text": "body conta",
                    }
                ],
            }
        ],
    }


def _raw(document: dict[str, object]) -> bytes:
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _parse(raw_json: bytes):
    return reader_impl._parse_fixture_bytes(raw_json, observed_at=FIXTURE_OBSERVED_AT)


def test_ascii_unicode_crlf_and_repeated_phrase_ranges_match_body_bytes() -> None:
    issues = read_packaged_github_fixture().issues
    first, unicode_issue, _instruction = issues

    assert [(span.span.start_byte, span.span.end_byte) for span in first.citations] == [
        (17, 31),
        (68, 72),
        (74, 78),
    ]
    assert [verify_bound_citation(first.normalized_source, span) for span in first.citations] == [
        "parser reports",
        "done",
        "done",
    ]
    assert [(span.span.start_byte, span.span.end_byte) for span in unicode_issue.citations] == [
        (23, 27),
        (32, 41),
        (42, 44),
        (61, 63),
        (66, 68),
    ]
    assert [
        verify_bound_citation(unicode_issue.normalized_source, span)
        for span in unicode_issue.citations
    ] == ["🙂", "日本語", "\r\n", "go", "go"]
    assert [(span.span.start_byte, span.span.end_byte) for span in issues[2].citations] == [
        (16, 41)
    ]


def test_every_bound_reference_matches_issue_identity_and_both_hashes() -> None:
    for issue in read_packaged_github_fixture().issues:
        body = issue.body_text.encode("utf-8")
        source_digest = hashlib.sha256(body).hexdigest()
        for citation in issue.citations:
            cited_bytes = body[citation.span.start_byte : citation.span.end_byte]
            assert citation.source_id == issue.source_id
            assert citation.content_sha256 == source_digest
            assert citation.span.text_sha256 == hashlib.sha256(cited_bytes).hexdigest()
            assert verify_bound_citation(issue.normalized_source, citation) == cited_bytes.decode(
                "utf-8"
            )


def test_cross_issue_bound_reference_fails_even_for_equal_bodies() -> None:
    document = _valid_document()
    issue_a = document["issues"][0]  # type: ignore[index]
    assert isinstance(issue_a, dict)
    issue_b = json.loads(json.dumps(issue_a))
    issue_b["issue_number"] = 102
    document["issues"].append(issue_b)  # type: ignore[union-attr]
    parsed = _parse(_raw(document))
    source_a, source_b = (item.normalized_source for item in parsed.issues)
    citation_a = parsed.issues[0].citations[0]

    assert source_a.original_bytes == source_b.original_bytes
    with pytest.raises(NormalizationError):
        verify_bound_citation(source_b, citation_a)


def test_changed_issue_body_invalidates_existing_bound_reference() -> None:
    document = _valid_document()
    original = _parse(_raw(document)).issues[0]
    revision_document = _valid_document()
    revised_issue = revision_document["issues"][0]  # type: ignore[index]
    assert isinstance(revised_issue, dict)
    revised_issue["body"] = "Synthetic changed source body."
    revised_issue["evidence_spans"] = []
    revision = _parse(_raw(revision_document)).issues[0]

    assert original.source_id == revision.source_id
    with pytest.raises(NormalizationError):
        verify_bound_citation(revision.normalized_source, original.citations[0])


def test_reader_revalidates_malformed_nested_citation_copy() -> None:
    issue = read_packaged_github_fixture().issues[0]
    invalid_span = issue.citations[0].span.model_copy(update={"start_byte": -1})
    invalid_reference = issue.citations[0].model_copy(update={"span": invalid_span})

    with pytest.raises(NormalizationError):
        verify_bound_citation(issue.normalized_source, invalid_reference)
